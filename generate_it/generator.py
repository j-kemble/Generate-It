"""Core generation logic for Generate It.

This module is UI-agnostic: both the curses TUI and any CLI wrapper can use it.
"""

from __future__ import annotations

from pathlib import Path
import functools
import hashlib
import math
import os
import secrets
import string

MIN_PASSWORD_CHARS = 8
MAX_PASSWORD_CHARS = 64

MIN_PASSPHRASE_WORDS = 3
MAX_PASSPHRASE_WORDS = 10

MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 64
MIN_USERNAME_WORDS = 1
MAX_USERNAME_WORDS = 3

LETTERS = string.ascii_letters
NUMBERS = string.digits
SPECIAL_CHARACTERS = "!@#$%^&*()-_=+[]{};:,.?/"

# Used when the user asks to add special characters to a passphrase.
PASSPHRASE_SPECIALS = "!@#$%&*?"  # nosec B105 — character pool, not a credential

# Username-related character sets.
USERNAME_ALPHANUMERIC = string.ascii_lowercase + string.digits
USERNAME_SEPARATORS = frozenset(["_", "-"])

# Wordlist lookup order:
# 1) explicit `path` argument
# 2) $GENERATE_IT_WORDLIST env var
# 3) packaged default: generate_it/wordlist.txt
PACKAGED_WORDLIST_PATH = Path(__file__).with_name("wordlist.txt")

DEFAULT_WORDLIST = [
    # Small built-in fallback list (you can expand by editing wordlist.txt).
    "apple",
    "brisk",
    "candle",
    "delta",
    "ember",
    "forest",
    "glacier",
    "harbor",
    "island",
    "jupiter",
    "kitten",
    "lantern",
    "meadow",
    "nebula",
    "ocean",
    "pepper",
    "quartz",
    "river",
    "sunrise",
    "tiger",
    "umbrella",
    "violet",
    "willow",
    "xenon",
    "yellow",
    "zephyr",
]

# Minimum entropy the wordlist must provide for a 4-word passphrase.
_MIN_PASSPHRASE_ENTROPY_BITS = 50.0


class WordlistSecurityError(ValueError):
    """Raised when a custom wordlist is too small for secure passphrases."""
    pass


def _ordered_sample_entropy_bits(n: int, k: int) -> float:
    """Entropy (bits) of selecting k items without replacement from n.
    
    bits = log2(n! / (n-k)!) = sum(log2(i)) for i in range(n-k+1, n+1)
    """
    if k > n or n <= 0 or k <= 0:
        return 0.0
    total = 0.0
    for i in range(n - k + 1, n + 1):
        total += math.log2(i)
    return total


# Adjectives for username generation.
DEFAULT_ADJECTIVES = [
    "able",
    "ancient",
    "angry",
    "bright",
    "bold",
    "calm",
    "clever",
    "cosmic",
    "cool",
    "crazy",
    "dark",
    "daring",
    "deft",
    "dense",
    "dry",
    "easy",
    "epic",
    "fast",
    "fierce",
    "free",
    "fresh",
    "fun",
    "fuzzy",
    "gentle",
    "giant",
    "gleaming",
    "golden",
    "grand",
    "great",
    "green",
    "gritty",
    "happy",
    "hardy",
    "hasty",
    "holy",
    "hot",
    "huge",
    "humble",
    "icy",
    "ideal",
    "idle",
    "jolly",
    "keen",
    "kind",
    "kinetic",
    "lazy",
    "legal",
    "lethal",
    "light",
    "lively",
    "local",
    "lonely",
    "loud",
    "lovely",
    "loyal",
    "lucky",
    "lunar",
    "major",
    "mean",
    "meek",
    "mighty",
    "mild",
    "mini",
    "misty",
    "mortal",
    "mystic",
    "neat",
    "needy",
    "noble",
    "noisy",
    "normal",
    "novel",
    "odd",
    "ominous",
    "open",
    "pale",
    "partial",
    "perfect",
    "pesky",
    "plain",
    "playful",
    "polar",
    "prime",
    "proud",
    "pure",
    "quick",
    "quiet",
    "quirky",
    "radiant",
    "rapid",
    "rare",
    "rash",
    "raw",
    "real",
    "red",
    "risky",
    "rough",
    "round",
    "rude",
    "rural",
    "sacred",
    "sad",
    "safe",
    "sage",
    "salty",
    "sane",
    "savage",
    "secret",
    "secure",
    "selfish",
    "senior",
    "serene",
    "serious",
    "sharp",
    "shiny",
    "sick",
    "silent",
    "silly",
    "simple",
    "sleepy",
    "slim",
    "small",
    "smart",
    "smooth",
    "snappy",
    "sneaky",
    "soft",
    "solar",
    "solid",
    "sore",
    "sorry",
    "sound",
    "sour",
    "sparse",
    "spatial",
    "special",
    "speedy",
    "spiral",
    "splendid",
    "stable",
    "stark",
    "stellar",
    "stern",
    "stiff",
    "still",
    "stoic",
    "strange",
    "strong",
    "subtle",
    "sudden",
    "sullen",
    "sunny",
    "super",
    "swift",
    "swollen",
    "tall",
    "tame",
    "tart",
    "tasty",
    "tense",
    "terrible",
    "thick",
    "thin",
    "thorny",
    "thoughtful",
    "tidy",
    "timid",
    "tiny",
    "tired",
    "total",
    "tough",
    "tragic",
    "true",
    "trusty",
    "truthful",
    "turbid",
    "typical",
    "ugly",
    "ultimate",
    "unfit",
    "unique",
    "united",
    "unknown",
    "unruly",
    "untidy",
    "unusual",
    "upright",
    "urban",
    "used",
    "useful",
    "useless",
    "usual",
    "valid",
    "vain",
    "vast",
    "vile",
    "violent",
    "viral",
    "virtual",
    "visible",
    "vivid",
    "vocal",
    "void",
    "volatile",
    "vulgar",
    "wacky",
    "wary",
    "weak",
    "wealthy",
    "weird",
    "welcome",
    "wet",
    "whole",
    "wicked",
    "wide",
    "wild",
    "willing",
    "windswept",
    "wise",
    "woeful",
    "wonderful",
    "wooden",
    "worn",
    "worried",
    "worthy",
    "wrong",
    "xenial",
    "yellow",
    "young",
    "youthful",
    "zealous",
]


def secure_shuffle(items: list[str]) -> None:
    """Shuffle a list in-place using `secrets` for randomness."""
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _secure_sample_without_replacement(words: list[str], count: int) -> list[str]:
    """Select distinct words with CSPRNG indices and no shifting removals."""
    pool = list(words)
    for position in range(count):
        selected_index = position + secrets.randbelow(len(pool) - position)
        pool[position], pool[selected_index] = pool[selected_index], pool[position]
    return pool[:count]


def resolve_wordlist_source(path: Path | None = None) -> tuple[Path | None, bool]:
    """Resolve explicit path, $GENERATE_IT_WORDLIST env var, or packaged default.

    Returns (resolved_path, is_custom).
    """
    is_custom = path is not None
    if path is None:
        env_path = os.environ.get("GENERATE_IT_WORDLIST")
        if env_path:
            path = Path(env_path).expanduser()
            is_custom = True
        else:
            path = PACKAGED_WORDLIST_PATH

    return path, is_custom


_WORDLIST_CACHE: dict[Path | None, tuple[int, int, bytes, tuple[str, ...]]] = {}
_WORDLIST_CACHE_MAX_SIZE = 8


def clear_wordlist_cache() -> None:
    """Clear the wordlist cache (used by tests and cache invalidation)."""
    _WORDLIST_CACHE.clear()


def _get_file_signature(path: Path | None) -> tuple[Path | None, int, int]:
    """Return resolved path and metadata used for the wordlist fast path."""
    if path is None or not path.exists():
        return (None, 0, 0)
    try:
        st = path.stat()
        return (path.resolve(), st.st_mtime_ns, st.st_size)
    except OSError:
        return (path.resolve(), 0, 0)


def _hash_wordlist(path: Path) -> bytes:
    """Hash a wordlist only after its filesystem metadata changes."""
    digest = hashlib.blake2b(digest_size=16)
    with path.open("rb") as wordlist_file:
        for chunk in iter(lambda: wordlist_file.read(65536), b""):
            digest.update(chunk)
    return digest.digest()


def load_wordlist(path: Path | None = None) -> list[str]:
    """Load passphrase words.

    Source order:
    1) explicit `path`
    2) $GENERATE_IT_WORDLIST env var
    3) packaged default (generate_it/wordlist.txt)

    Lines starting with `#` and blank lines are ignored.
    Custom wordlists (explicit path or env var) are validated against
    a 50-bit entropy floor at 4 words.

    Cached by resolved path and metadata in a small bounded cache. Content is
    hashed only when the path is first loaded or its metadata changes.
    Returns a defensive copy so caller mutations do not corrupt shared cached data.
    """
    resolved_path, is_custom = resolve_wordlist_source(path)
    cache_path, mtime_ns, file_size = _get_file_signature(resolved_path)
    cached = _WORDLIST_CACHE.get(cache_path)
    if cached is not None:
        cached_mtime_ns, cached_size, cached_hash, cached_words = cached
        if (cached_mtime_ns, cached_size) == (mtime_ns, file_size):
            if cache_path is None:
                return list(cached_words)
            if _hash_wordlist(cache_path) == cached_hash:
                return list(cached_words)

    if cache_path is None or not cache_path.exists():
        words_tuple = tuple(DEFAULT_WORDLIST)
        content_hash = b""
    else:
        content_hash = _hash_wordlist(cache_path)
        raw_words: list[str] = []
        for line in cache_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            w = line.strip()
            if not w or w.startswith("#"):
                continue
            raw_words.append(w)
        words_tuple = tuple(_dedupe_preserve_order(raw_words))

    # Validate only a file that was actually loaded as a custom wordlist.
    if is_custom and cache_path is not None:
        bits = _ordered_sample_entropy_bits(len(words_tuple), 4)
        if bits < _MIN_PASSPHRASE_ENTROPY_BITS:
            raise WordlistSecurityError(
                f"Custom wordlist has only {len(words_tuple)} unique words, "
                f"providing {bits:.1f} bits of entropy for a 4-word passphrase. "
                f"Minimum required: {_MIN_PASSPHRASE_ENTROPY_BITS:.0f} bits. "
                f"Need at least ~5,800 unique words."
            )

    # Maintain bounded cache size.
    if len(_WORDLIST_CACHE) >= _WORDLIST_CACHE_MAX_SIZE:
        oldest_key = next(iter(_WORDLIST_CACHE))
        del _WORDLIST_CACHE[oldest_key]

    _WORDLIST_CACHE[cache_path] = (mtime_ns, file_size, content_hash, words_tuple)
    return list(words_tuple)


# Attach cache_clear attribute for backwards compatibility with tests that called
# load_wordlist.cache_clear().
load_wordlist.cache_clear = clear_wordlist_cache  # type: ignore[attr-defined]


def generate_character_password(
    length: int, *, use_letters: bool, use_numbers: bool, use_special: bool
) -> str:
    """Generate a random character password.

    Ensures at least one character from each selected category appears.
    """

    if length < MIN_PASSWORD_CHARS or length > MAX_PASSWORD_CHARS:
        raise ValueError(
            f"length must be between {MIN_PASSWORD_CHARS} and {MAX_PASSWORD_CHARS}"
        )

    pools: list[str] = []
    required: list[str] = []

    if use_letters:
        pools.append(LETTERS)
        required.append(secrets.choice(LETTERS))
    if use_numbers:
        pools.append(NUMBERS)
        required.append(secrets.choice(NUMBERS))
    if use_special:
        pools.append(SPECIAL_CHARACTERS)
        required.append(secrets.choice(SPECIAL_CHARACTERS))

    # If no categories are selected, return an empty string or a string of the requested length
    # with characters from an empty pool (which is impossible, so just return empty).
    if len(pools) == 0:
        return ""

    alphabet = "".join(pools)
    remaining = length - len(required)
    if remaining < 0:
        raise ValueError("Password length is too small for the required categories")

    chars = required + [secrets.choice(alphabet) for _ in range(remaining)]
    secure_shuffle(chars)
    return "".join(chars)


def _insert_token_into_words(words: list[str], token: str) -> None:
    """Insert `token` into a random word at a random position."""

    idx = secrets.randbelow(len(words))
    w = words[idx]

    # Default: allow insertion at any position.
    max_pos = len(w)

    # If we picked the last word, avoid inserting at the final position so it
    # doesn't *feel* appended to the end of the whole passphrase.
    if idx == len(words) - 1 and len(w) > 0:
        max_pos = len(w) - 1

    pos = secrets.randbelow(max_pos + 1)
    words[idx] = w[:pos] + token + w[pos:]


def generate_passphrase(
    word_count: int,
    *,
    add_numbers: bool,
    add_special: bool,
    words: list[str] | None = None,
) -> str:
    """Generate a hyphen-separated passphrase.

    If enabled, numbers/special characters are inserted into random words.
    """

    if word_count < MIN_PASSPHRASE_WORDS or word_count > MAX_PASSPHRASE_WORDS:
        raise ValueError(
            f"word_count must be between {MIN_PASSPHRASE_WORDS} and {MAX_PASSPHRASE_WORDS}"
        )

    if words is None:
        words = load_wordlist()

    if len(words) < word_count:
        raise ValueError("wordlist is too small for the requested word_count")

    # Choose words without replacement so a passphrase never repeats a word.
    chosen_words = _secure_sample_without_replacement(words, word_count)

    if add_numbers:
        digits_len = secrets.choice([2, 3, 4])
        digits = "".join(str(secrets.randbelow(10)) for _ in range(digits_len))
        _insert_token_into_words(chosen_words, digits)

    if add_special:
        _insert_token_into_words(chosen_words, secrets.choice(PASSPHRASE_SPECIALS))

    return "-".join(chosen_words)


def generate_username_words(
    word_count: int,
    *,
    add_numbers: bool = False,
    separator: str = "_",
    words: list[str] | None = None,
) -> str:
    """Generate a username from random words.

    Args:
        word_count: Number of words (1-3)
        add_numbers: Whether to append 1-3 random digits
        separator: Character to join words (typically "_" or "-")
        words: Custom wordlist (defaults to packaged wordlist)

    Returns:
        Username string in format: word_word_number
    """
    if word_count < MIN_USERNAME_WORDS or word_count > MAX_USERNAME_WORDS:
        raise ValueError(
            f"word_count must be between {MIN_USERNAME_WORDS} and {MAX_USERNAME_WORDS}"
        )

    if separator not in USERNAME_SEPARATORS:
        raise ValueError(
            f"separator must be one of {USERNAME_SEPARATORS}, got {separator!r}"
        )

    if words is None:
        words = load_wordlist()

    if len(words) < word_count:
        raise ValueError("wordlist is too small for the requested word_count")

    # Choose words without replacement.
    chosen_words = _secure_sample_without_replacement(words, word_count)

    username = separator.join(chosen_words)

    if add_numbers:
        digits = "".join(str(secrets.randbelow(10)) for _ in range(3))
        username = f"{username}{digits}"

    return username


def generate_username_random(
    length: int,
    *,
    separator_style: str = "none",
) -> str:
    """Generate a random character username.

    Args:
        length: Username length (3-25)
        separator_style: "none", "underscore", or "hyphen"

    Returns:
        Random alphanumeric username
    """
    if length < MIN_USERNAME_LENGTH or length > MAX_USERNAME_LENGTH:
        raise ValueError(
            f"length must be between {MIN_USERNAME_LENGTH} and {MAX_USERNAME_LENGTH}"
        )

    if separator_style not in ["none", "underscore", "hyphen"]:
        raise ValueError(
            f"separator_style must be 'none', 'underscore', or 'hyphen', got {separator_style!r}"
        )

    if separator_style == "none":
        chars = [secrets.choice(USERNAME_ALPHANUMERIC) for _ in range(length)]
        return "".join(chars)

    # Use as many separators as fit while keeping every segment non-empty.
    separator = "_" if separator_style == "underscore" else "-"
    separator_count = min(2, max(1, (length - 1) // 2))
    content_length = length - separator_count
    segment_count = separator_count + 1
    first_length, remainder = divmod(content_length, segment_count)
    segment_lengths = [first_length] * segment_count
    for index in range(remainder):
        segment_lengths[index] += 1
    segments = [
        "".join(secrets.choice(USERNAME_ALPHANUMERIC) for _ in range(segment_length))
        for segment_length in segment_lengths
    ]
    return separator.join(segments)


def generate_username_adjective_noun(
    *,
    add_numbers: bool = False,
    separator: str = "_",
    adjectives: list[str] | None = None,
    nouns: list[str] | None = None,
) -> str:
    """Generate a username from adjective + noun combination.

    Args:
        add_numbers: Whether to append 1-3 random digits
        separator: Character to join words ("_" or "-")
        adjectives: Custom adjective list (defaults to built-in)
        nouns: Custom noun list (defaults to packaged wordlist)

    Returns:
        Username string in format: adjective_noun or adjective_noun_123
    """
    if separator not in USERNAME_SEPARATORS:
        raise ValueError(
            f"separator must be one of {USERNAME_SEPARATORS}, got {separator!r}"
        )

    if adjectives is None:
        adjectives = DEFAULT_ADJECTIVES

    if nouns is None:
        nouns = load_wordlist()

    if not adjectives or not nouns:
        raise ValueError("Both adjectives and nouns lists must be non-empty")

    adjective = secrets.choice(adjectives)
    noun = secrets.choice(nouns)
    username = f"{adjective}{separator}{noun}"

    if add_numbers:
        digits = "".join(str(secrets.randbelow(10)) for _ in range(2))
        username = f"{username}{digits}"

    return username
