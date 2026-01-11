"""Core generation logic for Generate It.

This module is UI-agnostic: both the curses TUI and any CLI wrapper can use it.
"""

from __future__ import annotations

from pathlib import Path
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
PASSPHRASE_SPECIALS = "!@#$%&*?"

# Username-related character sets.
USERNAME_ALPHANUMERIC = string.ascii_lowercase + string.digits
USERNAME_SEPARATORS = ["_", "-"]

# Wordlist lookup order:
# 1) explicit `path` argument
# 2) $GENERATE_IT_WORDLIST
# 3) ./wordlist.txt (current working directory)
# 4) packaged default: generate_it/wordlist.txt
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
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def load_wordlist(path: Path | None = None) -> list[str]:
    """Load passphrase words.

    Source order:
    1) explicit `path`
    2) $GENERATE_IT_WORDLIST
    3) ./wordlist.txt (current working directory)
    4) packaged default (generate_it/wordlist.txt)

    Lines starting with `#` and blank lines are ignored.
    Falls back to a small built-in list if the file is missing or too small.
    """

    if path is None:
        env_path = os.environ.get("GENERATE_IT_WORDLIST")
        if env_path:
            path = Path(env_path).expanduser()
        else:
            cwd_path = Path.cwd() / "wordlist.txt"
            path = cwd_path if cwd_path.exists() else PACKAGED_WORDLIST_PATH

    if not path.exists():
        return DEFAULT_WORDLIST

    words: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        w = line.strip()
        if not w or w.startswith("#"):
            continue
        words.append(w)

    words = _dedupe_preserve_order(words)

    # If the file is empty or nearly empty, fall back to the built-in list.
    return words if len(words) >= 10 else DEFAULT_WORDLIST


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
    pool = list(words)
    chosen_words: list[str] = []
    for _ in range(word_count):
        idx = secrets.randbelow(len(pool))
        chosen_words.append(pool.pop(idx))

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
    pool = list(words)
    chosen_words: list[str] = []
    for _ in range(word_count):
        idx = secrets.randbelow(len(pool))
        chosen_words.append(pool.pop(idx))

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

    # For separator styles, create segments separated by _ or -
    separator = "_" if separator_style == "underscore" else "-"
    segment_length = length // 3
    segments: list[str] = []

    for _ in range(3):
        seg = "".join(
            secrets.choice(USERNAME_ALPHANUMERIC) for _ in range(segment_length)
        )
        segments.append(seg)

    # Adjust last segment to match exact length
    username = separator.join(segments)
    while len(username) < length:
        username += secrets.choice(USERNAME_ALPHANUMERIC)

    return username[:length]


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
