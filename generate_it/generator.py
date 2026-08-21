"""Core generation logic for Generate It.

This module is UI-agnostic: both the curses TUI and any CLI wrapper can use it.
"""

from __future__ import annotations

from pathlib import Path
import hashlib
import logging
import math
import os
import secrets

_log = logging.getLogger("generator")

from .constants import (
    DEFAULT_WORDLIST,
    LETTERS,
    MAX_PASSPHRASE_WORDS,
    MAX_PASSWORD_CHARS,
    MAX_USERNAME_LENGTH,
    MAX_USERNAME_WORDS,
    MIN_PASSPHRASE_WORDS,
    MIN_PASSWORD_CHARS,
    MIN_USERNAME_LENGTH,
    MIN_USERNAME_WORDS,
    NUMBERS,
    PASSPHRASE_SPECIALS,
    SPECIAL_CHARACTERS,
    USERNAME_ALPHANUMERIC,
    USERNAME_SEPARATORS,
    _MAX_WORDLIST_FILE_BYTES,
    _MAX_WORDLIST_WORDS,
    _MIN_PASSPHRASE_ENTROPY_BITS,
    _WORDLIST_CACHE_MAX_SIZE as _CONST_WORDLIST_CACHE_MAX_SIZE,
    _WORDLIST_HASH_CHUNK_BYTES as _CONST_WORDLIST_HASH_CHUNK_BYTES,
    _WORDLIST_HASH_DIGEST_SIZE as _CONST_WORDLIST_HASH_DIGEST_SIZE,
)

# Re-export for backwards compatibility; constants.py is the single source of truth.
__all__ = [
    "DEFAULT_WORDLIST",
    "MIN_PASSWORD_CHARS",
    "MAX_PASSWORD_CHARS",
    "MIN_PASSPHRASE_WORDS",
    "MAX_PASSPHRASE_WORDS",
    "MIN_USERNAME_LENGTH",
    "MAX_USERNAME_LENGTH",
    "MIN_USERNAME_WORDS",
    "MAX_USERNAME_WORDS",
    "LETTERS",
    "NUMBERS",
    "SPECIAL_CHARACTERS",
    "PASSPHRASE_SPECIALS",
    "USERNAME_ALPHANUMERIC",
    "USERNAME_SEPARATORS",
]

# Wordlist lookup order:
# 1) explicit `path` argument
# 2) $GENERATE_IT_WORDLIST env var
# 3) packaged default: generate_it/wordlist.txt
PACKAGED_WORDLIST_PATH = Path(__file__).with_name("wordlist.txt")


class WordlistSecurityError(ValueError):
    """Raised when a custom wordlist is too small for secure passphrases."""
    pass


def _ordered_sample_entropy_bits(n: int, k: int) -> float:
    """Entropy (bits) of selecting k items without replacement from n.

    bits = log2(n! / (n-k)!) — uses lgamma for O(1) without loop.
    """
    if k > n or n <= 0 or k <= 0:
        return 0.0
    # lgamma(n+1) = ln(n!), so bits = (ln(n!) - ln((n-k)!)) / ln2
    return (math.lgamma(n + 1) - math.lgamma(n - k + 1)) / math.log(2)


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
    """Flat helper: dedupe while preserving order, reusable."""
    return list(dict.fromkeys(items))


def _secure_sample_without_replacement(words: list[str], count: int) -> list[str]:
    """Select distinct words with CSPRNG indices — O(k) allocations, reusable.

    Avoids copying the entire wordlist. Uses a flat, modular partial-sample
    with a dict mapping for swapped indices, so memory travel stays constant
    for large wordlists (2B-scale).
    """
    if count <= 0:
        return []
    if count > len(words):
        raise ValueError("count exceeds wordlist size")
    # Flat O(k) sampling without full pool copy.
    index_map: dict[int, int] = {}
    result: list[str] = []
    n = len(words)
    for position in range(count):
        # Random index in [position, n-1]
        rand_offset = secrets.randbelow(n - position)
        selected_index = position + rand_offset
        # Resolve actual indices via swap map
        pos_val = index_map.get(position, position)
        sel_val = index_map.get(selected_index, selected_index)
        # Record selection and update map
        result.append(words[sel_val])
        index_map[selected_index] = pos_val
        # No need to keep position entry beyond this iteration
        if selected_index != position:
            index_map[position] = sel_val
        else:
            # When we swapped with itself, keep map consistent
            index_map[position] = pos_val
    return result


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


from collections import OrderedDict as _OrderedDict

_WORDLIST_CACHE: _OrderedDict[Path | None, tuple[int, int, bytes, tuple[str, ...]]] = _OrderedDict()
_WORDLIST_CACHE_MAX_SIZE = _CONST_WORDLIST_CACHE_MAX_SIZE
_WORDLIST_HASH_CHUNK_BYTES = _CONST_WORDLIST_HASH_CHUNK_BYTES
_WORDLIST_HASH_DIGEST_SIZE = _CONST_WORDLIST_HASH_DIGEST_SIZE


def clear_wordlist_cache() -> None:
    """Clear the wordlist cache (used by tests and cache invalidation)."""
    _WORDLIST_CACHE.clear()


def _validate_custom_wordlist_path(path: Path) -> None:
    """Reject symlinks, non-regular files, and oversize files."""
    try:
        lst = path.lstat()
    except OSError as exc:
        raise WordlistSecurityError(f"Cannot stat wordlist: {exc}") from exc
    import stat as _stat
    if _stat.S_ISLNK(lst.st_mode):
        raise WordlistSecurityError("Custom wordlist path is a symlink — refused for security.")
    if not _stat.S_ISREG(lst.st_mode):
        raise WordlistSecurityError("Custom wordlist is not a regular file.")
    if lst.st_size > _MAX_WORDLIST_FILE_BYTES:
        raise WordlistSecurityError(
            f"Custom wordlist too large ({lst.st_size} bytes). Maximum: {_MAX_WORDLIST_FILE_BYTES} bytes."
        )


def _get_file_signature(path: Path | None) -> tuple[Path | None, int, int]:
    """Return resolved path and metadata used for the wordlist fast path.

    Uses ``lstat`` so a symlink is not followed — the caller must have already
    validated the path via :func:`_validate_custom_wordlist_path`.  If the
    path is a symlink at this point it is treated as missing (0, 0) so the
    cache cannot be poisoned via a TOCTOU swap.
    """
    if path is None or not path.exists():
        return (None, 0, 0)
    try:
        import stat as _stat

        lst = path.lstat()
        if _stat.S_ISLNK(lst.st_mode):
            return (path.resolve(), 0, 0)
        return (path.resolve(), lst.st_mtime_ns, lst.st_size)
    except OSError:
        return (path.resolve(), 0, 0)


def _hash_wordlist(path: Path) -> bytes:
    """Hash a wordlist only after its filesystem metadata changes — reusable.

    On POSIX opens the file with ``O_NOFOLLOW`` so a symlink swap between
    validation and hashing cannot be exploited.  Falls back to ``lstat``
    + regular ``open`` on platforms without ``O_NOFOLLOW``.
    """
    digest = hashlib.blake2b(digest_size=_WORDLIST_HASH_DIGEST_SIZE)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if os.name == "posix" and no_follow is not None:
        try:
            fd = os.open(str(path), os.O_RDONLY | no_follow)
        except OSError as exc:
            # ELOOP (Too many levels of symbolic links) means O_NOFOLLOW
            # blocked a symlink — normalize to WordlistSecurityError.
            import errno as _errno

            if exc.errno in (_errno.ELOOP, _errno.EMLINK) or "symlink" in str(exc).lower() or "Too many levels" in str(exc):
                raise WordlistSecurityError("Custom wordlist path is a symlink — refused for security.") from exc
            raise WordlistSecurityError(f"Cannot open wordlist: {exc}") from exc
        try:
            import stat as _stat

            st = os.fstat(fd)
            if _stat.S_ISLNK(st.st_mode):
                raise WordlistSecurityError("Custom wordlist path is a symlink — refused for security.")
            if not _stat.S_ISREG(st.st_mode):
                raise WordlistSecurityError("Custom wordlist is not a regular file.")
            if st.st_size > _MAX_WORDLIST_FILE_BYTES:
                raise WordlistSecurityError(
                    f"Custom wordlist too large ({st.st_size} bytes). Maximum: {_MAX_WORDLIST_FILE_BYTES} bytes."
                )
            # Stream from the already-validated fd to avoid a second open race.
            while True:
                chunk = os.read(fd, _WORDLIST_HASH_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
        finally:
            os.close(fd)
        return digest.digest()
    # Fallback for non-POSIX or missing O_NOFOLLOW.
    import stat as _stat

    try:
        lst = path.lstat()
        if _stat.S_ISLNK(lst.st_mode):
            raise WordlistSecurityError("Custom wordlist path is a symlink — refused for security.")
        if not _stat.S_ISREG(lst.st_mode):
            raise WordlistSecurityError("Custom wordlist is not a regular file.")
    except OSError as exc:
        raise WordlistSecurityError(f"Cannot stat wordlist: {exc}") from exc
    with path.open("rb") as wordlist_file:
        for chunk in iter(lambda: wordlist_file.read(_WORDLIST_HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.digest()


def _read_wordlist_text_secure(path: Path) -> str:
    """Read wordlist text without following symlinks (TOCTOU defense).

    On POSIX uses ``O_NOFOLLOW``; on other platforms falls back to
    ``lstat`` symlink check before read.
    """
    _, text = _hash_and_read_wordlist(path)
    return text


def _hash_and_read_wordlist(path: Path) -> tuple[bytes, str]:
    """Single-pass hash+read for wordlist — halves I/O vs two opens.

    POSIX: one ``os.open(O_NOFOLLOW)`` → ``fstat`` → loop ``os.read``
    updating ``blake2b`` and collecting chunks.  Fallback: ``lstat`` +
    ``path.read_text`` with separate hash pass (still 2 reads, but rare).
    Returns ``(digest, text)``.
    """
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if os.name == "posix" and no_follow is not None:
        digest = hashlib.blake2b(digest_size=_WORDLIST_HASH_DIGEST_SIZE)
        try:
            fd = os.open(str(path), os.O_RDONLY | no_follow)
        except OSError as exc:
            import errno as _errno

            if exc.errno in (_errno.ELOOP, _errno.EMLINK) or "symlink" in str(exc).lower() or "Too many levels" in str(exc):
                raise WordlistSecurityError("Custom wordlist path is a symlink — refused for security.") from exc
            raise WordlistSecurityError(f"Cannot open wordlist: {exc}") from exc
        try:
            import stat as _stat

            st = os.fstat(fd)
            if _stat.S_ISLNK(st.st_mode):
                raise WordlistSecurityError("Custom wordlist path is a symlink — refused for security.")
            if not _stat.S_ISREG(st.st_mode):
                raise WordlistSecurityError("Custom wordlist is not a regular file.")
            if st.st_size > _MAX_WORDLIST_FILE_BYTES:
                raise WordlistSecurityError(
                    f"Custom wordlist too large ({st.st_size} bytes)."
                )
            chunks: list[bytes] = []
            while True:
                chunk = os.read(fd, _WORDLIST_HASH_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
                chunks.append(chunk)
            text = b"".join(chunks).decode("utf-8", errors="ignore")
            return digest.digest(), text
        finally:
            os.close(fd)
    # Fallback (Windows / no O_NOFOLLOW): two passes but still secure via lstat
    import stat as _stat

    try:
        lst = path.lstat()
        if _stat.S_ISLNK(lst.st_mode):
            raise WordlistSecurityError("Custom wordlist path is a symlink — refused for security.")
        if not _stat.S_ISREG(lst.st_mode):
            raise WordlistSecurityError("Custom wordlist is not a regular file.")
    except OSError as exc:
        raise WordlistSecurityError(f"Cannot stat wordlist: {exc}") from exc
    # Single read + hash in Python loop (one I/O pass)
    digest = hashlib.blake2b(digest_size=_WORDLIST_HASH_DIGEST_SIZE)
    text_bytes = path.read_bytes()
    digest.update(text_bytes)
    # Enforce file-size limit on actually-read bytes (covers race where file grew)
    if len(text_bytes) > _MAX_WORDLIST_FILE_BYTES:
        raise WordlistSecurityError(f"Custom wordlist too large ({len(text_bytes)} bytes).")
    return digest.digest(), text_bytes.decode("utf-8", errors="ignore")


def _parse_wordlist_lines(text: str) -> tuple[str, ...]:
    """Flat helper: parse wordlist text into deduped tuple, reusable."""
    raw_words: list[str] = []
    for line in text.splitlines():
        w = line.strip()
        if not w or w.startswith("#"):
            continue
        raw_words.append(w)
    return tuple(_dedupe_preserve_order(raw_words))


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
    # Security: validate custom wordlist path before any read.
    if is_custom and resolved_path is not None and resolved_path.exists():
        _validate_custom_wordlist_path(resolved_path)
    elif is_custom and resolved_path is not None and not resolved_path.exists():
        _log.warning(
            "Custom wordlist %s not found — falling back to bundled default. "
            "Check GENERATE_IT_WORDLIST or the --wordlist path.",
            resolved_path,
        )
    cache_path, mtime_ns, file_size = _get_file_signature(resolved_path)
    cached = _WORDLIST_CACHE.get(cache_path)
    if cached is not None:
        cached_mtime_ns, cached_size, cached_hash, cached_words = cached
        if (cached_mtime_ns, cached_size) == (mtime_ns, file_size):
            if cache_path is None:
                _WORDLIST_CACHE.move_to_end(cache_path)
                return list(cached_words)
            # Flat helper would skip hash, but correctness requires hash verification
            # when metadata collides (e.g., same size/mtime after rapid rewrite).
            if _hash_wordlist(cache_path) == cached_hash:
                _WORDLIST_CACHE.move_to_end(cache_path)
                return list(cached_words)

    if cache_path is None or not cache_path.exists():
        words_tuple = tuple(DEFAULT_WORDLIST)
        content_hash = b""
    else:
        # Re-validate symlink + size after signature (TOCTOU defense) and
        # before read.  Uses lstat so a swapped-in symlink is caught even if
        # the original validation passed.  Size is also checked inside
        # _hash_wordlist / _read_wordlist_text_secure via fstat.
        if is_custom:
            import stat as _stat

            try:
                lst = cache_path.lstat()
                if _stat.S_ISLNK(lst.st_mode):
                    raise WordlistSecurityError("Custom wordlist path is a symlink — refused for security.")
                if not _stat.S_ISREG(lst.st_mode):
                    raise WordlistSecurityError("Custom wordlist is not a regular file.")
                if lst.st_size > _MAX_WORDLIST_FILE_BYTES:
                    raise WordlistSecurityError(
                        f"Custom wordlist too large ({lst.st_size} bytes)."
                    )
            except OSError as exc:
                raise WordlistSecurityError(f"Cannot stat wordlist: {exc}") from exc
        content_hash, text = _hash_and_read_wordlist(cache_path)
        words_tuple = _parse_wordlist_lines(text)
        if len(words_tuple) > _MAX_WORDLIST_WORDS:
            raise WordlistSecurityError(
                f"Custom wordlist has {len(words_tuple)} unique words, exceeding maximum {_MAX_WORDLIST_WORDS}."
            )

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

    # Maintain bounded cache size (true LRU via OrderedDict).
    if len(_WORDLIST_CACHE) >= _WORDLIST_CACHE_MAX_SIZE:
        _WORDLIST_CACHE.popitem(last=False)
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
