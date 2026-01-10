"""Core generation logic for Generate It.

This module is UI-agnostic: both the curses TUI and any CLI wrapper can use it.
"""

from __future__ import annotations

from pathlib import Path
import secrets
import string

MIN_PASSWORD_CHARS = 8
MAX_PASSWORD_CHARS = 24

MIN_PASSPHRASE_WORDS = 3
MAX_PASSPHRASE_WORDS = 10

LETTERS = string.ascii_letters
NUMBERS = string.digits
SPECIAL_CHARACTERS = "!@#$%^&*()-_=+[]{};:,.?/"

# Used when the user asks to add special characters to a passphrase.
PASSPHRASE_SPECIALS = "!@#$%&*?"

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORDLIST_PATH = PROJECT_ROOT / "wordlist.txt"

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


def secure_shuffle(items: list[str]) -> None:
    """Shuffle a list in-place using `secrets` for randomness."""
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]


def load_wordlist(path: Path | None = None) -> list[str]:
    """Load passphrase words from `wordlist.txt`.

    Lines starting with `#` and blank lines are ignored.
    Falls back to a small built-in list if the file is missing or too small.
    """

    path = WORDLIST_PATH if path is None else path

    if not path.exists():
        return DEFAULT_WORDLIST

    words: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        w = line.strip()
        if not w or w.startswith("#"):
            continue
        words.append(w)

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

    if len(pools) < 2:
        raise ValueError("At least two categories must be selected")

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
