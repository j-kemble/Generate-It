"""Central constants for Generate It."""

from __future__ import annotations

# --- TUI constants (from tui.py) ---
ESC_QUIT_WINDOW_SECONDS = 1.0
AUTO_LOCK_SCREEN_OFF = "screen_off"
SCREEN_OFF_LOCK_GAP_SECONDS = 20.0

CLIPBOARD_AUTO_CLEAR_OPTIONS: tuple[tuple[str, int | None], ...] = (
    ("No auto-clear", None),
    ("15 seconds", 15),
    ("30 seconds", 30),
    ("45 seconds", 45),
    ("1 minute", 60),
    ("2 minutes", 120),
    ("3 minutes", 180),
)

AUTO_LOCK_OPTIONS: tuple[tuple[str, int | str | None], ...] = (
    ("No auto-lock", None),
    ("Lock when screen off", AUTO_LOCK_SCREEN_OFF),
    ("5 minutes", 5 * 60),
    ("10 minutes", 10 * 60),
    ("15 minutes", 15 * 60),
)

SETTING_KEY_CLIPBOARD_AUTO_CLEAR_INDEX = "clipboard_auto_clear_index"
SETTING_KEY_AUTO_LOCK_INDEX = "auto_lock_index"

# --- Rate limiting (from tui_security.py) ---
# Escalating delays after failed unlock attempts.
LOCKOUT_DELAYS_SECONDS = [0, 30, 300, 1800]  # 1st=immediate, 2nd=30s, 3rd=5min, 4th+=30min

# --- Storage constants (from storage.py) ---
_DEFAULT_PBKDF2_ITERATIONS = 480_000
_DEFAULT_SALT_LENGTH = 32
_LEGACY_PBKDF2_ITERATIONS = 100_000

_MAX_MASTER_PASSWORD_LENGTH = 1024

_MAX_CSV_FILE_BYTES = 10 * 1024 * 1024  # 10 MB
_MAX_CSV_ROWS = 10_000
_MAX_CSV_FIELD_BYTES = 500

# Identity schema marker
_IDENTITY_SCHEMA_VERSION = 1
# Index names (also asserted by tests).
_IDX_IDENTITY_UNIQUE = "idx_credentials_identity"
_IDX_IDENTITY_ORDER = "idx_credentials_order"

# --- Generator constants (from generator.py) ---
MIN_PASSWORD_CHARS = 8
MAX_PASSWORD_CHARS = 64

MIN_PASSPHRASE_WORDS = 3
MAX_PASSPHRASE_WORDS = 10

MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 64
MIN_USERNAME_WORDS = 1
MAX_USERNAME_WORDS = 3

# Username-related character sets.
LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
NUMBERS = "0123456789"
SPECIAL_CHARACTERS = "!@#$%^&*()-_=+[]{};:,.?/"

# Username-related character sets.
USERNAME_ALPHANUMERIC = "abcdefghijklmnopqrstuvwxyz0123456789"
USERNAME_SEPARATORS = frozenset(["_", "-"])

# Username styles
USERNAME_STYLE_ADJECTIVE = "adjective"
USERNAME_STYLE_RANDOM = "random"
USERNAME_STYLE_WORDS = "words"

# PASSPHRASE_SPECIALS moved from generator.py
PASSPHRASE_SPECIALS = "!@#$%&*?"  # nosec B105 — character pool, not a credential

# Wordlist
PACKAGED_WORDLIST_PATH = "__default_wordlist_path__"  # Will be set at runtime from generator

# Default built-in wordlist (from generator.py)
DEFAULT_WORDLIST = [
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

_MIN_PASSPHRASE_ENTROPY_BITS = 50.0