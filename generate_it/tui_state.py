from __future__ import annotations

from dataclasses import dataclass, field
import time

from .storage import StorageManager
from ._bounded_set import BoundedSet


@dataclass
class AppState:
    mode: str = "chars"  # "chars", "words", or "username"

    char_length: int = 12
    use_letters: bool = True
    use_numbers: bool = True
    use_special: bool = False

    word_count: int = 4
    add_numbers: bool = True
    add_special: bool = False

    # Username settings
    username_style: str = "adjective"  # "adjective", "random", or "words"
    username_length: int = 12
    username_separator: str = "_"  # "_" or "-"
    username_word_count: int = 2
    username_add_numbers: bool = True

    output: str = ""
    seen_passphrases: BoundedSet[str] = field(default_factory=BoundedSet)

    message: str = "Press Enter (or g) to generate."
    focus_index: int = 0
    focus_items_cache_key: tuple[str, str, bool, bool] | None = None
    focus_items_cache: tuple[str, ...] = ()

    # Vault / Storage
    storage: StorageManager | None = None
    vault_unlocked: bool = False
    vault_credentials: list[dict] = field(default_factory=list)
    vault_scroll_y: int = 0
    vault_selected_idx: int = 0

    # Security settings
    clipboard_auto_clear_index: int = 2  # 30 seconds
    auto_lock_index: int = 2  # 5 minutes
    clipboard_clear_due_at: float | None = None
    clipboard_clear_expected: str | None = None
    last_activity_at: float = field(default_factory=time.monotonic)
    last_tick_at: float = field(default_factory=time.monotonic)

    # Transient: currently revealed credential secret (password + note).
    # Cleared on lock, modal close, selection change, and in finally block on modal exit.
    revealed_secret: dict | None = None
    revealed_secret_id: int | None = None

    failed_unlock_attempts: int = 0
    lockout_until: float | None = None
