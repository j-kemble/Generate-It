from __future__ import annotations

import curses
from typing import Optional

from . import tui
from . import tui_modal
from .tui_state import AppState
from .storage import StorageManager, InvalidPasswordError, StorageError


def _prompt_unlock_vault(
    stdscr: curses.window,
    theme: tui.Theme,
    state: AppState,
    *,
    reason: str,
) -> bool:
    if not state.storage:
        state.message = "Vault unavailable."
        return False

    while True:
        pwd = tui_modal._run_modal(
            stdscr,
            theme,
            "VAULT LOCKED",
            f"{reason} Enter Master Password to unlock (Esc to keep locked):",
            is_password=True,
            max_length=200,
        )
        if pwd is None:
            state.message = "Vault locked."
            return False

        try:
            state.storage.unlock_vault(pwd)
            state.vault_unlocked = True
            state.vault_credentials = state.storage.list_credentials()
            tui._record_user_activity(state)
            state.message = "Vault unlocked."
            return True
        except InvalidPasswordError:
            tui_modal._run_modal(stdscr, theme, "ERROR", "Invalid master password.")
        except StorageError as e:
            tui_modal._run_modal(stdscr, theme, "ERROR", f"Unlock failed: {e}")
            state.message = "Vault locked."
            return False
