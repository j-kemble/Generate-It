from __future__ import annotations

import curses
from typing import Optional

from . import tui
from . import tui_modal
from .tui_state import AppState
from .storage import StorageManager, InvalidPasswordError, StorageError


def _maybe_prompt_aad_migration(
    stdscr: curses.window,
    theme: tui.Theme,
    state: AppState,
) -> None:
    """If the unlocked v2 vault is at AAD v1, offer a one-time upgrade to v2.

    AAD v2 binds ciphertext to service+username metadata, preventing
    UUID+ciphertext substitution attacks.  The migration is opt-in with
    a confirmation prompt; a backup file is created before re-encryption.
    """
    if not state.storage:
        return
    if state.storage._vault_version != 2:
        return
    if state.storage._aad_version < 2:
        confirm = tui_modal._run_modal(
            stdscr,
            theme,
            "SECURITY UPGRADE",
            "Your vault uses an older encryption binding (AAD v1) "
            "that doesn't protect against credential metadata swaps. "
            "A one-time upgrade to AAD v2 will re-encrypt all stored "
            "credentials with stronger bindings.\n\n"
            "A backup file (vault.db.aad_v1.bak) will be created "
            "before migration.\n\nProceed with upgrade? (Y/n)",
            max_length=1,
        )
        if confirm is not None and confirm.strip().lower() == "n":
            state.message = "AAD upgrade deferred. Vault remains at v1."
            return
        try:
            state.storage.migrate_aad_v1_to_v2()
            state.message = "Vault upgraded to AAD v2."
        except StorageError as e:
            tui_modal._run_modal(
                stdscr, theme, "ERROR",
                f"AAD migration failed: {e}\nVault remains at v1.",
            )
            state.message = "AAD upgrade failed. Vault at v1."


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
            state.vault_credentials = state.storage.list_credential_metadata()
            tui._record_user_activity(state)
            state.message = "Vault unlocked."
            _maybe_prompt_aad_migration(stdscr, theme, state)
            return True
        except InvalidPasswordError:
            tui_modal._run_modal(stdscr, theme, "ERROR", "Invalid master password.")
        except StorageError as e:
            tui_modal._run_modal(stdscr, theme, "ERROR", f"Unlock failed: {e}")
            state.message = "Vault locked."
            return False
