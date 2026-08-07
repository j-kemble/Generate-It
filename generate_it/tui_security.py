from __future__ import annotations

import curses

from . import tui, tui_modal
from .storage import InvalidPasswordError, StorageError
from .tui_state import AppState

_AAD_MIGRATION_MESSAGE = (
    "Your vault uses an older encryption binding (AAD v1) "
    "that doesn't protect against credential metadata swaps. "
    "A one-time upgrade to AAD v2 will re-encrypt all stored "
    "credentials with stronger bindings.\n\n"
    "A backup file (vault.db.aad_v1.bak) will be created "
    "before migration.\n\nProceed with upgrade? (Y/n)"
)
_UNLOCK_RETRY_FLAG = "_tui_security_unlock_retry"


def _storage_available(state: AppState) -> bool:
    return state.storage is not None


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
    if not _storage_available(state):
        return
    storage = state.storage
    if storage is None:
        return
    if storage._vault_version != 2 or storage._aad_version >= 2:
        return
    _maybe_migrate_aad_v2(stdscr, theme, state)


def _maybe_migrate_aad_v2(
    stdscr: curses.window,
    theme: tui.Theme,
    state: AppState,
) -> None:
    confirm = tui_modal._run_modal(
        stdscr,
        theme,
        "SECURITY UPGRADE",
        _AAD_MIGRATION_MESSAGE,
        max_length=1,
    )
    if confirm is not None and confirm.strip().lower() == "n":
        state.message = "AAD upgrade deferred. Vault remains at v1."
        return

    storage = state.storage
    if storage is None:
        return
    try:
        storage.migrate_aad_v1_to_v2()
        state.message = "Vault upgraded to AAD v2."
    except StorageError as e:
        tui_modal._run_modal(
            stdscr,
            theme,
            "ERROR",
            f"AAD migration failed: {e}\nVault remains at v1.",
        )
        state.message = "AAD upgrade failed. Vault at v1."


def _try_unlock_vault(
    stdscr: curses.window,
    theme: tui.Theme,
    state: AppState,
    pwd: str,
) -> bool:
    storage = state.storage
    if storage is None:
        state.message = "Vault unavailable."
        return False

    try:
        storage.unlock_vault(pwd)
        state.vault_unlocked = True
        state.vault_credentials = storage.list_credential_metadata()
        tui._record_user_activity(state)
        state.message = "Vault unlocked."
        _maybe_prompt_aad_migration(stdscr, theme, state)
        return True
    except InvalidPasswordError:
        tui_modal._run_modal(stdscr, theme, "ERROR", "Invalid master password.")
        setattr(state, _UNLOCK_RETRY_FLAG, True)
    except StorageError as e:
        tui_modal._run_modal(stdscr, theme, "ERROR", f"Unlock failed: {e}")
        state.message = "Vault locked."
    return False


def _prompt_unlock_vault(
    stdscr: curses.window,
    theme: tui.Theme,
    state: AppState,
    *,
    reason: str,
) -> bool:
    if not _storage_available(state):
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

        setattr(state, _UNLOCK_RETRY_FLAG, False)
        try:
            unlocked = _try_unlock_vault(stdscr, theme, state, pwd)
        finally:
            retry = getattr(state, _UNLOCK_RETRY_FLAG, False)
            delattr(state, _UNLOCK_RETRY_FLAG)

        if unlocked:
            return True
        if retry:
            continue
        return False
