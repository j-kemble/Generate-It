from __future__ import annotations

import curses

from . import tui, tui_modal
from .storage import (
    CredentialIdentityConflictError,
    InvalidPasswordError,
    StorageError,
)
from .tui_state import AppState

_AAD_MIGRATION_MESSAGE = (
    "Your vault uses an older encryption binding (AAD v1/v2). "
    "A one-time upgrade to AAD v3 will re-encrypt all stored "
    "credentials with explicit length-delimited associated data.\n\n"
    "A backup file will be created before migration.\n\n"
    "Proceed with upgrade? (Y/n)"
)
_UNLOCK_RETRY_FLAG = "_tui_security_unlock_retry"


def _storage_available(state: AppState) -> bool:
    return state.storage is not None


def _maybe_show_identity_conflict(
    stdscr: curses.window,
    theme: tui.Theme,
    state: AppState,
) -> None:
    """Surface deferred canonical-identity conflicts after unlock.

    The identity-schema migration is non-destructive: when existing rows
    collide under the canonical identity rules, the vault stays usable and
    ``storage.identity_conflict`` carries the details.  Show them here so
    the user can remediate (rename/delete in the vault explorer); the
    migration retries on the next unlock.
    """
    if not _storage_available(state):
        return
    storage = state.storage
    # isinstance (not a truthiness/None check) so duck-typed or mocked
    # storage objects without a real conflict object never trigger the modal.
    conflict = getattr(storage, "identity_conflict", None)
    if not isinstance(conflict, CredentialIdentityConflictError):
        return
    lines = [
        "Some stored credentials are duplicates under the vault's identity",
        "rules (same service/username ignoring case, surrounding whitespace,",
        "and equivalent Unicode).",
        "",
        "Nothing was changed or deleted, but the uniqueness upgrade is",
        "deferred until the duplicates are resolved.",
        "",
        "Conflicting entries (id: service / username):",
    ]
    for item in conflict.conflicts:
        item_ids = item.get("ids", [])
        if isinstance(item_ids, list):
            ids = ", ".join(str(i) for i in item_ids)
        else:
            ids = str(item_ids)
        lines.append(f"- #{ids}: {item['service']} / {item['username']}")
    lines.extend(
        [
            "",
            "Open the vault explorer (v), rename or delete the duplicates,",
            "then restart the app to finish the upgrade.",
        ]
    )
    tui_modal._run_scrollable_modal(stdscr, theme, "VAULT UPGRADE NEEDED", lines)
    state.message = "Duplicate credentials need attention (vault explorer)."


def _maybe_prompt_aad_migration(
    stdscr: curses.window,
    theme: tui.Theme,
    state: AppState,
) -> None:
    """If the unlocked v2 vault is at AAD v1 or v2, offer a one-time upgrade to v3.

    AAD v3 uses unambiguous length-prefixed associated data binding.  The
    migration is opt-in with a confirmation prompt; a backup file is created
    before re-encryption.
    """
    if not _storage_available(state):
        return
    storage = state.storage
    if storage is None:
        return
    if storage._vault_version != 2 or storage._aad_version >= 3:
        return
    _maybe_migrate_aad_v3(stdscr, theme, state)


def _maybe_migrate_aad_v3(
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
        state.message = "AAD upgrade deferred."
        return

    storage = state.storage
    if storage is None:
        return
    try:
        storage.migrate_aad_to_v3()
        state.message = "Vault upgraded to AAD v3."
    except StorageError as e:
        tui_modal._run_modal(
            stdscr,
            theme,
            "ERROR",
            f"AAD migration failed: {e}",
        )
        state.message = "AAD upgrade failed."


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
        _maybe_show_identity_conflict(stdscr, theme, state)
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
