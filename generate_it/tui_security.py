from __future__ import annotations

import curses
import time

from . import tui, tui_modal
from .storage import (
    CredentialIdentityConflictError,
    InvalidPasswordError,
    StorageError,
)
from .tui_state import AppState

_AAD_MIGRATION_MESSAGE = (
    "Your vault uses an older encryption binding (AAD v1/v2). "
    "A one-time upgrade to the current AAD format (v4) will re-encrypt "
    "all stored credentials with explicit length-delimited associated "
    "data and zero-width-stripped identities.\n\n"
    "A backup file will be created before migration.\n\n"
    "Proceed with upgrade? (y/N)"
)
_UNLOCK_RETRY_FLAG = "_tui_security_unlock_retry"
_UNLOCK_CANCELLED_FLAG = "_tui_security_unlock_cancelled"
LOCKOUT_DELAYS_SECONDS: tuple[int, ...] = (0, 30, 300, 1800)


def _now() -> float:
    return time.monotonic()


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
    """If the unlocked v2 vault is below the current AAD (v4), offer an upgrade.

    The current AAD (v4) uses unambiguous length-prefixed associated data
    binding with zero-width-stripped canonical identities.  The migration
    is opt-in with a confirmation prompt; a backup file is created before
    re-encryption.

    Note: v2 vaults still at AAD v3 are upgraded automatically to v4 by the
    unlock-time zero-width migration (``_migrate_zero_width_identity``), so
    by the time this runs after a successful unlock the predicate below
    only fires for AAD v1/v2 vaults.
    """
    if not _storage_available(state):
        return
    storage = state.storage
    if storage is None:
        return
    if storage._vault_version != 2 or storage._aad_version >= 4:
        return
    _maybe_migrate_aad_v4(stdscr, theme, state)


def _maybe_migrate_aad_v4(
    stdscr: curses.window,
    theme: tui.Theme,
    state: AppState,
) -> None:
    confirm = tui_modal._run_modal(
        stdscr,
        theme,
        "SECURITY UPGRADE",
        _AAD_MIGRATION_MESSAGE,
        max_length=3,
    )
    if confirm is None or confirm.strip().lower() not in {"y", "yes"}:
        state.message = "AAD upgrade deferred."
        return

    storage = state.storage
    if storage is None:
        return
    try:
        storage.migrate_aad_to_v4()
        state.message = "Vault upgraded to the current AAD format."
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

    if not _wait_for_lockout(stdscr, theme, state):
        setattr(state, _UNLOCK_CANCELLED_FLAG, True)
        return False

    try:
        storage.unlock_vault(pwd)
        state.vault_unlocked = True
        state.vault_credentials = storage.list_credential_metadata()
        state.failed_unlock_attempts = 0
        state.lockout_until = None
        tui._record_user_activity(state)
        state.message = "Vault unlocked."
        _maybe_show_identity_conflict(stdscr, theme, state)
        _maybe_prompt_aad_migration(stdscr, theme, state)
        return True
    except InvalidPasswordError:
        _record_unlock_failure(state)
        tui_modal._run_modal(stdscr, theme, "ERROR", "Invalid master password.")
        setattr(state, _UNLOCK_RETRY_FLAG, True)
    except StorageError as e:
        state.vault_unlocked = False
        state.vault_credentials = []
        # Post-authentication initialization failed (e.g. metadata load or a
        # migration/conflict step) after a successful unlock.  Fail closed on
        # the storage manager itself, not just the UI state: clear the decrypted
        # key material so no later code path can consult storage directly while
        # the UI reports the vault locked.
        storage.close()
        tui_modal._run_modal(stdscr, theme, "ERROR", f"Unlock failed: {e}")
        state.message = "Vault locked."
    return False


def _lockout_delay_for_attempt(attempts: int) -> int:
    if attempts <= 0:
        return 0
    return LOCKOUT_DELAYS_SECONDS[min(attempts - 1, len(LOCKOUT_DELAYS_SECONDS) - 1)]


def _get_lockout_remaining(state: AppState, now: float | None = None) -> float:
    if state.lockout_until is None:
        return 0.0
    current = _now() if now is None else now
    remaining = max(0.0, state.lockout_until - current)
    if remaining == 0.0:
        state.lockout_until = None
    return remaining


def _record_unlock_failure(state: AppState) -> None:
    state.failed_unlock_attempts += 1
    delay = _lockout_delay_for_attempt(state.failed_unlock_attempts)
    state.lockout_until = _now() + delay if delay else None


def _wait_for_lockout(
    stdscr: curses.window,
    theme: tui.Theme,
    state: AppState,
) -> bool:
    """Wait out a lockout window, allowing Esc to cancel the unlock flow."""
    while True:
        remaining = _get_lockout_remaining(state)
        if remaining <= 0:
            return True
        seconds = max(1, int(remaining + 0.999))
        state.message = f"Too many attempts. Try again in {seconds} seconds."
        try:
            stdscr.timeout(250)
            stdscr.erase()
            stdscr.addstr(0, 0, state.message)
            stdscr.refresh()
        except curses.error:
            pass
        if stdscr.getch() == 27:
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
        setattr(state, _UNLOCK_CANCELLED_FLAG, False)
        try:
            unlocked = _try_unlock_vault(stdscr, theme, state, pwd)
        finally:
            retry = getattr(state, _UNLOCK_RETRY_FLAG, False)
            cancelled = getattr(state, _UNLOCK_CANCELLED_FLAG, False)
            delattr(state, _UNLOCK_RETRY_FLAG)
            delattr(state, _UNLOCK_CANCELLED_FLAG)

        if unlocked:
            return True
        if cancelled:
            state.message = "Vault locked."
            return False
        if retry:
            continue
        return False
