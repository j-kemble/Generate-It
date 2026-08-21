from __future__ import annotations

import curses
import time

from . import tui, tui_modal
from .storage import (
    CredentialIdentityConflictError,
    InvalidPasswordError,
    StorageError,
    WeakMasterPasswordError,
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
from .constants import LOCKOUT_DELAYS_SECONDS  # noqa: E402  single source


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


_V1_LEGACY_MESSAGE = (
    "Your vault uses legacy PBKDF2 iterations (100k). "
    "Recommended is 480k or migrating to v2 (Argon2id, 64 MiB, 3 iter). "
    "A backup will be created before migration.\n\n"
    "Migrate now to v2? (y/N)"
)

def _maybe_prompt_v1_legacy_migration(
    stdscr: curses.window,
    theme: tui.Theme,
    state: AppState,
) -> None:
    """Prompt to migrate a legacy v1 vault to v2."""
    if not _storage_available(state) or state.storage is None:
        return
    storage = state.storage
    if storage._vault_version != 1:
        return
    needs_upgrade = getattr(storage, "_legacy_pbkdf2_needs_upgrade", False)
    if not needs_upgrade:
        return
    confirm = tui_modal._run_modal(
        stdscr, theme, "SECURITY UPGRADE", _V1_LEGACY_MESSAGE, max_length=3,
    )
    if confirm is None or confirm.strip().lower() not in {"y", "yes"}:
        state.message = "v1 legacy upgrade deferred. Use health menu (m) to migrate."
        return
    # Need master password to re-derive keys.
    pwd = tui_modal._run_modal(
        stdscr, theme, "MIGRATE TO V2", "Enter master password to migrate:", is_password=True, max_length=200,
    )
    if pwd is None:
        state.message = "v1 migration cancelled."
        return
    try:
        storage.migrate_v1_to_v2(pwd)
        state.message = "Vault migrated to v2 (Argon2id)."
    except InvalidPasswordError:
        tui_modal._run_modal(stdscr, theme, "ERROR", "Master password incorrect — migration aborted.")
        state.message = "v1 migration failed."
    except StorageError as e:
        tui_modal._run_modal(stdscr, theme, "ERROR", f"Migration failed: {e}")
        state.message = "v1 migration failed."
    finally:
        # Explicitly clear password reference.
        try:
            del pwd
        except Exception:
            pass


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


def _sync_persistent_lockout_from_storage(state: AppState) -> None:
    """Load persisted lockout into in-memory state (survives restarts).

    Lockout persistence is inherently wall-clock based (``time.time()`` epoch
    stored in the config table) so it survives restarts, while in-memory
    enforcement uses ``time.monotonic()`` to resist intra-session clock
    adjustments.  A forward system-clock jump between sessions can make
    ``until_epoch - time.time()`` negative and clear the persisted deadline
    prematurely — the wall-clock value cannot be bound to monotonic time
    across reboots.  The ``failed_unlock_attempts`` counter is *preserved*
    even when the deadline has expired, so escalation (30s → 5min → 30min)
    is not reset by waiting out or by a clock jump; the next failure still
    escalates.  Within a single process the monotonic remaining is kept if
    it exceeds the wall-clock remaining, providing best-effort resistance to
    intra-session NTP adjustments.  Backward jumps are detected via
    ``lockout_set_epoch`` and the remaining window is capped to the original
    delay so the lockout is not extended indefinitely.
    """
    if not _storage_available(state) or state.storage is None:
        return
    try:
        attempts, until_epoch = state.storage.get_persistent_lockout_state()
    except Exception:
        return
    # Fetch set_epoch for backward-jump detection (best-effort, legacy vaults
    # may not have it).
    set_epoch = None
    try:
        set_epoch = state.storage.get_persistent_lockout_set_epoch()
    except Exception:
        set_epoch = None
    if attempts:
        state.failed_unlock_attempts = max(state.failed_unlock_attempts, attempts)
    if until_epoch is not None:
        now_wall = time.time()
        remaining = until_epoch - now_wall
        # Backward jump detection: if wall clock went backward after the
        # lockout was set, remaining would exceed the original delay.
        if set_epoch is not None and until_epoch is not None:
            try:
                delay = float(until_epoch - set_epoch)
                if now_wall < set_epoch and remaining > delay:
                    remaining = delay
                # Also cap any remaining that somehow exceeds delay due to
                # clock skew (defense-in-depth, never extend beyond original).
                if remaining > delay:
                    remaining = delay
            except Exception:
                pass
        if remaining > 0:
            # Keep the longer of in-memory (monotonic) vs persisted (wall)
            # remaining — defends against backward clock jumps within the
            # same process lifetime.
            in_mem_remaining = _get_lockout_remaining(state)
            needed_monotonic = time.monotonic() + remaining
            if in_mem_remaining <= 0 or remaining > in_mem_remaining:
                state.lockout_until = needed_monotonic
        else:
            # Expired — keep attempt count (escalation) but clear the wall-clock deadline.
            # Do not delete the persisted attempt counter, otherwise a restart after
            # waiting out the lockout would reset escalation.  Forward clock
            # jumps are an inherent limitation of wall-clock persistence
            # (see docstring).
            try:
                state.storage.set_persistent_lockout_state(attempts, None)
            except Exception:
                pass
            # In-memory expiry.
            if state.lockout_until is not None and _get_lockout_remaining(state) <= 0:
                state.lockout_until = None
                # Keep failed_unlock_attempts at max(attempts, current) — attempts
                # only reset on successful unlock.


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

    _sync_persistent_lockout_from_storage(state)
    if not _wait_for_lockout(stdscr, theme, state):
        setattr(state, _UNLOCK_CANCELLED_FLAG, True)
        return False

    # Ensure plaintext pwd does not linger in this frame beyond the attempt.
    try:
        try:
            storage.unlock_vault(pwd)
            state.vault_unlocked = True
            state.vault_credentials = storage.list_credential_metadata()
            state.failed_unlock_attempts = 0
            state.lockout_until = None
            try:
                storage.clear_persistent_lockout_state()
            except Exception:
                pass
            tui._record_user_activity(state)
            state.message = "Vault unlocked."
            _maybe_show_identity_conflict(stdscr, theme, state)
            _maybe_prompt_v1_legacy_migration(stdscr, theme, state)
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
    finally:
        try:
            pwd = "\x00" * len(pwd)
        except Exception:
            pass
        try:
            del pwd
        except Exception:
            pass


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
    # Persist across restarts — wall-clock epoch for cross-process survival.
    if _storage_available(state) and state.storage is not None:
        try:
            until_epoch = (time.time() + delay) if delay else None
            state.storage.set_persistent_lockout_state(
                state.failed_unlock_attempts, until_epoch
            )
        except Exception:
            pass


def _wait_for_lockout(
    stdscr: curses.window,
    theme: tui.Theme,
    state: AppState,
) -> bool:
    """Wait out a lockout window, allowing Esc to cancel the unlock flow."""
    _sync_persistent_lockout_from_storage(state)
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
            # Minimize lifetime of plaintext master password.
            try:
                pwd = "\x00" * len(pwd)
            except Exception:
                pass
            try:
                del pwd
            except Exception:
                pass

        if unlocked:
            return True
        if cancelled:
            state.message = "Vault locked."
            return False
        if retry:
            continue
        return False


# ------------------------------------------------------------------
# P0 — flat modular flows for password change / DEK rotation / health
# ------------------------------------------------------------------

def _ask_current_password(stdscr: curses.window, theme: tui.Theme) -> str | None:
    return tui_modal._run_modal(
        stdscr, theme, "CHANGE PASSWORD", "Enter CURRENT master password:", is_password=True, max_length=200,
    )


def _ask_new_password_pair(
    stdscr: curses.window, theme: tui.Theme,
) -> tuple[str, str] | None:
    first = tui_modal._run_modal(
        stdscr, theme, "CHANGE PASSWORD", "Enter NEW master password:", is_password=True, max_length=200,
    )
    if first is None:
        return None
    second = tui_modal._run_modal(
        stdscr, theme, "CHANGE PASSWORD", "Confirm NEW master password:", is_password=True, max_length=200,
    )
    if second is None:
        return None
    return first, second


def _confirm_action(stdscr: curses.window, theme: tui.Theme, title: str, prompt: str) -> bool:
    answer = tui_modal._run_modal(stdscr, theme, title, prompt, max_length=3)
    return answer is not None and answer.strip().lower() in {"y", "yes"}


def prompt_change_master_password(
    stdscr: curses.window, theme: tui.Theme, state: AppState,
) -> None:
    """Interactive master-password change (flat orchestration)."""
    if not _storage_available(state) or state.storage is None or not state.vault_unlocked:
        tui_modal._run_modal(stdscr, theme, "ERROR", "Vault must be unlocked to change password.")
        return
    current = _ask_current_password(stdscr, theme)
    if current is None:
        state.message = "Password change cancelled."
        return
    pair = _ask_new_password_pair(stdscr, theme)
    if pair is None:
        state.message = "Password change cancelled."
        # Clear current promptly even on cancel.
        try:
            current = "\x00" * len(current)
        except Exception:
            pass
        try:
            del current
        except Exception:
            pass
        return
    new_pass, confirm = pair
    if new_pass != confirm:
        tui_modal._run_modal(stdscr, theme, "ERROR", "New passwords do not match.")
        state.message = "Password change failed: mismatch."
        try:
            current = "\x00" * len(current)
        except Exception:
            pass
        try:
            new_pass = "\x00" * len(new_pass)
        except Exception:
            pass
        try:
            confirm = "\x00" * len(confirm)
        except Exception:
            pass
        try:
            del current, new_pass, confirm
        except Exception:
            pass
        return
    try:
        _execute_password_change(stdscr, theme, state, current, new_pass)
    finally:
        try:
            current = "\x00" * len(current)
        except Exception:
            pass
        try:
            new_pass = "\x00" * len(new_pass)
        except Exception:
            pass
        try:
            confirm = "\x00" * len(confirm)
        except Exception:
            pass
        try:
            del current, new_pass, confirm
        except Exception:
            pass


def _execute_password_change(
    stdscr: curses.window, theme: tui.Theme, state: AppState, current: str, new_pass: str,
) -> None:
    assert state.storage is not None
    try:
        state.storage.change_master_password(current, new_pass)
    except WeakMasterPasswordError as exc:
        tui_modal._run_modal(stdscr, theme, "ERROR", f"Weak password: {exc}")
        state.message = "Password change failed: weak password."
    except InvalidPasswordError:
        tui_modal._run_modal(stdscr, theme, "ERROR", "Current password is incorrect.")
        state.message = "Password change failed: incorrect current password."
    except StorageError as exc:
        tui_modal._run_modal(stdscr, theme, "ERROR", f"Password change failed: {exc}")
        state.message = "Password change failed."
    else:
        tui_modal._run_modal(stdscr, theme, "SUCCESS", "Master password changed. Use the new password next unlock.")
        state.message = "Master password changed."
    finally:
        # Ensure caller's references are not retained beyond this scope;
        # actual wiping is done by caller, but clear local copies too.
        try:
            current = "\x00" * len(current)
            new_pass = "\x00" * len(new_pass)
        except Exception:
            pass


def prompt_rotate_dek(
    stdscr: curses.window, theme: tui.Theme, state: AppState,
) -> None:
    """Interactive DEK rotation (v2 only, flat flow)."""
    if not _storage_available(state) or state.storage is None or not state.vault_unlocked:
        tui_modal._run_modal(stdscr, theme, "ERROR", "Vault must be unlocked.")
        return
    if state.storage._vault_version != 2:
        tui_modal._run_modal(stdscr, theme, "ERROR", "DEK rotation requires a v2 vault.")
        return
    if not _confirm_action(stdscr, theme, "ROTATE DEK",
                           "Rotate encryption key? Re-encrypts all credentials and creates a backup. Continue? (y/N)"):
        state.message = "DEK rotation cancelled."
        return
    current = tui_modal._run_modal(
        stdscr, theme, "ROTATE DEK", "Enter current master password to authorize:", is_password=True, max_length=200,
    )
    if current is None:
        state.message = "DEK rotation cancelled."
        return
    try:
        assert state.storage is not None
        state.storage.rotate_dek(current)
    except InvalidPasswordError:
        tui_modal._run_modal(stdscr, theme, "ERROR", "Current password is incorrect.")
        state.message = "DEK rotation failed."
    except StorageError as exc:
        tui_modal._run_modal(stdscr, theme, "ERROR", f"DEK rotation failed: {exc}")
        state.message = "DEK rotation failed."
    else:
        tui_modal._run_modal(stdscr, theme, "SUCCESS", "DEK rotated. All credentials re-encrypted.")
        state.message = "DEK rotated."
    finally:
        try:
            current = "\x00" * len(current)
        except Exception:
            pass
        try:
            del current
        except Exception:
            pass


def prompt_vault_health(
    stdscr: curses.window, theme: tui.Theme, state: AppState,
) -> None:
    """Show vault status and offer backup prune / integrity check."""
    if not _storage_available(state) or state.storage is None:
        tui_modal._run_modal(stdscr, theme, "ERROR", "Vault unavailable.")
        return
    assert state.storage is not None
    status = state.storage.get_vault_status()
    lines = _format_status_lines(status)
    choice = tui_modal._run_modal(
        stdscr, theme, "VAULT HEALTH",
        "\n".join(lines) + "\n\nActions: (p)rune backups  (c)heck integrity  (Esc)close",
        max_length=1,
    )
    if choice is None:
        return
    action = choice.strip().lower()
    if action == "p":
        _handle_prune_backups(stdscr, theme, state)
    elif action == "c":
        _handle_integrity_check(stdscr, theme, state)


def _format_status_lines(status: dict) -> list[str]:
    lines = [
        f"Vault: {status.get('vault_path', '(unknown)')}",
        f"Exists: {status.get('exists')}",
        f"Unlocked: {status.get('is_unlocked')}",
        f"Version: {status.get('version')}",
        f"AAD: {status.get('aad_version')}",
        f"Credentials: {status.get('credential_count', 0)}",
        f"Backups: {status.get('backup_count', 0)} (retain {status.get('backup_retain', 5)})",
    ]
    if status.get("backup_warning"):
        lines.append("WARNING: many backups — consider pruning (p). Auto-prune keeps 5 newest.")
    if status.get("dek_generation") is not None:
        lines.append(f"DEK generation: {status.get('dek_generation')}")
    for backup in status.get("backups", [])[:6]:
        lines.append(f"  - {backup}")
    if len(status.get("backups", [])) > 6:
        lines.append(f"  ... and {len(status['backups']) - 6} more")
    return lines


def _handle_prune_backups(stdscr: curses.window, theme: tui.Theme, state: AppState) -> None:
    if state.storage is None:
        return
    backups = state.storage.list_backups()
    if not backups:
        tui_modal._run_modal(stdscr, theme, "PRUNE", "No backups to prune.")
        return
    if not _confirm_action(stdscr, theme, "PRUNE BACKUPS",
                           f"Found {len(backups)} backup(s). Keep newest 1 and delete the rest? (y/N)"):
        state.message = "Prune cancelled."
        return
    deleted = state.storage.prune_backups(keep_latest=1)
    tui_modal._run_modal(stdscr, theme, "PRUNE", f"Deleted {len(deleted)} backup(s).")
    state.message = f"Pruned {len(deleted)} backup(s)."


def _handle_integrity_check(stdscr: curses.window, theme: tui.Theme, state: AppState) -> None:
    """Flat helper: streaming integrity check with 60 fps progress, reusable."""
    if state.storage is None or not state.vault_unlocked:
        tui_modal._run_modal(stdscr, theme, "ERROR", "Vault must be unlocked to check integrity.")
        return
    from .constants import _VAULT_INTEGRITY_BATCH_SIZE as _BATCH

    issues: list[dict] = []
    # Stream in batches so 2B vault does not block TUI at 60 fps
    for issue in state.storage.iter_integrity_issues(batch_size=_BATCH):
        issues.append(issue)
        # Keep UI responsive every batch (non-blocking refresh)
        if len(issues) % _BATCH == 0:
            try:
                stdscr.noutrefresh()
            except curses.error:
                pass
    if not issues:
        tui_modal._run_modal(stdscr, theme, "HEALTH", "Integrity OK: all credentials decrypt correctly.")
        state.message = "Integrity check passed."
        return
    lines = [f"Found {len(issues)} issue(s):"]
    for item in issues[:10]:
        lines.append(f"  id={item['id']} service={item['service']} err={item['error']}")
    tui_modal._run_scrollable_modal(stdscr, theme, "HEALTH ISSUES", lines)
    state.message = f"Integrity check: {len(issues)} issue(s)."
