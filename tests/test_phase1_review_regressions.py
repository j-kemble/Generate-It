from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from generate_it import identity, logging as app_logging, tui, tui_flow, tui_security
from generate_it.storage import InvalidPasswordError, StorageError, StorageManager


def test_intermediate_log_directory_symlink_is_rejected(tmp_path: Path) -> None:
    app_logging._reset_logging()
    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(app_logging.LoggingError, match="symlink"):
        app_logging.init_logging(link / "nested" / "app.log")

    assert not (target / "nested" / "app.log").exists()


def test_v1_master_password_limit_is_checked_in_utf8_bytes(tmp_path: Path) -> None:
    storage = StorageManager(db_path=tmp_path / "v1.db")
    try:
        with pytest.raises(StorageError, match="password exceeds 1024 bytes"):
            storage.initialize_vault("é" * 600 + "A1!")
    finally:
        storage.close()


def test_identity_lookup_uses_zero_width_stripped_canonical_key(temp_storage_initialized) -> None:
    storage = temp_storage_initialized
    storage.save_credential("Gmail\u200b", "user", "secret")

    found = storage.find_credential_by_identity("Gmail\u200b", "user")

    assert found is not None
    assert found["service"] == "Gmail\u200b"
    assert identity.validate_identity("Gmail\u200b", "user") == ("gmail", "user")


def test_v1_to_v2_migration_rejects_oversized_note_as_storage_error(tmp_path: Path) -> None:
    storage = StorageManager(db_path=tmp_path / "migration.db")
    master = "A-Strong-Passw0rd!"
    try:
        storage.initialize_vault(master)
        storage.save_credential("Service", "user", "password", "n")
        conn = storage._get_conn()
        oversized_note = storage._fernet.encrypt(("n" * 70000).encode())
        conn.execute("UPDATE credentials SET encrypted_note=? WHERE id=1", (oversized_note,))
        conn.commit()

        with pytest.raises(StorageError, match="note exceeds 65536 bytes"):
            storage.migrate_v1_to_v2(master)
    finally:
        storage.close()


def test_aad_migration_accepts_note_within_note_limit(tmp_path: Path) -> None:
    storage = StorageManager(db_path=tmp_path / "aad.db")
    master = "A-Strong-Passw0rd!"
    try:
        storage.initialize_vault_v2(master)
        storage._aad_version = 2
        storage._get_conn().execute("UPDATE config SET value='2' WHERE key='aad_version'")
        storage._get_conn().commit()
        storage.save_credential("Service", "user", "password", "n" * 1500)

        storage.migrate_aad_to_v3()
        assert storage.get_credential_secret(1)["note"] == "n" * 1500
    finally:
        storage.close()


def test_copy_helper_raises_when_clipboard_backend_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    from pyperclip import PyperclipException

    monkeypatch.setattr(tui_flow.pyperclip, "copy", MagicMock(side_effect=PyperclipException("down")))

    with pytest.raises(PyperclipException):
        tui_flow._copy_to_clipboard_with_policy(tui.AppState(), "secret")


def test_details_modal_bounds_long_note_and_marks_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    state = tui.AppState()
    state.storage = MagicMock()
    state.storage.get_credential_secret.return_value = {
        "password": "secret",
        "note": "long-note " * 200,
        "note_is_hidden": False,
    }
    theme = SimpleNamespace(title=0, dim=0, ok=1, warn=2)
    credential = {"id": 1, "service": "Service", "username": "user", "created_at": "today"}
    stdscr = MagicMock()
    stdscr.getmaxyx.return_value = (40, 120)
    window = MagicMock()
    window.getch.return_value = 27
    monkeypatch.setattr(tui.curses, "newwin", MagicMock(return_value=window))
    monkeypatch.setattr(tui, "_maybe_auto_clear_clipboard", lambda state: False)
    monkeypatch.setattr(tui, "_should_auto_lock_now", lambda state: False)
    monkeypatch.setattr(tui, "_record_user_activity", lambda state: None)

    tui._run_details_modal(stdscr, theme, state, credential)

    addstr_calls = [call for call in window.method_calls if call[0] == "addstr"]
    assert all(call.args[0] < 14 for call in addstr_calls)
    assert any("[truncated]" in str(call.args[2]) for call in addstr_calls)


def test_prompt_unlock_reuses_guarded_helper_for_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = MagicMock()
    storage.unlock_vault.side_effect = InvalidPasswordError()
    state = tui.AppState(storage=storage)
    responses = iter(["wrong", None])

    def modal_response(*args, **kwargs):
        if args[2] == "ERROR":
            return None
        return next(responses)

    monkeypatch.setattr(tui_security.tui_modal, "_run_modal", modal_response)
    monkeypatch.setattr(tui_security, "_now", lambda: 100.0)

    assert tui_security._prompt_unlock_vault(None, None, state, reason="Retry:") is False
    assert storage.unlock_vault.call_count == 1
    assert state.failed_unlock_attempts == 1


@pytest.mark.parametrize(
    "weak_password",
    ["Qwerty123!", "Welcome1!", "Admin123!", "qwerty", "123456", "letmein"],
)
def test_representative_common_passwords_are_rejected(temp_storage, weak_password: str) -> None:
    with pytest.raises(StorageError):
        temp_storage.initialize_vault(weak_password)
    with pytest.raises(StorageError):
        temp_storage.initialize_vault_v2(weak_password)


# ---------------------------------------------------------------------------
# Integration-level startup unlock (drives the real guarded path with a real
# on-disk storage manager; only the curses surface is faked).
# ---------------------------------------------------------------------------


class _FakeStdscr:
    def timeout(self, ms: int) -> None:
        pass

    def erase(self) -> None:
        pass

    def addstr(self, y: int, x: int, text: str) -> None:
        pass

    def refresh(self) -> None:
        pass

    def getch(self) -> int:
        return 27  # Esc


def _make_store(tmp_path: Path, master: str) -> Path:
    db_path = tmp_path / "int_vault.db"
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault_v2(master)
    storage.save_credential("GitHub", "octocat", "secret")
    storage.close()
    return db_path


def test_integration_unlock_real_storage_success_then_wrong_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real guarded startup unlock: success resets lockout, wrong resets DEK."""
    master = "A-Strong-Passw0rd!"
    db_path = _make_store(tmp_path, master)
    storage = StorageManager(db_path=db_path)
    state = tui.AppState(storage=storage)
    monkeypatch.setattr(tui_security.tui_modal, "_run_modal", lambda *a, **k: None)
    monkeypatch.setattr(tui_security.tui, "_record_user_activity", lambda s: None)
    monkeypatch.setattr(tui_security, "_maybe_show_identity_conflict", lambda *a: None)
    monkeypatch.setattr(tui_security, "_maybe_prompt_aad_migration", lambda *a: None)

    # Correct password unlocks end-to-end against the real vault.
    assert tui_security._try_unlock_vault(_FakeStdscr(), None, state, master) is True
    assert state.vault_unlocked is True
    assert storage._dek is not None and storage._vault_uuid is not None

    # Re-lock, then an invalid password fails and keeps storage locked.
    storage.close()
    state.vault_unlocked = False
    state.vault_credentials = []
    assert tui_security._try_unlock_vault(_FakeStdscr(), None, state, "wrong") is False
    assert state.vault_unlocked is False
    assert state.failed_unlock_attempts == 1
    # Invalid password never established key material.
    assert storage._dek is None and storage._vault_uuid is None
    storage.close()


def test_integration_post_auth_failure_locks_real_storage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Post-authentication init failure tears down the unlocked real storage."""
    master = "A-Strong-Passw0rd!"
    db_path = _make_store(tmp_path, master)
    storage = StorageManager(db_path=db_path)
    state = tui.AppState(storage=storage)
    monkeypatch.setattr(tui_security.tui_modal, "_run_modal", lambda *a, **k: None)
    monkeypatch.setattr(tui_security.tui, "_record_user_activity", lambda s: None)
    monkeypatch.setattr(tui_security, "_maybe_show_identity_conflict", lambda *a: None)
    monkeypatch.setattr(tui_security, "_maybe_prompt_aad_migration", lambda *a: None)
    monkeypatch.setattr(
        storage, "list_credential_metadata",
        MagicMock(side_effect=StorageError("metadata failed")),
    )

    assert tui_security._try_unlock_vault(_FakeStdscr(), None, state, master) is False
    assert state.vault_unlocked is False
    assert storage._dek is None and storage._vault_uuid is None
    assert storage._vault_version is None
    storage.close()
