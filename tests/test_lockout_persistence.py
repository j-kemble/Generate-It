from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from generate_it import tui_security
from generate_it.storage import InvalidPasswordError, StorageManager


def test_lockout_state_roundtrips_across_reopen(tmp_path) -> None:
    db_path = tmp_path / "vault.db"
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault("A-Strong-Passw0rd!")
    storage.close()

    storage = StorageManager(db_path=db_path)
    assert storage.get_failed_unlock_state() == (0, None)
    storage.record_failed_unlock(3, 1234.5)
    storage.close()

    reopened = StorageManager(db_path=db_path)
    assert reopened.get_failed_unlock_state() == (3, 1234.5)
    reopened.clear_failed_unlock_state()
    assert reopened.get_failed_unlock_state() == (0, None)
    reopened.close()


def test_failed_unlock_persists_attempt_and_success_clears(monkeypatch) -> None:
    storage = MagicMock()
    storage.unlock_vault.side_effect = [InvalidPasswordError(), None]
    storage.list_credential_metadata.return_value = []
    storage.vault_exists.return_value = True
    storage.get_failed_unlock_state.return_value = (0, None)
    state = SimpleNamespace(
        storage=storage,
        vault_unlocked=False,
        vault_credentials=[],
        message="",
        failed_unlock_attempts=0,
        last_failed_unlock_at=None,
    )
    monkeypatch.setattr(tui_security.tui_modal, "_run_modal", lambda *args, **kwargs: None)
    monkeypatch.setattr(tui_security.tui, "_record_user_activity", lambda state: None)
    monkeypatch.setattr(tui_security, "_maybe_show_identity_conflict", lambda *args: None)
    monkeypatch.setattr(tui_security, "_maybe_prompt_aad_migration", lambda *args: None)

    assert tui_security._try_unlock_vault(None, None, state, "wrong") is False
    assert state.failed_unlock_attempts == 1
    storage.record_failed_unlock.assert_called_once()
    assert storage.record_failed_unlock.call_args[0][0] == 1

    assert tui_security._try_unlock_vault(None, None, state, "right") is True
    assert state.failed_unlock_attempts == 0
    assert state.last_failed_unlock_at is None
    storage.clear_failed_unlock_state.assert_called_once()


def test_load_lockout_state_applies_persisted_delay(monkeypatch) -> None:
    storage = MagicMock()
    storage.vault_exists.return_value = True
    state = SimpleNamespace(
        storage=storage,
        failed_unlock_attempts=0,
        last_failed_unlock_at=None,
    )
    storage.get_failed_unlock_state.return_value = (3, 1000.0)
    monkeypatch.setattr(tui_security, "_now", lambda: 1005.0)
    monkeypatch.setattr(tui_security, "_get_lockout_delay_after_failure", lambda attempts: 1800)

    tui_security._load_lockout_state(state)

    assert state.failed_unlock_attempts == 3
    assert state.last_failed_unlock_at == 1000.0
    assert tui_security._get_lockout_delay(state) == pytest.approx(1795.0)


def test_load_lockout_state_ignores_when_no_vault(monkeypatch) -> None:
    storage = MagicMock()
    storage.vault_exists.return_value = False
    state = SimpleNamespace(storage=storage, failed_unlock_attempts=7, last_failed_unlock_at=99.0)
    tui_security._load_lockout_state(state)
    assert state.failed_unlock_attempts == 7
    assert state.last_failed_unlock_at == 99.0


def test_record_failed_unlock_uses_epoch_time(monkeypatch) -> None:
    state = SimpleNamespace(
        storage=MagicMock(),
        failed_unlock_attempts=0,
        last_failed_unlock_at=None,
    )
    monkeypatch.setattr(tui_security, "_now", lambda: 5000.0)
    tui_security._record_unlock_failure(state)
    assert state.failed_unlock_attempts == 1
    assert state.last_failed_unlock_at == 5000.0
    state.storage.record_failed_unlock.assert_called_once_with(1, 5000.0)