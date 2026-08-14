from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from generate_it import tui_security
from generate_it.storage import InvalidPasswordError


def test_lockout_thresholds_match_documented_sequence() -> None:
    assert [tui_security._get_lockout_delay_after_failure(i) for i in range(1, 6)] == [0, 30, 300, 1800, 1800]


def test_failed_unlock_records_attempt_and_success_resets(monkeypatch) -> None:
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
    monkeypatch.setattr(tui_security.tui_security if hasattr(tui_security, "tui_security") else tui_security, "_maybe_show_identity_conflict", lambda *args: None, raising=False)
    monkeypatch.setattr(tui_security, "_maybe_show_identity_conflict", lambda *args: None)
    monkeypatch.setattr(tui_security, "_maybe_prompt_aad_migration", lambda *args: None)

    assert tui_security._try_unlock_vault(None, None, state, "wrong") is False
    assert state.failed_unlock_attempts == 1
    assert state.last_failed_unlock_at is not None
    assert tui_security._try_unlock_vault(None, None, state, "right") is True
    assert state.failed_unlock_attempts == 0
    assert state.last_failed_unlock_at is None
