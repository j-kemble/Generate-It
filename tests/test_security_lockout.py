from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from generate_it import tui_security
from generate_it.storage import InvalidPasswordError


def _state(storage: MagicMock) -> SimpleNamespace:
    return SimpleNamespace(
        storage=storage,
        vault_unlocked=False,
        vault_credentials=[],
        message="",
        failed_unlock_attempts=0,
        lockout_until=None,
    )


def _patch_success_side_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tui_security.tui_modal, "_run_modal", lambda *args, **kwargs: None)
    monkeypatch.setattr(tui_security.tui, "_record_user_activity", lambda state: None)
    monkeypatch.setattr(tui_security, "_maybe_show_identity_conflict", lambda *args: None)
    monkeypatch.setattr(tui_security, "_maybe_prompt_aad_migration", lambda *args: None)


def test_first_wrong_unlock_is_retryable_immediately(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = MagicMock()
    storage.unlock_vault.side_effect = InvalidPasswordError()
    state = _state(storage)
    _patch_success_side_effects(monkeypatch)
    monkeypatch.setattr(tui_security, "_now", lambda: 100.0)

    assert tui_security._try_unlock_vault(None, None, state, "wrong") is False
    assert state.failed_unlock_attempts == 1
    assert state.lockout_until is None
    assert tui_security._get_lockout_remaining(state, now=100.0) == 0
    assert getattr(state, tui_security._UNLOCK_RETRY_FLAG) is True


def test_lockout_delay_escalates_after_each_failed_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = MagicMock()
    storage.unlock_vault.side_effect = InvalidPasswordError()
    state = _state(storage)
    _patch_success_side_effects(monkeypatch)
    current = [100.0]
    monkeypatch.setattr(tui_security, "_now", lambda: current[0])

    for attempts, expected_delay in enumerate((0, 30, 300, 1800), start=1):
        state.lockout_until = None
        assert tui_security._try_unlock_vault(None, None, state, "wrong") is False
        assert state.failed_unlock_attempts == attempts
        remaining = tui_security._get_lockout_remaining(state, now=current[0])
        assert remaining == pytest.approx(expected_delay)
        current[0] += expected_delay + 1


def test_successful_unlock_resets_lockout_state(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = MagicMock()
    storage.unlock_vault.side_effect = [InvalidPasswordError(), None]
    storage.list_credential_metadata.return_value = []
    state = _state(storage)
    _patch_success_side_effects(monkeypatch)
    monkeypatch.setattr(tui_security, "_now", lambda: 100.0)

    assert tui_security._try_unlock_vault(None, None, state, "wrong") is False
    assert tui_security._try_unlock_vault(None, None, state, "right") is True
    assert state.failed_unlock_attempts == 0
    assert state.lockout_until is None


def test_escape_cancels_lockout_countdown(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _state(MagicMock())
    state.failed_unlock_attempts = 2
    state.lockout_until = 130.0
    monkeypatch.setattr(tui_security, "_now", lambda: 100.0)
    stdscr = MagicMock()
    stdscr.getch.return_value = 27

    assert tui_security._wait_for_lockout(stdscr, None, state) is False


def test_lockout_countdown_expires_without_unlock_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _state(MagicMock())
    state.failed_unlock_attempts = 2
    state.lockout_until = 100.0
    monkeypatch.setattr(tui_security, "_now", lambda: 100.0)

    assert tui_security._get_lockout_remaining(state) == 0
    assert state.lockout_until is None
