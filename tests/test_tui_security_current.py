from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from generate_it import tui, tui_security
from generate_it.storage import StorageError


def _state(storage):
    return SimpleNamespace(
        storage=storage,
        vault_unlocked=False,
        vault_credentials=[],
        message="",
        failed_unlock_attempts=0,
        last_failed_unlock_at=None,
        last_activity_at=0.0,
        last_tick_at=0.0,
    )


def test_post_auth_initialization_failure_rolls_back_unlock_state(monkeypatch) -> None:
    storage = MagicMock()
    storage.unlock_vault.return_value = None
    storage.list_credential_metadata.side_effect = StorageError("metadata failed")
    storage.vault_exists.return_value = True
    storage.get_failed_unlock_state.return_value = (0, None)
    state = _state(storage)
    monkeypatch.setattr(tui_security.tui_modal, "_run_modal", lambda *args, **kwargs: None)

    assert tui_security._try_unlock_vault(None, None, state, "password") is False
    assert state.vault_unlocked is False
    assert state.vault_credentials == []
    storage.close.assert_called_once()
    assert state.failed_unlock_attempts == 0


def test_search_command_keys_are_search_text(monkeypatch) -> None:
    storage = MagicMock()
    storage.list_credential_metadata.return_value = []
    state = _state(storage)
    state.vault_unlocked = True
    stdscr = MagicMock()
    stdscr.getmaxyx.return_value = (40, 120)
    window = MagicMock()
    window.getch.side_effect = [ord("/"), ord("v"), ord("q"), 27, 27]
    monkeypatch.setattr(tui.curses, "newwin", MagicMock(return_value=window))
    monkeypatch.setattr(tui, "_maybe_auto_clear_clipboard", lambda state: False)
    monkeypatch.setattr(tui, "_should_auto_lock_now", lambda state: False)
    monkeypatch.setattr(tui, "_record_user_activity", lambda state: None)

    tui._run_vault_modal(stdscr, SimpleNamespace(dim=0, title=0, border=0), state, start_in_search=False)

    assert window.getch.call_count == 5


def test_auto_clear_changed_clipboard_reports_skipped(monkeypatch) -> None:
    state = _state(MagicMock())
    state.clipboard_clear_due_at = 1.0
    state.clipboard_clear_expected = "application secret"
    monkeypatch.setattr(tui.pyperclip, "paste", lambda: "new user content")

    assert tui._maybe_auto_clear_clipboard(state, now=2.0) is False
    assert state.clipboard_clear_due_at is None
    assert state.clipboard_clear_expected is None
    assert state.message == "Clipboard changed; auto-clear skipped."


def test_aad_migration_confirmation_is_affirmative_only(monkeypatch) -> None:
    storage = MagicMock(_vault_version=2, _aad_version=2)
    state = SimpleNamespace(storage=storage, message="")

    for response in (None, "", "n", "y", "yes"):
        storage.reset_mock()
        monkeypatch.setattr(
            tui_security.tui_modal,
            "_run_modal",
            lambda *args, response=response, **kwargs: response,
        )
        tui_security._maybe_prompt_aad_migration(None, None, state)
        if response in {"y", "yes"}:
            storage.migrate_aad_to_v3.assert_called_once()
        else:
            storage.migrate_aad_to_v3.assert_not_called()
        storage.reset_mock()
        state.message = ""


class _SearchWindow:
    def __init__(self) -> None:
        self.keys = iter([ord("/"), ord("v"), ord("q"), 27, 27])

    def getch(self):
        return next(self.keys)

    def getmaxyx(self):
        return (20, 80)

    def __getattr__(self, _name):
        return lambda *args, **kwargs: None
