"""Regression tests for the credential-details modal."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from generate_it import tui


def test_details_copy_feedback_is_rendered_on_next_frame_without_sleep(monkeypatch) -> None:
    state = tui.AppState()
    state.storage = MagicMock(name="StorageManager")
    state.storage.get_credential_secret.return_value = {"password": "secret", "note": "", "note_is_hidden": False}
    theme = SimpleNamespace(title=0, dim=0, ok=1, warn=2)
    credential = {
        "id": 1,
        "service": "GitHub",
        "username": "octocat",
        "created_at": "2026-07-10",
    }
    stdscr = MagicMock(name="stdscr")
    stdscr.getmaxyx.return_value = (40, 120)
    window = MagicMock(name="details_window")
    window.getch.side_effect = [ord("c"), -1, 27]
    newwin = MagicMock(return_value=window)
    napms = MagicMock(name="napms")
    moments = iter([0.0, 0.25, 0.75])

    monkeypatch.setattr(tui.curses, "newwin", newwin)
    monkeypatch.setattr(tui.curses, "napms", napms)
    monkeypatch.setattr(tui.time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(tui, "_maybe_auto_clear_clipboard", lambda state: False)
    monkeypatch.setattr(tui, "_should_auto_lock_now", lambda state: False)
    monkeypatch.setattr(tui, "_record_user_activity", lambda state: None)
    copy = MagicMock(return_value="Copied to clipboard.")
    monkeypatch.setattr(tui.tui_flow, "_copy_to_clipboard_with_policy", copy)

    tui._run_details_modal(stdscr, theme, state, credential)

    copy.assert_called_once_with(state, "secret")
    napms.assert_not_called()

    feedback_index = next(
        index
        for index, call in enumerate(window.method_calls)
        if call[0] == "addstr" and "COPIED PASSWORD" in call.args[2]
    )
    erase_indices = [
        index for index, call in enumerate(window.method_calls) if call[0] == "erase"
    ]
    assert feedback_index > erase_indices[1]


def test_details_modal_clears_revealed_secret_on_close(monkeypatch) -> None:
    """The finally block in _run_details_modal must clear revealed_secret/ID."""
    state = tui.AppState()
    state.storage = MagicMock(name="StorageManager")
    state.storage.get_credential_secret.return_value = {
        "password": "secret",
        "note": "",
        "note_is_hidden": False,
    }
    # Pre-populate with a stale value to prove the finally block clears it
    state.revealed_secret = {"password": "stale"}
    state.revealed_secret_id = 999

    theme = SimpleNamespace(title=0, dim=0, ok=1, warn=2)
    credential = {
        "id": 1,
        "service": "GitHub",
        "username": "octocat",
        "created_at": "2026-07-10",
    }
    stdscr = MagicMock(name="stdscr")
    stdscr.getmaxyx.return_value = (40, 120)
    window = MagicMock(name="details_window")
    window.getch.side_effect = [27]  # Esc to close immediately
    newwin = MagicMock(return_value=window)

    monkeypatch.setattr(tui.curses, "newwin", newwin)
    monkeypatch.setattr(tui, "_maybe_auto_clear_clipboard", lambda state: False)
    monkeypatch.setattr(tui, "_should_auto_lock_now", lambda state: False)
    monkeypatch.setattr(tui, "_record_user_activity", lambda state: None)

    tui._run_details_modal(stdscr, theme, state, credential)

    assert state.revealed_secret is None, (
        f"Expected revealed_secret to be None after modal close, got {state.revealed_secret}"
    )
    assert state.revealed_secret_id is None, (
        f"Expected revealed_secret_id to be None after modal close, got {state.revealed_secret_id}"
    )
