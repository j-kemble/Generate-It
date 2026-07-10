"""Regression tests for the credential-details modal."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from generate_it import tui


def test_details_copy_feedback_is_rendered_on_next_frame_without_sleep(monkeypatch) -> None:
    state = tui.AppState()
    theme = SimpleNamespace(title=0, dim=0, ok=1, warn=2)
    credential = {
        "id": 1,
        "service": "GitHub",
        "username": "octocat",
        "password": "secret",
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
