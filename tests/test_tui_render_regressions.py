from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from generate_it import tui
from generate_it import tui_render


def test_draw_lines_forward_attributes() -> None:
    window = MagicMock()

    tui_render._draw_hline(window, 1, 2, 3, "-", 7)
    tui_render._draw_vline(window, 4, 5, 6, "|", 8)

    window.attrset.assert_any_call(7)
    window.attrset.assert_any_call(8)
    window.hline.assert_called_once_with(1, 2, "-", 3)
    window.vline.assert_called_once_with(4, 5, "|", 6)


def test_details_modal_clamps_window_to_terminal_and_bounds_note(monkeypatch) -> None:
    state = tui.AppState()
    state.storage = MagicMock()
    state.storage.get_credential_secret.return_value = {
        "password": "password",
        "note": "long note " * 500,
        "note_is_hidden": False,
    }
    credential = {"id": 1, "service": "Service", "username": "user", "created_at": "today"}
    stdscr = MagicMock()
    stdscr.getmaxyx.return_value = (8, 20)
    window = MagicMock()
    window.getch.side_effect = [27]
    monkeypatch.setattr(tui.curses, "newwin", MagicMock(return_value=window))
    monkeypatch.setattr(tui, "_maybe_auto_clear_clipboard", lambda state: False)
    monkeypatch.setattr(tui, "_should_auto_lock_now", lambda state: False)
    monkeypatch.setattr(tui, "_record_user_activity", lambda state: None)

    tui._run_details_modal(stdscr, SimpleNamespace(title=0, dim=0), state, credential)

    tui.curses.newwin.assert_not_called()
    assert "Resize" in state.message


def test_details_modal_returns_recoverably_on_decryption_failure(monkeypatch) -> None:
    state = tui.AppState()
    state.storage = MagicMock()
    state.storage.get_credential_secret.side_effect = tui.StorageError("corrupt secret")
    stdscr = MagicMock()
    stdscr.getmaxyx.return_value = (24, 80)
    modal = MagicMock()
    monkeypatch.setattr(tui.curses, "newwin", MagicMock())
    monkeypatch.setattr(tui.tui_modal, "_run_modal", modal)

    tui._run_details_modal(
        stdscr,
        SimpleNamespace(title=0, dim=0),
        state,
        {"id": 1, "service": "Service", "username": "user", "created_at": "today"},
    )

    modal.assert_called_once()
    assert "corrupt secret" in modal.call_args.args[3]
