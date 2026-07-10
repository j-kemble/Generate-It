"""Regression-sensitive tests for TUI P0 performance paths.

These tests drive real modal loops with fake curses windows. They assert the
mechanisms behind the performance fixes: unchanged modal geometry reuses one
window, and unchanged fuzzy/vault queries do not repeat expensive ranking.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from generate_it import tui
from generate_it import tui_files
from generate_it import tui_modal


def _theme() -> SimpleNamespace:
    return SimpleNamespace(title=0, accent=0, dim=0, focus=0, ok=0, warn=0)


def _stdscr() -> MagicMock:
    screen = MagicMock(name="stdscr")
    screen.getmaxyx.return_value = (40, 120)
    return screen


def _window_with_keys(*keys: int) -> MagicMock:
    window = MagicMock(name="window")
    window.getmaxyx.return_value = (40, 120)
    window.getch.side_effect = keys
    return window


def test_text_modal_reuses_window_while_typing(monkeypatch) -> None:
    window = _window_with_keys(ord("a"), 10)
    newwin = MagicMock(return_value=window)
    monkeypatch.setattr(tui_modal.curses, "newwin", newwin)

    result = tui_modal._run_modal(_stdscr(), _theme(), "TITLE", "Prompt")

    assert result == "a"
    assert newwin.call_count == 1
    window.keypad.assert_called_once_with(True)


def test_fuzzy_picker_reuses_window_and_scores_once_per_distinct_query(tmp_path: Path, monkeypatch) -> None:
    files = [tmp_path / "alpha.txt", tmp_path / "beta.txt"]
    window = _window_with_keys(tui.curses.KEY_DOWN, ord("a"), 27)
    newwin = MagicMock(return_value=window)
    score_calls: list[tuple[str, str]] = []

    def score(query: str, candidate: str) -> int:
        score_calls.append((query, candidate))
        return 0

    monkeypatch.setattr(tui.curses, "newwin", newwin)
    monkeypatch.setattr(tui_files, "_collect_files_for_fuzzy", lambda root: files)
    monkeypatch.setattr(tui, "_fuzzy_score", score)

    result = tui._run_fuzzy_file_picker(_stdscr(), _theme(), tmp_path)

    assert result is None
    assert len(score_calls) == 2 * len(files)
    assert [query for query, _ in score_calls] == ["", "", "a", "a"]
    assert newwin.call_count == 1


def test_file_browser_reuses_window_while_navigating(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "entry.txt").write_text("entry", encoding="utf-8")
    window = _window_with_keys(tui.curses.KEY_DOWN, 27)
    newwin = MagicMock(return_value=window)
    monkeypatch.setattr(tui.curses, "newwin", newwin)

    result = tui._run_file_browser_modal(_stdscr(), _theme(), tmp_path)

    assert result is None
    assert newwin.call_count == 1


def test_path_modal_reuses_window_while_editing(monkeypatch) -> None:
    window = _window_with_keys(ord("a"), 27)
    newwin = MagicMock(return_value=window)
    monkeypatch.setattr(tui.curses, "newwin", newwin)

    result = tui._run_path_modal(_stdscr(), _theme(), "PATH", "Choose a path")

    assert result is None
    assert newwin.call_count == 1


def test_security_settings_reuses_window_while_navigating(monkeypatch) -> None:
    state = tui.AppState()
    window = _window_with_keys(tui.curses.KEY_DOWN, 27)
    newwin = MagicMock(return_value=window)
    monkeypatch.setattr(tui.curses, "newwin", newwin)
    monkeypatch.setattr(tui, "_maybe_auto_clear_clipboard", lambda state: False)
    monkeypatch.setattr(tui, "_should_auto_lock_now", lambda state: False)
    monkeypatch.setattr(tui, "_record_user_activity", lambda state: None)

    tui._run_security_settings_modal(_stdscr(), _theme(), state)

    assert newwin.call_count == 1


def test_vault_modal_reuses_window_and_refilters_after_credentials_refresh(monkeypatch) -> None:
    credentials = [
        {"id": 1, "service": "GitHub", "username": "octocat", "password": "secret"},
        {"id": 2, "service": "Gmail", "username": "alice", "password": "secret"},
    ]
    state = tui.AppState()
    state.vault_unlocked = True
    state.storage = SimpleNamespace(list_credentials=lambda: credentials)
    refreshed_credentials = list(credentials)
    window = _window_with_keys(-1, tui.curses.KEY_DOWN, 27)
    newwin = MagicMock(return_value=window)
    filter_calls: list[tuple[list[dict], str]] = []

    def filter_credentials(items: list[dict], query: str) -> list[dict]:
        filter_calls.append((items, query))
        return items

    monkeypatch.setattr(tui.curses, "newwin", newwin)
    monkeypatch.setattr(tui, "_filter_vault_credentials", filter_credentials)
    monkeypatch.setattr(tui, "_maybe_auto_clear_clipboard", lambda state: False)
    monkeypatch.setattr(tui, "_should_auto_lock_now", lambda state: False)
    monkeypatch.setattr(
        tui,
        "_record_user_activity",
        lambda state: setattr(state, "vault_credentials", refreshed_credentials),
    )

    tui._run_vault_modal(_stdscr(), _theme(), state)

    assert len(filter_calls) == 2
    assert filter_calls[0][0] is credentials
    assert filter_calls[1][0] is refreshed_credentials
    assert newwin.call_count == 1
