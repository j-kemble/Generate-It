from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from generate_it import tui, tui_helpers, tui_render
from generate_it.storage import StorageError


def test_details_modal_skips_when_terminal_cannot_fit(monkeypatch) -> None:
    stdscr = MagicMock()
    stdscr.getmaxyx.return_value = (3, 10)
    state = tui.AppState()
    theme = SimpleNamespace(title=0, dim=0, ok=1, warn=2)
    credential = {"id": 1, "service": "GitHub", "username": "user", "created_at": "now"}
    newwin = MagicMock()
    monkeypatch.setattr(tui.curses, "newwin", newwin)

    tui._run_details_modal(stdscr, theme, state, credential)

    newwin.assert_not_called()
    assert "Resize" in state.message


def test_details_modal_recovers_from_crypto_failure(monkeypatch) -> None:
    state = tui.AppState()
    state.storage = MagicMock()
    state.storage.get_credential_secret.side_effect = ValueError("bad ciphertext")
    stdscr = MagicMock()
    stdscr.getmaxyx.return_value = (40, 120)
    theme = SimpleNamespace(title=0, dim=0, ok=1, warn=2)
    credential = {"id": 1, "service": "GitHub", "username": "user", "created_at": "now"}
    monkeypatch.setattr(tui.curses, "newwin", MagicMock())
    error_modal = MagicMock()
    monkeypatch.setattr(tui.tui_modal, "_run_modal", error_modal)

    tui._run_details_modal(stdscr, theme, state, credential)

    error_modal.assert_called_once()
    assert "Cannot load credential" in error_modal.call_args.args[3]


def test_username_entropy_includes_appended_digits() -> None:
    state = tui.AppState(mode="username", username_style="adjective", username_add_numbers=True)
    without_numbers = tui_helpers._estimate_entropy_bits(
        SimpleNamespace(**{**state.__dict__, "username_add_numbers": False}), 100
    )
    with_numbers = tui_helpers._estimate_entropy_bits(state, 100)
    assert with_numbers > without_numbers


def test_username_info_shows_effective_separator_numbers_and_entropy(monkeypatch) -> None:
    state = tui.AppState(
        mode="username",
        username_style="random",
        username_separator="_",
        username_add_numbers=True,
    )
    stdscr = MagicMock()
    theme = SimpleNamespace(dim=0, ok=1, warn=2, bad=3, focus=3, border=4, title=5, gradient=[])
    for name in ("ACS_ULCORNER", "ACS_URCORNER", "ACS_LLCORNER", "ACS_LRCORNER", "ACS_HLINE", "ACS_VLINE"):
        monkeypatch.setattr(tui_render.curses, name, 0, raising=False)
    captured: list[str] = []
    monkeypatch.setattr(tui_render, "_addstr_safe", lambda _w, _y, _x, text, _attr=0: captured.append(text))

    tui_render._render_info_box(stdscr, theme, y=0, x=0, h=30, w=100, state=state, wordlist_size=100)

    joined = " ".join(captured)
    assert "Separator: none" in joined
    assert "Numbers: yes" in joined
    assert "Entropy:" in joined
