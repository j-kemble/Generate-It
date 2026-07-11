"""Security regression tests for the TUI layer."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from generate_it import tui
from generate_it import tui_modal
from generate_it import tui_render


def test_username_save_flow_masks_password_prompt(monkeypatch) -> None:
    """The username-mode save flow MUST call _run_modal with is_password=True."""
    state = tui.AppState()
    state.mode = "username"
    state.output = "testuser123"
    state.vault_unlocked = True
    state.storage = MagicMock(name="StorageManager")

    theme = SimpleNamespace(title=0, dim=0, ok=1, warn=2, border=0)
    stdscr = MagicMock(name="stdscr")

    call_args: list[dict] = []

    def _fake_run_modal(
        stdscr_,
        theme_,
        title,
        prompt,
        *,
        is_password=False,
        generator_func=None,
        **__: object,
    ):
        call_args.append({"prompt": prompt, "is_password": is_password})
        # Return a value for the service prompt, then a password for the password prompt
        if "Service" in prompt:
            return "example.com"
        if "Password" in prompt:
            return "testpassword"
        return ""

    monkeypatch.setattr(tui_modal, "_run_modal", _fake_run_modal)

    tui._run_save_generated_flow(stdscr, theme, state)

    # Find the password-prompt call
    password_calls = [
        c for c in call_args if "Password" in c["prompt"]
    ]
    assert len(password_calls) == 1, (
        f"Expected 1 password-prompt call, got {len(password_calls)}: {call_args}"
    )
    assert password_calls[0]["is_password"] is True, (
        "Password prompt MUST be masked (is_password=True)"
    )


def test_vault_list_render_never_contains_password(monkeypatch) -> None:
    """Vault list rendering must NOT include raw passwords."""
    import curses
    
    state = tui.AppState()
    state.vault_unlocked = True
    state.vault_credentials = [
        {"service": "GitHub", "username": "dev", "password": "SUPER_SECRET_PASSWORD", "created_at": "2026-01-01"},
    ]
    state.vault_selected_idx = 0
    state.vault_scroll_y = 0
    
    theme = SimpleNamespace(title=0, dim=0, ok=1, warn=2, border=0, focus=0, bad=0)
    stdscr = MagicMock(name="stdscr")
    stdscr.getmaxyx.return_value = (24, 80)
    
    # Mock curses module used by tui_render (for ACS_ULCORNER etc.)
    fake_curses = MagicMock(name="curses")
    fake_curses.ACS_ULCORNER = 0
    fake_curses.ACS_URCORNER = 0
    fake_curses.ACS_LLCORNER = 0
    fake_curses.ACS_LRCORNER = 0
    fake_curses.ACS_HLINE = 0
    fake_curses.ACS_VLINE = 0
    fake_curses.A_UNDERLINE = 0
    monkeypatch.setattr(tui_render, "curses", fake_curses)
    
    # Collect all addstr calls
    addstr_calls: list[str] = []
    def _capture_addstr(win, y, x, s, *args):
        addstr_calls.append(str(s))
    monkeypatch.setattr(tui_render, "_addstr_safe", _capture_addstr)
    
    tui_render._render_vault_box(stdscr, theme, y=0, x=0, h=20, w=70, state=state, focus_id="vault_list")
    
    all_text = " ".join(addstr_calls)
    assert "SUPER_SECRET_PASSWORD" not in all_text, (
        f"Password found in vault list render output: {all_text}"
    )


def test_details_modal_masks_password_by_default(monkeypatch) -> None:
    """The details modal must mask the password unless explicitly revealed."""
    import curses
    
    state = tui.AppState()
    state.vault_unlocked = True
    state.storage = MagicMock(name="StorageManager")
    
    credential = {
        "id": 1,
        "service": "GitHub",
        "username": "dev",
        "password": "my-secret-password",
        "note": "",
        "note_is_hidden": False,
        "created_at": "2026-01-01",
    }
    
    theme = SimpleNamespace(title=0, dim=0, ok=1, warn=2, border=0, focus=0, bad=0)
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
    
    # Collect all addstr calls to the window
    addstr_texts: list[str] = []
    for call in window.method_calls:
        if call[0] == "addstr" and len(call.args) >= 3:
            addstr_texts.append(str(call.args[2]))
    
    all_text = " ".join(addstr_texts)
    assert "my-secret-password" not in all_text, (
        f"Raw password appeared in details modal without reveal: {all_text}"
    )
