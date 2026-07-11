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


def test_lock_vault_clears_unchanged_clipboard(monkeypatch):
    """Locking must clear the clipboard when the secret hasn't changed."""
    state = tui.AppState()
    state.storage = MagicMock(name="StorageManager")
    state.vault_unlocked = True
    state.clipboard_clear_expected = "secret-value"
    state.clipboard_clear_due_at = float('inf')

    clipboard_state = {"value": "secret-value"}

    def fake_paste():
        return clipboard_state["value"]

    def fake_copy(val):
        clipboard_state["value"] = val

    monkeypatch.setattr(tui.pyperclip, "paste", fake_paste)
    monkeypatch.setattr(tui.pyperclip, "copy", fake_copy)

    tui._lock_vault(state)

    assert clipboard_state["value"] == ""  # cleared
    assert state.clipboard_clear_expected is None
    assert state.clipboard_clear_due_at is None


def test_lock_vault_does_not_clear_newer_clipboard(monkeypatch):
    """Locking must NOT clear newer clipboard content placed by the user."""
    state = tui.AppState()
    state.storage = MagicMock(name="StorageManager")
    state.vault_unlocked = True
    state.clipboard_clear_expected = "secret-value"
    state.clipboard_clear_due_at = float('inf')

    clipboard_state = {"value": "user-copied-something-else"}

    def fake_paste():
        return clipboard_state["value"]

    def fake_copy(val):
        clipboard_state["value"] = val

    monkeypatch.setattr(tui.pyperclip, "paste", fake_paste)
    monkeypatch.setattr(tui.pyperclip, "copy", fake_copy)

    tui._lock_vault(state)

    assert clipboard_state["value"] == "user-copied-something-else"  # preserved
    assert state.clipboard_clear_expected is None  # tracking reset


def test_revoke_clipboard_handles_pyperclip_error(monkeypatch):
    """Clipboard backend failure must not prevent vault lock."""
    from pyperclip import PyperclipException

    state = tui.AppState()
    state.storage = MagicMock(name="StorageManager")
    state.vault_unlocked = True
    state.clipboard_clear_expected = "secret"
    state.clipboard_clear_due_at = float('inf')

    monkeypatch.setattr(tui.pyperclip, "paste", MagicMock(side_effect=PyperclipException))
    monkeypatch.setattr(tui.pyperclip, "copy", MagicMock())

    # Must not raise
    tui._lock_vault(state)

    assert not state.vault_unlocked
    assert state.clipboard_clear_expected is None


def test_fresh_state_defaults_to_secure_clipboard_clear():
    """Fresh AppState must default to 30-second clipboard auto-clear."""
    state = tui.AppState()
    assert state.clipboard_auto_clear_index == 2  # 30 seconds
    seconds = tui._clipboard_auto_clear_seconds(state)
    assert seconds == 30


def test_fresh_state_defaults_to_secure_auto_lock():
    """Fresh AppState must default to 5-minute auto-lock."""
    state = tui.AppState()
    assert state.auto_lock_index == 2  # 5 minutes
    setting = tui._auto_lock_setting(state)
    assert setting == 300  # 5 * 60


# --- Terminal text sanitization ---------------------------------------------

def test_sanitize_replaces_control_characters():
    """C0/C1 controls must be replaced with visible escaped forms."""
    # Newline, tab, carriage return, ESC, backspace
    dirty = "hello\nworld\ttab\rCR\x1bESC\x08BS"
    clean = tui_render._sanitize_terminal_text(dirty)
    assert "\n" not in clean
    assert "\t" not in clean
    assert "\r" not in clean
    assert "\x1b" not in clean
    assert "\x08" not in clean
    # Should contain visible representations
    assert "\\n" in clean
    assert "\\t" in clean
    assert "\\e" in clean


def test_sanitize_replaces_c1_controls():
    """C1 controls (0x80-0x9F) must be replaced with \\xNN form."""
    dirty = "test\x80\x9fend"
    clean = tui_render._sanitize_terminal_text(dirty)
    assert "\x80" not in clean
    assert "\x9f" not in clean
    assert "\\x80" in clean
    assert "\\x9f" in clean


def test_sanitize_preserves_printable_unicode():
    """Ordinary text including non-ASCII must remain readable."""
    text = "café résumé 日本語"
    clean = tui_render._sanitize_terminal_text(text)
    assert clean == text


def test_sanitize_applied_in_addstr_safe():
    """_addstr_safe must sanitize before passing to curses."""
    fake_stdscr = MagicMock(name="stdscr")
    fake_stdscr.getmaxyx.return_value = (40, 120)
    # Call _addstr_safe with control characters
    tui_render._addstr_safe(fake_stdscr, 0, 0, "hello\nworld")
    # Verify addstr was called with sanitized text
    call_text = fake_stdscr.addstr.call_args[0][2]
    assert "\n" not in call_text
    assert "\\n" in call_text


def test_sanitize_handles_empty_and_ascii():
    """Empty string and clean ASCII should pass through unchanged."""
    assert tui_render._sanitize_terminal_text("") == ""
    assert tui_render._sanitize_terminal_text("hello world") == "hello world"
