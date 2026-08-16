"""Top-level key-action handlers for the Generate It curses TUI.

This module holds the standalone action helpers that used to live at the top
level of ``tui.py`` (the double-Esc quit logic and the clipboard-copy policy).
They are verbatim extractions; behavior is unchanged. Cross-module helpers
they depend on (e.g. ``_clipboard_auto_clear_seconds``) are reached through the
``tui`` module alias to avoid circular imports.
"""

from __future__ import annotations

import time
import pyperclip
from pyperclip import PyperclipException
from typing import TYPE_CHECKING

from . import tui
from .tui_state import AppState

if TYPE_CHECKING:
    pass


def _handle_double_esc_quit(
    *,
    key: int,
    last_esc_at: float | None,
    now: float | None = None,
    window_seconds: float = tui.ESC_QUIT_WINDOW_SECONDS,
) -> tuple[bool, float | None]:
    """Return (should_quit, new_last_esc_at) for double-Esc app exit logic."""
    if key != 27:
        return False, None

    current = time.monotonic() if now is None else now
    if last_esc_at is not None and (current - last_esc_at) <= window_seconds:
        return True, None
    return False, current


def _copy_to_clipboard_with_policy(state: AppState, value: str) -> str:
    try:
        pyperclip.copy(value)
    except PyperclipException:
        # Fallback for systems (like headless Linux) without a clipboard manager
        return "Clipboard error: Install 'xclip' or 'xsel'."

    seconds = tui._clipboard_auto_clear_seconds(state)
    if seconds is None:
        state.clipboard_clear_due_at = None
        state.clipboard_clear_expected = None
        return "Copied to clipboard."

    state.clipboard_clear_due_at = time.monotonic() + seconds
    state.clipboard_clear_expected = value
    return f"Copied to clipboard. Auto-clear in {tui._clipboard_auto_clear_label(state)}."
