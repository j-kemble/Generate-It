"""Modal input dialogs for the Generate It curses TUI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, TYPE_CHECKING
import curses
import textwrap

if TYPE_CHECKING:
    from . import tui


@dataclass
class _WindowCache:
    """Retain one curses window until a modal's geometry changes."""

    geometry: tuple[int, int, int, int] | None = None
    window: curses.window | None = None

    def get(self, height: int, width: int, y: int, x: int) -> curses.window:
        geometry = (height, width, y, x)
        if self.window is None or self.geometry != geometry:
            self.window = curses.newwin(height, width, y, x)
            self.window.keypad(True)
            self.geometry = geometry
        return self.window


def _run_modal(
    stdscr: curses.window,
    theme: "tui.Theme",
    title: str,
    prompt: str,
    is_password: bool = False,
    generator_func: Callable | None = None,
    max_length: int = 50,
    initial_value: str = "",
) -> str | None:
    """Runs a blocking modal dialog for text input. Returns the string or None if cancelled."""
    input_str = initial_value[:max_length]
    window_cache = _WindowCache()
    while True:
        h, w = stdscr.getmaxyx()
        min_w = 46
        max_w = max(min_w, w - 4)
        preferred_w = max(60, len(prompt) + 8)
        box_w = min(max_w, preferred_w)
        inner_w = max(10, box_w - 4)

        prompt_lines = textwrap.wrap(
            prompt,
            width=inner_w,
            break_long_words=True,
            break_on_hyphens=False,
        ) or [""]

        help_txt = "Enter: Confirm • Esc: Cancel"
        if generator_func:
            help_txt += " • Tab: Generate"

        input_row = 2 + len(prompt_lines) + 1
        help_row = input_row + 2
        box_h = max(8, help_row + 2)
        box_h = min(max(8, h - 2), box_h)

        max_prompt_lines = max(1, box_h - 6)
        if len(prompt_lines) > max_prompt_lines:
            prompt_lines = prompt_lines[: max_prompt_lines - 1] + ["..."]
            input_row = 2 + len(prompt_lines) + 1
            help_row = input_row + 2

        # Clamp geometry to fit within the terminal.
        box_h = min(box_h, h)
        box_w = min(box_w, w)
        y = max(0, (h - box_h) // 2)
        x = max(0, (w - box_w) // 2)

        # If the terminal is too small for a useful modal, show a resize message.
        if box_h < 5 or box_w < 20:
            stdscr.erase()
            try:
                stdscr.addstr(0, 0, "Terminal too small. Resize to at least 20x5.")
            except curses.error:
                pass
            stdscr.refresh()
            curses.napms(1000)
            return None

        win = window_cache.get(box_h, box_w, y, x)
        win.erase()
        win.box()
        # Title
        title_text = f" {title} "
        try:
            win.addstr(0, 2, title_text[: max(0, box_w - 4)], theme.title)
        except curses.error:
            pass

        # Prompt (wrapped)
        for i, line in enumerate(prompt_lines):
            try:
                win.addstr(2 + i, 2, line[:inner_w], theme.accent)
            except curses.error:
                pass
        # Input field
        field_attr = curses.A_REVERSE | theme.dim
        display_str = "*" * len(input_str) if is_password else input_str
        # Cursor simulation
        display_str += " "
        if len(display_str) > inner_w:
            display_str = display_str[-inner_w:]
        try:
            win.addstr(input_row, 2, display_str[:inner_w], field_attr)
        except curses.error:
            pass

        # Help
        try:
            win.addstr(help_row, 2, help_txt[:inner_w], theme.dim)
        except curses.error:
            pass
        win.refresh()
        key = win.getch()
        if key == 27: # ESC
            return None
        elif key in (curses.KEY_ENTER, 10, 13):
            return input_str
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            input_str = input_str[:-1]
        elif key == 9 and generator_func: # Tab
            try:
                # Generate and replace current input
                if generator_func is not None:
                    input_str = str(generator_func())[:max_length]
                else:
                    input_str = ""
            except Exception:
                pass
        elif 32 <= key <= 126:
            if len(input_str) < max_length:
                input_str += chr(key)


def _run_scrollable_modal(
    stdscr: curses.window,
    theme: "tui.Theme",
    title: str,
    lines: list[str],
) -> None:
    """Runs a blocking modal with scrollable multi-line text."""
    h, w = stdscr.getmaxyx()
    box_h = min(20, h - 4)
    box_w = min(70, w - 4)

    # Clamp geometry to fit within the terminal.
    box_h = min(box_h, h)
    box_w = min(box_w, w)
    y = max(0, (h - box_h) // 2)
    x = max(0, (w - box_w) // 2)

    # If the terminal is too small for a useful modal, show a resize message.
    if box_h < 5 or box_w < 20:
        stdscr.erase()
        try:
            stdscr.addstr(0, 0, "Terminal too small. Resize to at least 20x5.")
        except curses.error:
            pass
        stdscr.refresh()
        curses.napms(1000)
        return

    win = curses.newwin(box_h, box_w, y, x)
    win.keypad(True)

    scroll_pos = 0
    content_h = box_h - 4  # Reserve space for title, border, and footer

    while True:
        win.erase()
        win.box()
        # Title
        title_text = f" {title} "
        win.addstr(0, 2, title_text[:box_w-4], theme.title)

        # Content with scrolling
        visible_lines = lines[scroll_pos:scroll_pos + content_h]
        for i, line in enumerate(visible_lines):
            try:
                win.addstr(2 + i, 2, line[:box_w-4])
            except curses.error:
                pass

        # Footer with scroll indicator
        if len(lines) > content_h:
            footer = f"↑/↓: Scroll • Esc: Close ({scroll_pos+1}-{min(scroll_pos+content_h, len(lines))} of {len(lines)})"
        else:
            footer = "Esc: Close"
        try:
            win.addstr(box_h - 2, 2, footer[:box_w-4], theme.dim)
        except curses.error:
            pass

        win.refresh()

        key = win.getch()

        if key in (27, ord('q'), ord('Q')):  # ESC/q
            return
        elif key in (curses.KEY_UP, ord('k')):
            scroll_pos = max(0, scroll_pos - 1)
        elif key in (curses.KEY_DOWN, ord('j')):
            scroll_pos = min(max(0, len(lines) - content_h), scroll_pos + 1)
