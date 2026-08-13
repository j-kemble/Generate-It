"""Presentation / render layer for the Generate It curses TUI.

This module contains only drawing/presentation code: the Theme dataclass,
low-level curses drawing helpers, and the per-panel render functions. It is
a verbatim extraction from tui.py (the orchestration / state logic stays in
tui.py and calls into this module via the `R` alias).
"""

from __future__ import annotations

import curses
import datetime as _dt
import math
import textwrap
from dataclasses import dataclass
from typing import TYPE_CHECKING

from . import generator
from .constants import AUTO_LOCK_OPTIONS, CLIPBOARD_AUTO_CLEAR_OPTIONS
from .tui_helpers import _estimate_entropy_bits, _sanitize_terminal_text, _strength_label

if TYPE_CHECKING:
    from .tui_state import AppState

# State-label helpers that live in tui.py (kept there on purpose) â
# re-exported here so the verbatim-moved render code keeps working.
def _selected_category_count(state: AppState) -> int:
    return sum((state.use_letters, state.use_numbers, state.use_special))


def _clipboard_auto_clear_label(state: AppState) -> str:
    return CLIPBOARD_AUTO_CLEAR_OPTIONS[state.clipboard_auto_clear_index][0]


def _auto_lock_label(state: AppState) -> str:
    return AUTO_LOCK_OPTIONS[state.auto_lock_index][0]

HEADER_SMALL = ["Generate It"]

# A compact 5-row pixel font (only the glyphs we need).
_FONT_H = 5

_PIXEL_FONT: dict[str, list[str]] = {
    "A": [
        " ███ ",
        "█   █",
        "█████",
        "█   █",
        "█   █",
    ],
    "E": [
        "█████",
        "█    ",
        "████ ",
        "█    ",
        "█████",
    ],
    "G": [
        " ████",
        "█    ",
        "█ ███",
        "█   █",
        " ███ ",
    ],
    "I": [
        "█████",
        "  █  ",
        "  █  ",
        "  █  ",
        "█████",
    ],
    "N": [
        "█   █",
        "██  █",
        "█ █ █",
        "█  ██",
        "█   █",
    ],
    "R": [
        "████ ",
        "█   █",
        "████ ",
        "█  █ ",
        "█   █",
    ],
    "T": [
        "█████",
        "  █  ",
        "  █  ",
        "  █  ",
        "  █  ",
    ],
    " ": [
        "   ",
        "   ",
        "   ",
        "   ",
        "   ",
    ],
    "?": [
        "████ ",
        "   █ ",
        "  █  ",
        "     ",
        "  █  ",
    ],
}

def _pixel_banner(text: str) -> list[str]:
    lines = [""] * _FONT_H
    for ch in text.upper():
        glyph = _PIXEL_FONT.get(ch, _PIXEL_FONT["?"])
        for i in range(_FONT_H):
            lines[i] += glyph[i] + " "
    return [ln.rstrip() for ln in lines]


# --- Low-level drawing helpers ---------------------------------------------


def _addstr_safe(
    stdscr: curses.window, y: int, x: int, s: str, attr: int = 0
) -> None:
    s = _sanitize_terminal_text(s)
    h, w = stdscr.getmaxyx()
    if y < 0 or y >= h or x >= w:
        return
    if x < 0:
        s = s[-x:]
        x = 0
    if not s:
        return
    try:
        stdscr.addstr(y, x, s[: max(0, w - x)], attr)
    except curses.error:
        return


def _center_x(stdscr: curses.window, s: str) -> int:
    _, w = stdscr.getmaxyx()
    return max(0, (w - len(s)) // 2)


def _draw_hline(stdscr: curses.window, y: int, x: int, w: int, ch, attr: int = 0) -> None:
    if w <= 0:
        return
    try:
        stdscr.attrset(attr)
        stdscr.hline(y, x, ch, w)
    except curses.error:
        return


def _draw_vline(stdscr: curses.window, y: int, x: int, h: int, ch, attr: int = 0) -> None:
    if h <= 0:
        return
    try:
        stdscr.attrset(attr)
        stdscr.vline(y, x, ch, h)
    except curses.error:
        return


def _draw_box(
    stdscr: curses.window,
    y: int,
    x: int,
    h: int,
    w: int,
    *,
    title: str,
    border_attr: int = 0,
    title_attr: int = 0,
) -> None:
    if h < 2 or w < 2:
        return

    try:
        stdscr.addch(y, x, curses.ACS_ULCORNER, border_attr)
        stdscr.addch(y, x + w - 1, curses.ACS_URCORNER, border_attr)
        stdscr.addch(y + h - 1, x, curses.ACS_LLCORNER, border_attr)
        stdscr.addch(y + h - 1, x + w - 1, curses.ACS_LRCORNER, border_attr)
    except curses.error:
        return

    _draw_hline(stdscr, y, x + 1, w - 2, curses.ACS_HLINE, border_attr)
    _draw_hline(stdscr, y + h - 1, x + 1, w - 2, curses.ACS_HLINE, border_attr)
    _draw_vline(stdscr, y + 1, x, h - 2, curses.ACS_VLINE, border_attr)
    _draw_vline(stdscr, y + 1, x + w - 1, h - 2, curses.ACS_VLINE, border_attr)

    # Title
    t = f" {title} "
    if w - 4 > 0:
        _addstr_safe(stdscr, y, x + 2, t[: max(0, w - 4)], title_attr)


def _bar(value: float, max_value: float, width: int) -> str:
    if width <= 0:
        return ""
    if max_value <= 0:
        frac = 0.0
    else:
        frac = max(0.0, min(1.0, value / max_value))

    fill = int(round(frac * width))
    fill = max(0, min(width, fill))

    # Using simple block/shade characters for a btop-ish vibe.
    return "█" * fill + "░" * (width - fill)


@dataclass(frozen=True)
class Theme:
    border: int
    title: int
    dim: int
    ok: int
    warn: int
    bad: int
    accent: int
    focus: int
    gradient: tuple[int, ...]


def _init_theme() -> Theme:
    # Defaults if the terminal doesn't support color.
    border = 0
    title = curses.A_BOLD
    dim = curses.A_DIM
    ok = 0
    warn = 0
    bad = 0
    accent = curses.A_BOLD
    focus = curses.A_REVERSE
    gradient: tuple[int, ...] = (0, 0, 0, 0)

    if not curses.has_colors():
        return Theme(border, title, dim, ok, warn, bad, accent, focus, gradient)

    curses.start_color()
    try:
        curses.use_default_colors()
    except curses.error:
        pass

    # Pair IDs
    PAIR_RED = 1
    PAIR_WHITE = 2
    PAIR_BLUE = 3
    PAIR_MAGENTA = 4
    PAIR_GREEN = 5
    PAIR_YELLOW = 6
    PAIR_CYAN = 7

    def _pair(pair_id: int) -> int:
        try:
            return curses.color_pair(pair_id)
        except curses.error:
            return 0

    def _init_pair(pair_id: int, fg: int, bg: int = -1) -> None:
        try:
            curses.init_pair(pair_id, fg, bg)
        except curses.error:
            # Some terminals don't like -1 bg; try black.
            try:
                curses.init_pair(pair_id, fg, curses.COLOR_BLACK)
            except curses.error:
                return

    _init_pair(PAIR_RED, curses.COLOR_RED)
    _init_pair(PAIR_WHITE, curses.COLOR_WHITE)
    _init_pair(PAIR_BLUE, curses.COLOR_BLUE)
    _init_pair(PAIR_MAGENTA, curses.COLOR_MAGENTA)
    _init_pair(PAIR_GREEN, curses.COLOR_GREEN)
    _init_pair(PAIR_YELLOW, curses.COLOR_YELLOW)
    _init_pair(PAIR_CYAN, curses.COLOR_CYAN)

    border = _pair(PAIR_CYAN)
    title = _pair(PAIR_WHITE) | curses.A_BOLD
    dim = _pair(PAIR_WHITE) | curses.A_DIM
    ok = _pair(PAIR_GREEN) | curses.A_BOLD
    warn = _pair(PAIR_YELLOW) | curses.A_BOLD
    bad = _pair(PAIR_RED) | curses.A_BOLD
    accent = _pair(PAIR_MAGENTA) | curses.A_BOLD
    focus = curses.A_REVERSE
    # Smooth gradient: red -> white -> blue (duplicated for smooth transitions)
    gradient = (
        _pair(PAIR_RED),
        _pair(PAIR_RED),
        _pair(PAIR_WHITE),
        _pair(PAIR_WHITE),
        _pair(PAIR_BLUE),
        _pair(PAIR_BLUE),
    )

    return Theme(border, title, dim, ok, warn, bad, accent, focus, gradient)

def _add_gradient(
    stdscr: curses.window,
    y: int,
    x: int,
    s: str,
    *,
    theme: Theme,
    bold: bool = True,
    span: int | None = None,
    axis: str = "x",
    row_index: int = 0,
    row_count: int = 1,
) -> None:
    if not s:
        return

    if axis == "y":
        # Color changes top-to-bottom (horizontal bands).
        band = int(
            round(
                (row_index / max(1, row_count - 1))
                * (len(theme.gradient) - 1)
            )
        )
        band = max(0, min(len(theme.gradient) - 1, band))
        attr = theme.gradient[band]
        if bold:
            attr |= curses.A_BOLD

        for i, ch in enumerate(s):
            if ch == " ":
                _addstr_safe(stdscr, y, x + i, ch)
            else:
                _addstr_safe(stdscr, y, x + i, ch, attr)
        return

    # axis == "x": color changes left-to-right.
    # When drawing multi-line ASCII art, we want each line to share the same
    # gradient alignment. `span` lets the caller provide a consistent width.
    grad_span = len(s) if span is None else max(1, span)

    for i, ch in enumerate(s):
        if ch == " ":
            _addstr_safe(stdscr, y, x + i, ch)
            continue

        band = int((i / max(1, grad_span - 1)) * (len(theme.gradient) - 1))
        band = max(0, min(len(theme.gradient) - 1, band))
        attr = theme.gradient[band]
        if bold:
            attr |= curses.A_BOLD
        _addstr_safe(stdscr, y, x + i, ch, attr)


def _header_lines_for_width(w: int) -> list[str]:
    # Large: pixel banner
    large = _pixel_banner("Generate It")
    needed = max((len(line) for line in large), default=0)

    if w >= needed + 2:
        return large

    # Small fallback
    return HEADER_SMALL


def _render_header(stdscr: curses.window, theme: Theme) -> int:
    h, w = stdscr.getmaxyx()
    lines = _header_lines_for_width(w)

    # Center the ASCII art as a block (not line-by-line), so uneven line lengths
    # don't cause the art to "zig-zag".
    block_width = max((len(line) for line in lines), default=0)
    block_x = max(0, (w - block_width) // 2)

    for i, line in enumerate(lines):
        _add_gradient(
            stdscr,
            i,
            block_x,
            line,
            theme=theme,
            span=block_width,
            axis="y",
            row_index=i,
            row_count=len(lines),
        )

    # Right side clock (btop-ish)
    t = _dt.datetime.now().strftime("%H:%M:%S")
    _addstr_safe(stdscr, 0, max(0, w - len(t) - 1), t, theme.dim)

    y = len(lines)
    _draw_hline(stdscr, y, 0, max(0, w - 1), curses.ACS_HLINE, theme.border)
    return y + 1


def _render_resize_hint(stdscr: curses.window, theme: Theme) -> None:
    h, w = stdscr.getmaxyx()
    msg = "Resize terminal for dashboard view (recommended: 80x24). Press Esc twice to quit."
    _addstr_safe(stdscr, h // 2, _center_x(stdscr, msg), msg, theme.title)


def _render_mode_box(
    stdscr: curses.window,
    theme: Theme,
    *,
    y: int,
    x: int,
    h: int,
    w: int,
    state: AppState,
    focus_id: str,
) -> None:
    _draw_box(stdscr, y, x, h, w, title="MODE", border_attr=theme.border, title_attr=theme.title)

    def _radio(selected: bool) -> str:
        return "(*)" if selected else "( )"

    opts = [
        ("mode_chars", f"{_radio(state.mode == 'chars')} Random characters"),
        ("mode_words", f"{_radio(state.mode == 'words')} Random words (passphrase)"),
        ("mode_username", f"{_radio(state.mode == 'username')} Random username"),
    ]

    row = y + 1
    for cid, label in opts:
        attr = theme.focus if cid == focus_id else 0
        _addstr_safe(stdscr, row, x + 2, label[: max(0, w - 4)], attr)
        row += 1

    hint = "Space/Enter to select • b jump here"
    _addstr_safe(stdscr, y + h - 2, x + 2, hint[: max(0, w - 4)], theme.dim)


def _render_settings_box(
    stdscr: curses.window,
    theme: Theme,
    *,
    y: int,
    x: int,
    h: int,
    w: int,
    state: AppState,
    focus_id: str,
) -> None:
    if state.mode == "vault":
        # Vault mode renders its own full-height panel, so settings box might be unused or reused.
        # We will handle this in the main loop by hiding settings/actions/output/info 
        # and showing a big vault box instead.
        return

    if state.mode == "chars":
        title = "SETTINGS • characters"
    elif state.mode == "words":
        title = "SETTINGS • words"
    else:
        title = "SETTINGS • username"
    _draw_box(stdscr, y, x, h, w, title=title, border_attr=theme.border, title_attr=theme.title)

    inner_w = max(0, w - 4)
    row = y + 1

    def _line(label: str, value: str, focused: bool) -> None:
        nonlocal row
        attr = theme.focus if focused else 0
        s = f"{label:<10} {value}"
        _addstr_safe(stdscr, row, x + 2, s[:inner_w], attr)
        row += 1

    if state.mode == "chars":
        bar_w = max(10, inner_w - 22)
        bar = _bar(
            state.char_length - generator.MIN_PASSWORD_CHARS,
            generator.MAX_PASSWORD_CHARS - generator.MIN_PASSWORD_CHARS,
            bar_w,
        )
        _line(
            "Length",
            f"[{bar}] {state.char_length}",
            focus_id == "char_length",
        )

        row += 1
        _addstr_safe(stdscr, row, x + 2, "Categories:"[:inner_w], theme.dim)
        row += 1

        items = [
            ("letters", "Letters (a-z, A-Z)", state.use_letters),
            ("numbers", "Numbers (0-9)", state.use_numbers),
            ("special", "Special characters", state.use_special),
        ]

        for cid, label, checked in items:
            mark = "[x]" if checked else "[ ]"
            attr = theme.focus if cid == focus_id else 0
            _addstr_safe(stdscr, row, x + 2, f"{mark} {label}"[:inner_w], attr)
            row += 1

        # Show selected count
        row += 1
        count = _selected_category_count(state)
        _addstr_safe(stdscr, row, x + 2, f"Selected: {count}"[:inner_w], theme.ok)

    elif state.mode == "words":
        bar_w = max(10, inner_w - 22)
        bar = _bar(
            state.word_count - generator.MIN_PASSPHRASE_WORDS,
            generator.MAX_PASSPHRASE_WORDS - generator.MIN_PASSPHRASE_WORDS,
            bar_w,
        )
        _line(
            "Words",
            f"[{bar}] {state.word_count}",
            focus_id == "word_count",
        )

        row += 1
        _addstr_safe(stdscr, row, x + 2, "Extras:"[:inner_w], theme.dim)
        row += 1

        items = [
            ("add_numbers", "Add numbers", state.add_numbers),
            ("add_special", "Add special characters", state.add_special),
        ]
        for cid, label, checked in items:
            mark = "[x]" if checked else "[ ]"
            attr = theme.focus if cid == focus_id else 0
            _addstr_safe(stdscr, row, x + 2, f"{mark} {label}"[:inner_w], attr)
            row += 1

        row += 1
        _addstr_safe(
            stdscr,
            row,
            x + 2,
            "Numbers/specials are inserted into random words."[:inner_w],
            theme.dim,
        )

    else:  # username mode
        _addstr_safe(stdscr, row, x + 2, "Style:"[:inner_w], theme.dim)
        row += 1

        styles = [
            ("username_style_adj", "Adjective + Noun", state.username_style == "adjective"),
            ("username_style_rand", "Random chars", state.username_style == "random"),
            ("username_style_words", "Multiple words", state.username_style == "words"),
        ]

        for cid, label, selected in styles:
            mark = "[*]" if selected else "[ ]"
            attr = theme.focus if focus_id == "username_style" else 0
            _addstr_safe(stdscr, row, x + 2, f"{mark} {label}"[:inner_w], attr)
            row += 1

        row += 1

        if state.username_style == "random":
            bar_w = max(10, inner_w - 22)
            bar = _bar(
                state.username_length - generator.MIN_USERNAME_LENGTH,
                generator.MAX_USERNAME_LENGTH - generator.MIN_USERNAME_LENGTH,
                bar_w,
            )
            _line(
                "Length",
                f"[{bar}] {state.username_length}",
                focus_id == "username_length",
            )

        elif state.username_style == "words":
            bar_w = max(10, inner_w - 22)
            bar = _bar(
                state.username_word_count - generator.MIN_USERNAME_WORDS,
                generator.MAX_USERNAME_WORDS - generator.MIN_USERNAME_WORDS,
                bar_w,
            )
            _line(
                "Words",
                f"[{bar}] {state.username_word_count}",
                focus_id == "username_word_count",
            )

        row += 1

        # Separator (for all styles except random-only)
        if state.username_style != "random":
            sep_opts = [
                ("username_separator_u", "Underscore", state.username_separator == "_"),
                ("username_separator_h", "Hyphen", state.username_separator == "-"),
            ]
            for cid, label, selected in sep_opts:
                mark = "[*]" if selected else "[ ]"
                attr = theme.focus if focus_id == "username_separator" else 0
                _addstr_safe(stdscr, row, x + 2, f"{mark} {label}"[:inner_w], attr)
                row += 1

            row += 1

        # Numbers option (for adjective and words)
        if state.username_style in {"adjective", "words"}:
            mark = "[x]" if state.username_add_numbers else "[ ]"
            attr = theme.focus if focus_id == "username_add_numbers" else 0
            _addstr_safe(stdscr, row, x + 2, f"{mark} Add numbers"[:inner_w], attr)
            row += 1


def _render_actions_box(
    stdscr: curses.window,
    theme: Theme,
    *,
    y: int,
    x: int,
    h: int,
    w: int,
    state: AppState,
    focus_id: str,
) -> None:
    _draw_box(stdscr, y, x, h, w, title="ACTIONS", border_attr=theme.border, title_attr=theme.title)

    inner_w = max(0, w - 4)
    row = y + 1

    btn = "[ Generate ]"
    attr = theme.focus if focus_id == "generate" else theme.accent
    _addstr_safe(stdscr, row, x + 2, btn[:inner_w], attr)
    row += 1

    if state.vault_unlocked:
        btn_add = "[ Add manually ]"
        attr_add = theme.focus if focus_id == "manual_add" else theme.ok
        _addstr_safe(stdscr, row, x + 2, btn_add[:inner_w], attr_add)
        row += 1

    if state.output and state.vault_unlocked:
        btn_save = "[ Save ]"
        attr_save = theme.focus if focus_id == "save" else theme.ok
        _addstr_safe(stdscr, row, x + 2, btn_save[:inner_w], attr_save)
        row += 1

    _addstr_safe(
        stdscr,
        row,
        x + 2,
        f"Clipboard: {_clipboard_auto_clear_label(state)}"[:inner_w],
        theme.dim,
    )
    row += 1
    _addstr_safe(
        stdscr,
        row,
        x + 2,
        f"Auto-lock: {_auto_lock_label(state)}"[:inner_w],
        theme.dim,
    )
    row += 1


def _render_vault_box(
    stdscr: curses.window,
    theme: Theme,
    *,
    y: int,
    x: int,
    h: int,
    w: int,
    state: AppState,
    focus_id: str,
) -> None:
    """Renders the full-screen vault list."""
    _draw_box(stdscr, y, x, h, w, title="VAULT", border_attr=theme.border, title_attr=theme.title)
    
    if not state.vault_unlocked:
        msg = "Vault is locked."
        _addstr_safe(stdscr, y + h//2, x + (w-len(msg))//2, msg, theme.warn)
        return

    inner_w = max(0, w - 4)
    inner_h = max(0, h - 2)
    list_x = x + 2
    list_y = y + 1
    
    # Headers
    headers = f"{'Service':<20} {'Username':<20}"
    _addstr_safe(stdscr, list_y, list_x, headers[:inner_w], theme.dim | curses.A_UNDERLINE)
    list_y += 1
    inner_h -= 1
    
    if not state.vault_credentials:
        _addstr_safe(stdscr, list_y + 1, list_x, "No credentials saved yet.", theme.dim)
        return

    # Scrolling logic
    visible_count = inner_h
    total_count = len(state.vault_credentials)
    
    # Ensure selection is visible
    if state.vault_selected_idx < state.vault_scroll_y:
        state.vault_scroll_y = state.vault_selected_idx
    elif state.vault_selected_idx >= state.vault_scroll_y + visible_count:
        state.vault_scroll_y = state.vault_selected_idx - visible_count + 1
        
    start_idx = state.vault_scroll_y
    end_idx = min(total_count, start_idx + visible_count)
    
    for i in range(start_idx, end_idx):
        cred = state.vault_credentials[i]
        is_selected = (i == state.vault_selected_idx) and (focus_id == "vault_list")
        
        attr = theme.focus if is_selected else 0
        
        # Format row
        s_serv = cred['service']
        s_user = cred['username']
        
        row_str = f"{s_serv:<20} {s_user:<20}"
        _addstr_safe(stdscr, list_y + (i - start_idx), list_x, row_str[:inner_w], attr)

    # Scrollbar hint if needed
    if total_count > visible_count:
        bar_h = max(1, int((visible_count / total_count) * inner_h))
        bar_y = int((start_idx / total_count) * inner_h)
        for i in range(bar_h):
             _addstr_safe(stdscr, y + 1 + bar_y + i, x + w - 1, "█", theme.dim)



def _render_output_box(
    stdscr: curses.window,
    theme: Theme,
    *,
    y: int,
    x: int,
    h: int,
    w: int,
    state: AppState,
) -> None:
    _draw_box(stdscr, y, x, h, w, title="OUTPUT", border_attr=theme.border, title_attr=theme.title)

    inner_w = max(0, w - 4)
    inner_h = max(0, h - 2)

    if not state.output:
        _addstr_safe(stdscr, y + 1, x + 2, "(Press Enter or g to generate)"[:inner_w], theme.dim)
        return

    lines = textwrap.wrap(
        state.output,
        width=max(10, inner_w),
        break_long_words=True,
        break_on_hyphens=False,
    )

    row = y + 1
    for line in lines[: max(0, inner_h - 1)]:
        _addstr_safe(stdscr, row, x + 2, line[:inner_w])
        row += 1


def _render_info_box(
    stdscr: curses.window,
    theme: Theme,
    *,
    y: int,
    x: int,
    h: int,
    w: int,
    state: AppState,
    wordlist_size: int,
) -> None:
    _draw_box(stdscr, y, x, h, w, title="INFO", border_attr=theme.border, title_attr=theme.title)

    inner_w = max(0, w - 4)
    row = y + 1

    bits = _estimate_entropy_bits(state, wordlist_size)
    label, kind = _strength_label(bits)

    if kind == "bad":
        kind_attr = theme.bad
    elif kind == "warn":
        kind_attr = theme.warn
    else:
        kind_attr = theme.ok

    mode_str = (
        "characters"
        if state.mode == "chars"
        else "passphrase"
        if state.mode == "words"
        else "username"
    )
    _addstr_safe(stdscr, row, x + 2, f"Mode: {mode_str}"[:inner_w], theme.dim)
    row += 1

    if state.mode == "chars":
        cats: list[str] = []
        if state.use_letters:
            cats.append("letters")
        if state.use_numbers:
            cats.append("numbers")
        if state.use_special:
            cats.append("special")
        _addstr_safe(stdscr, row, x + 2, f"Length: {state.char_length}"[:inner_w], theme.dim)
        row += 1
        _addstr_safe(stdscr, row, x + 2, f"Cats: {', '.join(cats) if cats else 'none'}"[:inner_w], theme.dim)
        row += 1
    elif state.mode == "words":
        _addstr_safe(stdscr, row, x + 2, f"Words: {state.word_count}"[:inner_w], theme.dim)
        row += 1
        _addstr_safe(stdscr, row, x + 2, f"Wordlist: {wordlist_size}"[:inner_w], theme.dim)
        row += 1
        extras: list[str] = []
        if state.add_numbers:
            extras.append("numbers")
        if state.add_special:
            extras.append("special")
        _addstr_safe(stdscr, row, x + 2, f"Extras: {', '.join(extras) if extras else 'none'}"[:inner_w], theme.dim)
        row += 1
    else:
        _addstr_safe(stdscr, row, x + 2, f"Style: {state.username_style}"[:inner_w], theme.dim)
        row += 1
        if state.username_style == "random":
            _addstr_safe(stdscr, row, x + 2, f"Length: {state.username_length}"[:inner_w], theme.dim)
        elif state.username_style == "words":
            _addstr_safe(stdscr, row, x + 2, f"Words: {state.username_word_count}"[:inner_w], theme.dim)
        else:
            _addstr_safe(stdscr, row, x + 2, "Adjective + noun"[:inner_w], theme.dim)
        row += 1
        _addstr_safe(stdscr, row, x + 2, f"Separator: {state.username_separator}"[:inner_w], theme.dim)
        row += 1

    if state.mode != "username":
        # Strength bar
        _addstr_safe(stdscr, row, x + 2, f"Entropy: ~{bits:0.1f} bits"[:inner_w], theme.dim)
        row += 1

        prefix = "Strength: ["
        suffix = f"] {label}"
        bar_w = max(0, inner_w - len(prefix) - len(suffix))
        if state.mode == "chars":
            # Theoretical max: all categories at max length
            max_bits = float(generator.MAX_PASSWORD_CHARS) * math.log2(
                len(generator.LETTERS) + len(generator.NUMBERS) + len(generator.SPECIAL_CHARACTERS)
            )
        else:
            # Theoretical max: max words + 3-digit number + 1 special
            max_bits = (
                float(generator.MAX_PASSPHRASE_WORDS) * math.log2(wordlist_size)
                + 3.0 * math.log2(10.0)
                + math.log2(len(generator.PASSPHRASE_SPECIALS))
            )
        bar = _bar(min(bits, max_bits), max_bits, bar_w)
        _addstr_safe(stdscr, row, x + 2, f"{prefix}{bar}{suffix}"[:inner_w], kind_attr)
