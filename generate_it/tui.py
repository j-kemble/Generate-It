"""Curses TUI for Generate It.

Design goal: a btop-inspired dashboard layout (boxes/panels/bars) plus a
header graphic.

Controls (default):
- q / ESC: quit
- Tab / Shift-Tab, ↑/↓: move focus
- Space: toggle
- ←/→: adjust numeric values
- Enter / g: generate
- v: vault explorer
- i: import CSV
- e: export CSV
- a: add credential manually
- ?: hotkey legend
- b: jump focus to mode
"""

from __future__ import annotations

from dataclasses import dataclass, field
import curses
import datetime as _dt
import locale
import math
import textwrap
import pyperclip

from . import generator
from .storage import StorageManager, InvalidPasswordError

APP_NAME = "Generate It"


class QuitApp(Exception):
    """Raised when the user requests to quit from anywhere in the TUI."""


def _run_modal(
    stdscr: "curses._CursesWindow",
    theme: Theme,
    title: str,
    prompt: str,
    is_password: bool = False,
    generator_func: callable | None = None,
    max_length: int = 50,
) -> str | None:
    """Runs a blocking modal dialog for text input. Returns the string or None if cancelled."""
    h, w = stdscr.getmaxyx()
    box_h, box_w = 8, 60
    y, x = (h - box_h) // 2, (w - box_w) // 2
    
    # Create a new window for the modal
    win = curses.newwin(box_h, box_w, y, x)
    win.keypad(True)
    
    input_str = ""
    
    while True:
        win.erase()
        win.box()
        
        # Title
        title_text = f" {title} "
        win.addstr(0, 2, title_text, theme.title)
        
        # Prompt
        win.addstr(2, 2, prompt, theme.accent)
        
        # Input field
        field_attr = curses.A_REVERSE | theme.dim
        display_str = "*" * len(input_str) if is_password else input_str
        # Cursor simulation
        display_str += " " 
        
        win.addstr(4, 2, display_str[:box_w-4], field_attr)
        
        # Help
        help_txt = "Enter: Confirm • Esc: Cancel"
        if generator_func:
            help_txt += " • Tab: Generate"
        win.addstr(6, 2, help_txt, theme.dim)
        
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
                input_str = generator_func()
            except Exception:
                pass
        elif 32 <= key <= 126:
            if len(input_str) < max_length:
                input_str += chr(key)

def _run_scrollable_modal(
    stdscr: "curses._CursesWindow",
    theme: Theme,
    title: str,
    lines: list[str],
) -> None:
    """Runs a blocking modal with scrollable multi-line text."""
    h, w = stdscr.getmaxyx()
    box_h = min(20, h - 4)
    box_w = min(70, w - 4)
    y, x = (h - box_h) // 2, (w - box_w) // 2
    
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

# --- Header art -------------------------------------------------------------

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
    stdscr: "curses._CursesWindow", y: int, x: int, s: str, attr: int = 0
) -> None:
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


def _center_x(stdscr: "curses._CursesWindow", s: str) -> int:
    _, w = stdscr.getmaxyx()
    return max(0, (w - len(s)) // 2)


def _draw_hline(stdscr: "curses._CursesWindow", y: int, x: int, w: int, ch, attr: int = 0) -> None:
    if w <= 0:
        return
    try:
        stdscr.hline(y, x, ch, w, attr)
    except curses.error:
        return


def _draw_vline(stdscr: "curses._CursesWindow", y: int, x: int, h: int, ch, attr: int = 0) -> None:
    if h <= 0:
        return
    try:
        stdscr.vline(y, x, ch, h, attr)
    except curses.error:
        return


def _draw_box(
    stdscr: "curses._CursesWindow",
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


# --- Theme ------------------------------------------------------------------


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
    stdscr: "curses._CursesWindow",
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


# --- App state --------------------------------------------------------------


@dataclass
class AppState:
    mode: str = "chars"  # "chars", "words", or "username"

    char_length: int = 12
    use_letters: bool = True
    use_numbers: bool = True
    use_special: bool = False

    word_count: int = 4
    add_numbers: bool = True
    add_special: bool = False

    # Username settings
    username_style: str = "adjective"  # "adjective", "random", or "words"
    username_length: int = 12
    username_separator: str = "_"  # "_" or "-"
    username_word_count: int = 2
    username_add_numbers: bool = True

    output: str = ""
    seen_passphrases: set[str] = field(default_factory=set)
    seen_usernames: set[str] = field(default_factory=set)

    message: str = "Press Enter (or g) to generate."
    focus_index: int = 0
    
    # Vault / Storage
    storage: StorageManager | None = None
    vault_unlocked: bool = False
    vault_credentials: list[dict] = field(default_factory=list)
    vault_scroll_y: int = 0
    vault_selected_idx: int = 0


def _focus_items(state: AppState) -> list[str]:
    items = ["mode_chars", "mode_words", "mode_username"]

    if state.mode == "chars":
        items += ["char_length", "letters", "numbers", "special", "generate"]
    elif state.mode == "words":
        items += ["word_count", "add_numbers", "add_special", "generate"]
    else:  # username
        items += ["username_style"]
        if state.username_style == "adjective":
            items += ["username_separator", "username_add_numbers"]
        elif state.username_style == "random":
            items += ["username_length"]
        else:  # words
            items += ["username_word_count", "username_separator", "username_add_numbers"]
        items += ["generate"]
    
    # Manual add is always available when vault is unlocked
    if state.vault_unlocked:
        items.append("manual_add")
    # Add Save button if there is output
    if state.output and state.vault_unlocked:
        items.append("save")
        
    return items


def _selected_category_count(state: AppState) -> int:
    return int(state.use_letters) + int(state.use_numbers) + int(state.use_special)


def _estimate_entropy_bits(state: AppState, wordlist_size: int) -> float:
    if state.mode == "chars":
        alphabet = 0
        if state.use_letters:
            alphabet += len(generator.LETTERS)
        if state.use_numbers:
            alphabet += len(generator.NUMBERS)
        if state.use_special:
            alphabet += len(generator.SPECIAL_CHARACTERS)
        if alphabet <= 1:
            return 0.0
        return float(state.char_length) * math.log2(alphabet)

    if wordlist_size <= 1:
        base = 0.0
    else:
        base = float(state.word_count) * math.log2(wordlist_size)

    # Extra tokens are inserted into words; we show an approximate addition.
    extra = 0.0
    if state.add_numbers:
        # Digits length chosen randomly from {2,3,4}; approximate with 3 digits.
        extra += 3.0 * math.log2(10)
    if state.add_special:
        extra += math.log2(max(2, len(generator.PASSPHRASE_SPECIALS)))

    return base + extra


def _strength_label(bits: float) -> tuple[str, str]:
    # label, kind
    if bits < 40:
        return "weak", "bad"
    if bits < 60:
        return "ok", "warn"
    if bits < 80:
        return "strong", "ok"
    return "very strong", "ok"


# --- Rendering --------------------------------------------------------------


def _header_lines_for_width(w: int) -> list[str]:
    # Large: pixel banner (gemini-cli-ish vibe)
    large = _pixel_banner("Generate It")
    needed = max((len(line) for line in large), default=0)

    if w >= needed + 2:
        return large

    # Small fallback
    return HEADER_SMALL


def _render_header(stdscr: "curses._CursesWindow", theme: Theme) -> int:
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


def _render_resize_hint(stdscr: "curses._CursesWindow", theme: Theme) -> None:
    h, w = stdscr.getmaxyx()
    msg = "Resize terminal for dashboard view (recommended: 80x24). Press q to quit."
    _addstr_safe(stdscr, h // 2, _center_x(stdscr, msg), msg, theme.title)


def _render_footer(stdscr: "curses._CursesWindow", theme: Theme, message: str) -> None:
    h, w = stdscr.getmaxyx()

    msg = message[: max(0, w - 1)]
    help_line = "Tab/↑/↓ move • Space toggle • Enter/g gen • a add • v vault • ? help • q quit"

    _addstr_safe(stdscr, h - 2, 0, " " * max(0, w - 1), theme.dim)
    _addstr_safe(stdscr, h - 2, 1, msg, theme.accent)

    _addstr_safe(stdscr, h - 1, 0, " " * max(0, w - 1), theme.dim)
    _addstr_safe(stdscr, h - 1, 1, help_line[: max(0, w - 2)], theme.dim)


def _render_mode_box(
    stdscr: "curses._CursesWindow",
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
    stdscr: "curses._CursesWindow",
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
    stdscr: "curses._CursesWindow",
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
        "Hotkeys: g generate • v vault • a add • ? help • q quit"[:inner_w],
        theme.dim,
    )


def _render_vault_box(
    stdscr: "curses._CursesWindow",
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
    headers = f"{'Service':<20} {'Username':<20} {'Password'}"
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
        # Mask password partially for display safety? Or just show it? 
        # Usually password managers hide it until requested, but here we can just show it 
        # or maybe mask it. Let's show it for now as per requirements "list and retrieve".
        s_pass = cred['password']
        
        row_str = f"{s_serv:<20} {s_user:<20} {s_pass}"
        _addstr_safe(stdscr, list_y + (i - start_idx), list_x, row_str[:inner_w], attr)

    # Scrollbar hint if needed
    if total_count > visible_count:
        bar_h = max(1, int((visible_count / total_count) * inner_h))
        bar_y = int((start_idx / total_count) * inner_h)
        for i in range(bar_h):
             _addstr_safe(stdscr, y + 1 + bar_y + i, x + w - 1, "█", theme.dim)



def _render_output_box(
    stdscr: "curses._CursesWindow",
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
    stdscr: "curses._CursesWindow",
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

    mode_str = "characters" if state.mode == "chars" else "passphrase"
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
    else:
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

    row += 1

    # Strength bar
    _addstr_safe(stdscr, row, x + 2, f"Entropy: ~{bits:0.1f} bits"[:inner_w], theme.dim)
    row += 1

    prefix = "Strength: ["
    suffix = f"] {label}"
    bar_w = max(0, inner_w - len(prefix) - len(suffix))
    bar = _bar(min(bits, 100.0), 100.0, bar_w)
    _addstr_safe(stdscr, row, x + 2, f"{prefix}{bar}{suffix}"[:inner_w], kind_attr)


# --- Input handling ----------------------------------------------------------


def _toggle_category(state: AppState, which: str) -> None:
    # Allow user to select any combination of categories, including none.
    if which == "letters":
        state.use_letters = not state.use_letters
    elif which == "numbers":
        state.use_numbers = not state.use_numbers
    elif which == "special":
        state.use_special = not state.use_special

    after = _selected_category_count(state)
    state.message = f"Selected: {after}"


def _generate(state: AppState, words: list[str]) -> None:
    try:
        if state.mode == "chars":
            state.output = generator.generate_character_password(
                state.char_length,
                use_letters=state.use_letters,
                use_numbers=state.use_numbers,
                use_special=state.use_special,
            )
            if not state.output:
                state.message = "Generated empty password (no categories selected)."
            else:
                state.message = "Generated password."
            return

        if state.mode == "words":
            # Avoid repeating the same passphrase during a single run of the program.
            for _ in range(200):
                candidate = generator.generate_passphrase(
                    state.word_count,
                    add_numbers=state.add_numbers,
                    add_special=state.add_special,
                    words=words,
                )
                if candidate not in state.seen_passphrases:
                    state.seen_passphrases.add(candidate)
                    state.output = candidate
                    state.message = "Generated passphrase."
                    return

            state.message = "Unable to generate a unique passphrase (too many already generated)."
            curses.beep()
            return

        # Username mode
        if state.username_style == "adjective":
            username = generator.generate_username_adjective_noun(
                add_numbers=state.username_add_numbers,
                separator=state.username_separator,
            )
        elif state.username_style == "random":
            username = generator.generate_username_random(
                state.username_length,
                separator_style="none",
            )
        else:  # words
            username = generator.generate_username_words(
                state.username_word_count,
                add_numbers=state.username_add_numbers,
                separator=state.username_separator,
                words=words,
            )

        state.output = username
        state.message = "Generated username."

    except Exception as exc:  # pragma: no cover
        state.message = f"Error: {exc}"
        curses.beep()


def _run_details_modal(stdscr: "curses._CursesWindow", theme: Theme, credential: dict) -> None:
    """Runs a modal to show credential details and allow copying."""
    h, w = stdscr.getmaxyx()
    box_h, box_w = 12, 60
    y, x = (h - box_h) // 2, (w - box_w) // 2
    
    win = curses.newwin(box_h, box_w, y, x)
    win.keypad(True)
    
    while True:
        win.erase()
        win.box()
        
        # Title
        win.addstr(0, 2, " CREDENTIAL DETAILS ", theme.title)
        
        # Content
        # We use safe addstr to avoid crashing if strings are too long
        row = 2
        
        label_attr = theme.dim
        val_attr = curses.A_BOLD
        
        win.addstr(row, 2, "Service:", label_attr)
        win.addstr(row, 12, credential['service'][:box_w-14], val_attr)
        row += 2
        
        win.addstr(row, 2, "Username:", label_attr)
        win.addstr(row, 12, credential['username'][:box_w-14], val_attr)
        row += 2
        
        win.addstr(row, 2, "Password:", label_attr)
        win.addstr(row, 12, credential['password'][:box_w-14], val_attr)
        row += 2
        
        win.addstr(row, 2, "Created:", label_attr)
        win.addstr(row, 12, str(credential['created_at'])[:box_w-14])
        
        # Footer
        footer = "c: Copy Pass • u: Copy User • Esc: Close"
        win.addstr(box_h - 2, 2, footer, theme.dim)
        
        win.refresh()
        
        key = win.getch()
        
        if key in (27, ord('q'), ord('Q')): # Esc/q
            return
            
        elif key in (ord('c'), ord('C')):
            try:
                pyperclip.copy(credential['password'])
                # Quick feedback overlay
                win.addstr(box_h - 2, 2, "       COPIED PASSWORD!       ", theme.ok)
                win.refresh()
                curses.napms(500)
            except Exception:
                pass

        elif key in (ord('u'), ord('U')):
            try:
                pyperclip.copy(credential['username'])
                win.addstr(box_h - 2, 2, "       COPIED USERNAME!       ", theme.ok)
                win.refresh()
                curses.napms(500)
            except Exception:
                pass


def _run_vault_modal(stdscr: "curses._CursesWindow", theme: Theme, state: AppState) -> None:
    """Runs a modal vault manager."""
    if not state.vault_unlocked or not state.storage:
        _run_modal(stdscr, theme, "ERROR", "Vault locked or unavailable.")
        return
        
    # Reload credentials
    state.vault_credentials = state.storage.list_credentials()
    
    while True:
        h, w = stdscr.getmaxyx()
        
        # Calculate box dimensions (80% of screen)
        box_h = max(10, int(h * 0.8))
        box_w = max(40, int(w * 0.8))
        y = (h - box_h) // 2
        x = (w - box_w) // 2
        
        # Draw background shadow/dimming?
        # Standard curses doesn't support transparency easily, so just draw the box.
        
        # We need to clear the area or redraw the whole screen behind it? 
        # Easier to just draw a solid box on top.
        win = curses.newwin(box_h, box_w, y, x)
        win.keypad(True)
        win.erase()
        win.box()
        
        # Title
        title = " VAULT EXPLORER "
        try:
            win.addstr(0, 2, title, theme.title)
        except curses.error:
            pass
            
        inner_h = box_h - 2
        inner_w = box_w - 4
        list_y = 1
        
        # Header
        headers = f"{'Service':<20} {'Username':<20}"
        try:
            win.addstr(list_y, 2, headers[:inner_w], theme.dim | curses.A_UNDERLINE)
        except curses.error:
            pass
            
        list_y += 2
        content_h = inner_h - 3 # Reserve space for footer
        
        if not state.vault_credentials:
            try:
                win.addstr(list_y, 2, "No credentials found.", theme.dim)
            except curses.error:
                pass
        else:
            total = len(state.vault_credentials)
            
            # Scrolling
            if state.vault_selected_idx < state.vault_scroll_y:
                state.vault_scroll_y = state.vault_selected_idx
            elif state.vault_selected_idx >= state.vault_scroll_y + content_h:
                state.vault_scroll_y = state.vault_selected_idx - content_h + 1
            
            # Clamp scroll
            state.vault_scroll_y = max(0, min(state.vault_scroll_y, total - 1))
            
            start = state.vault_scroll_y
            end = min(total, start + content_h)
            
            for i in range(start, end):
                cred = state.vault_credentials[i]
                is_selected = (i == state.vault_selected_idx)
                
                attr = theme.focus if is_selected else 0
                s_serv = cred['service']
                s_user = cred['username']
                
                line = f"{s_serv:<20} {s_user:<20}"
                try:
                    win.addstr(list_y + (i - start), 2, line[:inner_w], attr)
                except curses.error:
                    pass

        # Footer
        footer = "Enter: Details • c: Copy Pass • u: Copy User • d: Delete • Esc/v: Close"
        try:
            win.addstr(box_h - 2, 2, footer[:inner_w], theme.dim)
        except curses.error:
            pass
            
        win.refresh()
        
        key = win.getch()
        
        if key in (27, ord('v'), ord('V'), ord('q'), ord('Q')): # Esc/v/q
            return
            
        if key in (curses.KEY_UP, ord('k')):
            if state.vault_credentials:
                state.vault_selected_idx = max(0, state.vault_selected_idx - 1)
        elif key in (curses.KEY_DOWN, ord('j')):
            if state.vault_credentials:
                state.vault_selected_idx = min(len(state.vault_credentials) - 1, state.vault_selected_idx + 1)
        
        elif key in (ord('c'), ord('C')):
            if state.vault_credentials:
                cred = state.vault_credentials[state.vault_selected_idx]
                try:
                    pyperclip.copy(cred['password'])
                    _run_modal(stdscr, theme, "SUCCESS", "Password copied to clipboard.")
                except Exception as e:
                    _run_modal(stdscr, theme, "ERROR", f"Copy failed: {e}")

        elif key in (ord('u'), ord('U')):
            if state.vault_credentials:
                cred = state.vault_credentials[state.vault_selected_idx]
                try:
                    pyperclip.copy(cred['username'])
                    _run_modal(stdscr, theme, "SUCCESS", "Username copied to clipboard.")
                except Exception as e:
                    _run_modal(stdscr, theme, "ERROR", f"Copy failed: {e}")

        elif key in (curses.KEY_ENTER, 10, 13):
            if state.vault_credentials:
                cred = state.vault_credentials[state.vault_selected_idx]
                _run_details_modal(stdscr, theme, cred)
        
        elif key in (ord('d'), ord('D')):
            if state.vault_credentials:
                cred = state.vault_credentials[state.vault_selected_idx]
                confirm = _run_modal(stdscr, theme, "CONFIRM", f"Delete {cred['service']}? (type 'yes'):")
                if confirm and confirm.lower() == 'yes':
                    try:
                        state.storage.delete_credential(cred['id'])
                        state.vault_credentials = state.storage.list_credentials()
                        if state.vault_selected_idx >= len(state.vault_credentials):
                            state.vault_selected_idx = max(0, len(state.vault_credentials) - 1)
                    except Exception as e:
                        _run_modal(stdscr, theme, "ERROR", f"Delete failed: {e}")


# --- Main loop --------------------------------------------------------------


def run() -> int:
    """Run the curses TUI."""

    try:
        locale.setlocale(locale.LC_ALL, "")
    except Exception:
        pass

    def _main(stdscr: "curses._CursesWindow") -> int:
        theme = _init_theme()

        try:
            curses.curs_set(0)
        except curses.error:
            pass

        stdscr.keypad(True)

        words = generator.load_wordlist()
        state = AppState()
        
        # --- Storage Initialization ---
        try:
            state.storage = StorageManager()
        except Exception as e:
            # If we can't create the storage manager (e.g. permission error on folder),
            # we should display it and exit or fallback.
            # Since we are in curses, we can show a modal.
            while True:
                stdscr.erase()
                _render_header(stdscr, theme)
                msg = f"Storage Error: {e}"
                _draw_box(stdscr, 10, 5, 5, 70, title="CRITICAL ERROR", border_attr=theme.bad, title_attr=theme.bad)
                _addstr_safe(stdscr, 12, 7, msg, theme.dim)
                _addstr_safe(stdscr, 13, 7, "Press q to quit", theme.dim)
                stdscr.refresh()
                if stdscr.getch() in (ord('q'), ord('Q')):
                    return 1

        if not state.storage.vault_exists():
            # First time setup
            while True:
                stdscr.erase()
                _render_header(stdscr, theme)
                pwd = _run_modal(stdscr, theme, "SETUP", "Create Master Password:", is_password=True)
                if pwd is None: # Cancelled
                    return 0
                if len(pwd) < 4:
                    _run_modal(stdscr, theme, "ERROR", "Password too short (min 4 chars). Press Enter.")
                    continue
                
                # Confirm password
                pwd2 = _run_modal(stdscr, theme, "SETUP", "Confirm Master Password:", is_password=True)
                if pwd2 is None: # Cancelled
                    continue

                if pwd == pwd2:
                    try:
                        state.storage.initialize_vault(pwd)
                        state.vault_unlocked = True
                        break
                    except Exception as e:
                        _run_modal(stdscr, theme, "ERROR", f"Init failed: {e}. Press Enter.")
                else:
                    _run_modal(stdscr, theme, "ERROR", "Passwords do not match. Press Enter.")
        else:
            # Unlock existing vault
            while True:
                stdscr.erase()
                _render_header(stdscr, theme)
                pwd = _run_modal(stdscr, theme, "LOGIN", "Enter Master Password:", is_password=True)
                if pwd is None: # Cancelled
                    return 0
                
                try:
                    state.storage.unlock_vault(pwd)
                    state.vault_unlocked = True
                    break
                except InvalidPasswordError:
                    # Visual feedback loop
                    continue

        # Load initial credentials
        if state.vault_unlocked and state.storage:
             state.vault_credentials = state.storage.list_credentials()

        # Generate something immediately so the dashboard isn't empty.
        _generate(state, words)

        while True:
            stdscr.erase()
            header_end = _render_header(stdscr, theme)
            h, w = stdscr.getmaxyx()

            min_w, min_h = 70, 20
            if w < min_w or h < min_h:
                _render_resize_hint(stdscr, theme)
                _render_footer(stdscr, theme, state.message)
                stdscr.refresh()
                key = stdscr.getch()
                if key in (ord("q"), ord("Q"), 27):
                    return 0
                continue

            footer_h = 2
            body_y = header_end
            body_h = max(1, h - body_y - footer_h)

            gap = 1
            # Two columns
            left_w = max(34, min((w - gap) // 2, w - gap - 30))
            right_x = left_w + gap
            right_w = max(1, w - right_x)

            # Standard layout heights
            mode_h = 6
            actions_h = 7 # Increased for Save button
            settings_h = max(6, body_h - mode_h - actions_h - 2 * gap)

            # Right column: OUTPUT + INFO
            info_h = 8
            output_h = max(6, body_h - info_h - gap)
            info_h = max(6, body_h - output_h - gap)

            focus_items = _focus_items(state)
            state.focus_index = max(0, min(state.focus_index, len(focus_items) - 1))
            focus_id = focus_items[state.focus_index]

            # --- Rendering ---
            
            # Mode box is always visible
            _render_mode_box(
                stdscr,
                theme,
                y=body_y,
                x=0,
                h=mode_h,
                w=left_w,
                state=state,
                focus_id=focus_id,
            )

            # Standard Generator Layout
            _render_settings_box(
                stdscr,
                theme,
                y=body_y + mode_h + gap,
                x=0,
                h=settings_h,
                w=left_w,
                state=state,
                focus_id=focus_id,
            )
            _render_actions_box(
                stdscr,
                theme,
                y=body_y + mode_h + gap + settings_h + gap,
                x=0,
                h=actions_h,
                w=left_w,
                state=state,
                focus_id=focus_id,
            )

            _render_output_box(
                stdscr,
                theme,
                y=body_y,
                x=right_x,
                h=output_h,
                w=right_w,
                state=state,
            )
            _render_info_box(
                stdscr,
                theme,
                y=body_y + output_h + gap,
                x=right_x,
                h=info_h,
                w=right_w,
                state=state,
                wordlist_size=len(words),
            )

            _render_footer(stdscr, theme, state.message)
            stdscr.refresh()

            key = stdscr.getch()

            if key in (ord("q"), ord("Q"), 27):
                return 0
            if key == curses.KEY_RESIZE:
                continue

            # Navigation
            if key in (9,):  # Tab
                state.focus_index = (state.focus_index + 1) % len(focus_items)
                continue
            if key == curses.KEY_BTAB:  # Shift-Tab
                state.focus_index = (state.focus_index - 1) % len(focus_items)
                continue
            
            # Up/Down navigation (Standard)
            if key in (curses.KEY_UP, ord("k")):
                state.focus_index = (state.focus_index - 1) % len(focus_items)
                continue
            if key in (curses.KEY_DOWN, ord("j")):
                state.focus_index = (state.focus_index + 1) % len(focus_items)
                continue

            if key in (ord("b"), ord("B")):
                state.focus_index = 0
                continue

            # Adjust numeric values
            if key in (curses.KEY_LEFT, ord("h")):
                if focus_id == "char_length":
                    state.char_length = max(generator.MIN_PASSWORD_CHARS, state.char_length - 1)
                elif focus_id == "word_count":
                    state.word_count = max(generator.MIN_PASSPHRASE_WORDS, state.word_count - 1)
                elif focus_id == "username_length":
                    state.username_length = max(generator.MIN_USERNAME_LENGTH, state.username_length - 1)
                elif focus_id == "username_word_count":
                    state.username_word_count = max(generator.MIN_USERNAME_WORDS, state.username_word_count - 1)
                continue
            if key in (curses.KEY_RIGHT, ord("l")):
                if focus_id == "char_length":
                    state.char_length = min(generator.MAX_PASSWORD_CHARS, state.char_length + 1)
                elif focus_id == "word_count":
                    state.word_count = min(generator.MAX_PASSPHRASE_WORDS, state.word_count + 1)
                elif focus_id == "username_length":
                    state.username_length = min(generator.MAX_USERNAME_LENGTH, state.username_length + 1)
                elif focus_id == "username_word_count":
                    state.username_word_count = min(generator.MAX_USERNAME_WORDS, state.username_word_count + 1)
                continue

            activate = key in (curses.KEY_ENTER, 10, 13)
            toggle = key == ord(" ")
            generate_now = key in (ord("g"), ord("G"))
            open_vault = key in (ord("v"), ord("V"))
            import_csv = key in (ord("i"), ord("I"))
            export_csv = key in (ord("e"), ord("E"))
            manual_add = key in (ord("a"), ord("A"))
            show_help = key == ord("?")

            if show_help:
                help_lines = [
                    "GLOBAL HOTKEYS",
                    "g       : Generate new credential",
                    "v       : Open Vault Explorer",
                    "i       : Import credentials from CSV",
                    "e       : Export credentials to CSV",
                    "?       : Show this help",
                    "q / Esc : Quit application",
                    "",
                    "NAVIGATION & EDITING",
                    "Tab     : Move focus forward",
                    "S-Tab   : Move focus backward",
                    "↑ / ↓   : Move focus up/down",
                    "b       : Jump focus to Mode selection",
                    "Space   : Toggle checkboxes / radio buttons",
                    "← / →   : Adjust numeric values",
                    "Enter   : Confirm / Generate",
                    "",
                    "VAULT EXPLORER (inside 'v')",
                    "↑ / ↓   : Navigate list",
                    "Enter   : View details",
                    "c       : Copy Password",
                    "u       : Copy Username",
                    "d       : Delete entry",
                    "Esc     : Close vault",
                ]
                _run_scrollable_modal(stdscr, theme, "HOTKEY LEGEND", help_lines)
                stdscr.clear()
                continue

            # Manual add (hotkey)
            if manual_add:
                if not state.vault_unlocked or not state.storage:
                    _run_modal(stdscr, theme, "ERROR", "Vault is locked or unavailable.")
                    stdscr.clear()
                    continue
                try:
                    service = _run_modal(stdscr, theme, "ADD", "Service name:", max_length=120)
                    if not service:
                        state.message = "Add cancelled."
                        stdscr.clear()
                        continue

                    def _gen_user():
                        return generator.generate_username_adjective_noun(add_numbers=True)

                    username = _run_modal(
                        stdscr,
                        theme,
                        "ADD",
                        "Username:",
                        generator_func=_gen_user,
                        max_length=120,
                    )
                    if not username:
                        state.message = "Add cancelled."
                        stdscr.clear()
                        continue

                    def _gen_pwd():
                        return generator.generate_character_password(
                            16, use_letters=True, use_numbers=True, use_special=True
                        )

                    password = _run_modal(
                        stdscr,
                        theme,
                        "ADD",
                        "Password:",
                        is_password=True,
                        generator_func=_gen_pwd,
                        max_length=200,
                    )
                    if not password:
                        state.message = "Add cancelled."
                        stdscr.clear()
                        continue

                    state.storage.save_credential(service, username, password)
                    state.vault_credentials = state.storage.list_credentials()
                    state.message = f"Added credential for {service}."
                except Exception as e:
                    _run_modal(stdscr, theme, "ERROR", f"Add failed: {e}")
                    state.message = "Add failed."
                stdscr.clear()
                continue

            if open_vault:
                _run_vault_modal(stdscr, theme, state)
                # Force full redraw after modal closes
                stdscr.clear() 
                continue

            if generate_now:
                _generate(state, words)
                continue

            # CSV Export
            if export_csv:
                if not state.vault_unlocked or not state.storage:
                    _run_modal(stdscr, theme, "ERROR", "Vault is locked or unavailable.")
                    stdscr.clear()
                    continue
                
                file_path = _run_modal(stdscr, theme, "EXPORT CSV", "Enter file path:", max_length=200)
                if file_path:
                    from pathlib import Path
                    csv_path = Path(file_path).expanduser()
                    
                    # Check if file exists and confirm overwrite
                    if csv_path.exists():
                        confirm = _run_modal(stdscr, theme, "CONFIRM", f"File exists. Overwrite? (type 'yes'):")
                        if not confirm or confirm.lower() != 'yes':
                            state.message = "Export cancelled."
                            stdscr.clear()
                            continue
                    
                    try:
                        exported, skipped = state.storage.export_to_csv(csv_path)
                        
                        if skipped:
                            skip_lines = [f"The following {len(skipped)} credential(s) failed to export:", ""]
                            for item in skipped:
                                skip_lines.append(f"- {item['service']} / {item['username']}: {item['error']}")
                            _run_scrollable_modal(stdscr, theme, "EXPORT WARNING", skip_lines)
                        
                        state.message = f"Exported {exported} credential(s) to {csv_path}."
                        if skipped:
                            state.message += f" ({len(skipped)} skipped)"
                    except Exception as e:
                        _run_modal(stdscr, theme, "ERROR", f"Export failed: {e}")
                        state.message = "Export failed."
                
                stdscr.clear()
                continue

            # CSV Import
            if import_csv:
                if not state.vault_unlocked or not state.storage:
                    _run_modal(stdscr, theme, "ERROR", "Vault is locked or unavailable.")
                    stdscr.clear()
                    continue
                
                file_path = _run_modal(stdscr, theme, "IMPORT CSV", "Enter file path:", max_length=200)
                if file_path:
                    from pathlib import Path
                    csv_path = Path(file_path).expanduser()
                    
                    if not csv_path.exists():
                        _run_modal(stdscr, theme, "ERROR", f"File not found: {csv_path}")
                        stdscr.clear()
                        continue
                    
                    try:
                        # Preview pass: detect duplicates without importing
                        _, _, preview_issues = state.storage.import_from_csv(
                            csv_path, merge_duplicates=False, dry_run=True
                        )
                        
                        merge = False
                        dup_count = len([d for d in preview_issues if 'Duplicate' in d['reason']])
                        if dup_count > 0:
                            # Show duplicate summary and ask user
                            dup_lines = [f"Found {dup_count} duplicate(s):", ""]
                            for item in preview_issues:
                                if 'Duplicate' in item['reason']:
                                    dup_lines.append(f"- {item['service']} / {item['username']}")
                            dup_lines.append("")
                            dup_lines.append("Do you want to merge (overwrite) duplicates?")
                            _run_scrollable_modal(stdscr, theme, "DUPLICATES FOUND", dup_lines)
                            
                            merge_confirm = _run_modal(stdscr, theme, "MERGE?", "Type 'yes' to merge/overwrite:")
                            if merge_confirm and merge_confirm.lower() == 'yes':
                                merge = True
                        
                        # Import with merge decision
                        imported, skipped, duplicates = state.storage.import_from_csv(
                            csv_path, merge_duplicates=merge, dry_run=False
                        )
                        
                        # Show results
                        if duplicates:
                            result_lines = [f"Import complete:", ""]
                            result_lines.append(f"Imported: {imported}")
                            result_lines.append(f"Skipped: {skipped}")
                            if duplicates:
                                result_lines.append("")
                                result_lines.append("Issues:")
                                for item in duplicates:
                                    result_lines.append(f"- {item['service']} / {item['username']}: {item['reason']}")
                            _run_scrollable_modal(stdscr, theme, "IMPORT RESULTS", result_lines)
                        else:
                            _run_modal(stdscr, theme, "SUCCESS", f"Imported {imported} credential(s).")
                        
                        state.message = f"Imported {imported} credential(s). ({skipped} skipped)"
                        
                        # Refresh vault list
                        state.vault_credentials = state.storage.list_credentials()
                        
                    except Exception as e:
                        _run_modal(stdscr, theme, "ERROR", f"Import failed: {e}")
                        state.message = "Import failed."
                
                stdscr.clear()
                continue

            if activate or toggle:
                if focus_id == "mode_chars":
                    state.mode = "chars"
                    state.message = "Mode: characters"
                    focus_items = _focus_items(state)
                    state.focus_index = max(0, min(state.focus_index, len(focus_items) - 1))
                elif focus_id == "mode_words":
                    state.mode = "words"
                    state.message = "Mode: words"
                    focus_items = _focus_items(state)
                    state.focus_index = max(0, min(state.focus_index, len(focus_items) - 1))
                elif focus_id == "mode_username":
                    state.mode = "username"
                    state.message = "Mode: username"
                    focus_items = _focus_items(state)
                    state.focus_index = max(0, min(state.focus_index, len(focus_items) - 1))
                elif focus_id in {"letters", "numbers", "special"}:
                    _toggle_category(state, focus_id)
                elif focus_id == "add_numbers":
                    state.add_numbers = not state.add_numbers
                elif focus_id == "add_special":
                    state.add_special = not state.add_special
                elif focus_id == "username_style":
                    styles = ["adjective", "random", "words"]
                    idx = styles.index(state.username_style)
                    state.username_style = styles[(idx + 1) % len(styles)]
                    state.message = f"Username style: {state.username_style}"
                    focus_items = _focus_items(state)
                    state.focus_index = max(0, min(state.focus_index, len(focus_items) - 1))
                elif focus_id == "username_separator":
                    state.username_separator = "-" if state.username_separator == "_" else "_"
                    state.message = f"Separator: {state.username_separator}"
                elif focus_id == "username_add_numbers":
                    state.username_add_numbers = not state.username_add_numbers
                elif focus_id == "generate" and activate:
                    _generate(state, words)
                elif focus_id == "manual_add" and activate:
                    manual_add = True
                    # reuse hotkey path
                    key = ord("a")
                    continue
                elif focus_id == "save" and activate:
                    # SAVE FLOW
                    service = _run_modal(stdscr, theme, "SAVE", "Enter Service/Website Name:")
                    if service and state.storage and state.output:
                        try:
                            final_username = ""
                            final_password = ""

                            if state.mode == "username":
                                # We generated a username, so we need a password.
                                final_username = state.output
                                
                                def _gen_pwd():
                                    return generator.generate_character_password(16, use_letters=True, use_numbers=True, use_special=True)
                                
                                final_password = _run_modal(
                                    stdscr, 
                                    theme, 
                                    "SAVE", 
                                    f"Enter Password for {final_username}:",
                                    is_password=False, # Show it so they can see what they generated? Or hide it? Usually show during creation.
                                    generator_func=_gen_pwd
                                )
                            else:
                                # We generated a password, so we need a username.
                                final_password = state.output
                                
                                def _gen_user():
                                    return generator.generate_username_adjective_noun(add_numbers=True)
                                    
                                final_username = _run_modal(
                                    stdscr, 
                                    theme, 
                                    "SAVE", 
                                    "Enter Username:",
                                    generator_func=_gen_user
                                )

                            if final_username and final_password:
                                state.storage.save_credential(service, final_username, final_password)
                                state.message = f"Saved credential for {service}."
                            else:
                                state.message = "Save cancelled."

                        except Exception as e:
                            state.message = f"Error saving: {e}"
                else:
                    # Enter on sliders generates as a convenience.
                    if activate and focus_id in {"char_length", "word_count", "username_length", "username_word_count"}:
                        _generate(state, words)

        return 0

    try:
        return curses.wrapper(_main)
    except QuitApp:
        return 0
