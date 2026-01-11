"""Curses TUI for Generate It.

Design goal: a btop-inspired dashboard layout (boxes/panels/bars) plus a
header graphic.

Controls (default):
- q / ESC: quit
- Tab / Shift-Tab, ↑/↓: move focus
- Space: toggle
- ←/→: adjust numeric values
- Enter / g: generate
- b: jump focus to mode
"""

from __future__ import annotations

from dataclasses import dataclass, field
import curses
import datetime as _dt
import locale
import math
import textwrap

from . import generator

APP_NAME = "Generate It"


class QuitApp(Exception):
    """Raised when the user requests to quit from anywhere in the TUI."""


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
    PAIR_CYAN = 1
    PAIR_BLUE = 2
    PAIR_MAGENTA = 3
    PAIR_RED = 4
    PAIR_GREEN = 5
    PAIR_YELLOW = 6
    PAIR_WHITE = 7

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

    _init_pair(PAIR_CYAN, curses.COLOR_CYAN)
    _init_pair(PAIR_BLUE, curses.COLOR_BLUE)
    _init_pair(PAIR_MAGENTA, curses.COLOR_MAGENTA)
    _init_pair(PAIR_RED, curses.COLOR_RED)
    _init_pair(PAIR_GREEN, curses.COLOR_GREEN)
    _init_pair(PAIR_YELLOW, curses.COLOR_YELLOW)
    _init_pair(PAIR_WHITE, curses.COLOR_WHITE)

    border = _pair(PAIR_CYAN)
    title = _pair(PAIR_WHITE) | curses.A_BOLD
    dim = _pair(PAIR_WHITE) | curses.A_DIM
    ok = _pair(PAIR_GREEN) | curses.A_BOLD
    warn = _pair(PAIR_YELLOW) | curses.A_BOLD
    bad = _pair(PAIR_RED) | curses.A_BOLD
    accent = _pair(PAIR_MAGENTA) | curses.A_BOLD
    focus = curses.A_REVERSE
    gradient = (_pair(PAIR_CYAN), _pair(PAIR_BLUE), _pair(PAIR_MAGENTA), _pair(PAIR_RED))

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


def _focus_items(state: AppState) -> list[str]:
    items = ["mode_chars", "mode_words", "mode_username"]
    if state.mode == "chars":
        items += ["char_length", "letters", "numbers", "special", "generate"]
    elif state.mode == "words":
        items += ["word_count", "add_numbers", "add_special", "generate"]
    else:  # username
        items += ["username_style", "generate"]
        if state.username_style == "adjective":
            items.insert(-1, "username_add_numbers")
            items.insert(-1, "username_separator")
        elif state.username_style == "random":
            items.insert(-1, "username_length")
            items.insert(-1, "username_separator")
        else:  # words
            items.insert(-1, "username_word_count")
            items.insert(-1, "username_add_numbers")
            items.insert(-1, "username_separator")
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
    help_line = "Tab/↑/↓ move • Space toggle • ←/→ adjust • Enter/g generate • q quit"

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
    row += 2

    _addstr_safe(stdscr, row, x + 2, "Hotkeys: g generate • q quit"[:inner_w], theme.dim)


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

            # Left column: MODE + SETTINGS + ACTIONS
            mode_h = 6
            actions_h = 5
            settings_h = max(6, body_h - mode_h - actions_h - 2 * gap)

            # Right column: OUTPUT + INFO
            info_h = 8
            output_h = max(6, body_h - info_h - gap)
            info_h = max(6, body_h - output_h - gap)

            focus_items = _focus_items(state)
            state.focus_index = max(0, min(state.focus_index, len(focus_items) - 1))
            focus_id = focus_items[state.focus_index]

            # Draw panels
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

            if generate_now:
                _generate(state, words)
                continue

            if activate or toggle:
                if focus_id == "mode_chars":
                    state.mode = "chars"
                    state.message = "Mode: characters"
                elif focus_id == "mode_words":
                    state.mode = "words"
                    state.message = "Mode: words"
                elif focus_id == "mode_username":
                    state.mode = "username"
                    state.message = "Mode: username"
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
                elif focus_id == "username_separator":
                    state.username_separator = "-" if state.username_separator == "_" else "_"
                    state.message = f"Separator: {state.username_separator}"
                elif focus_id == "username_add_numbers":
                    state.username_add_numbers = not state.username_add_numbers
                elif focus_id == "generate" and activate:
                    _generate(state, words)
                else:
                    # Enter on sliders generates as a convenience.
                    if activate and focus_id in {"char_length", "word_count", "username_length", "username_word_count"}:
                        _generate(state, words)

                # Keep focus list consistent after mode changes.
                focus_items = _focus_items(state)
                state.focus_index = max(0, min(state.focus_index, len(focus_items) - 1))

        return 0

    try:
        return curses.wrapper(_main)
    except QuitApp:
        return 0
