"""Curses TUI for Generate It.

Design goal: a btop-inspired dashboard layout (boxes/panels/bars) plus a
header graphic.

Controls (default):
- Esc twice: quit
- Tab / Shift-Tab, ↑/↓: move focus
- Space: toggle
- ←/→: adjust numeric values
- Enter / g: generate
- s: save generated credential
- v: vault explorer
- i: import CSV
- e: export CSV
- a: add credential manually
- t: security settings
- ?: hotkey legend
- b: jump focus to mode
"""

from __future__ import annotations

from dataclasses import dataclass, field
import curses
import datetime as _dt
import os
import locale
import math
import time
from pathlib import Path
import textwrap
import pyperclip

from . import generator
from . import csv_formats
from .storage import StorageManager, InvalidPasswordError

APP_NAME = "Generate It"
ESC_QUIT_WINDOW_SECONDS = 1.0
AUTO_LOCK_SCREEN_OFF = "screen_off"
SCREEN_OFF_LOCK_GAP_SECONDS = 20.0

CLIPBOARD_AUTO_CLEAR_OPTIONS: tuple[tuple[str, int | None], ...] = (
    ("No auto-clear", None),
    ("15 seconds", 15),
    ("30 seconds", 30),
    ("45 seconds", 45),
    ("1 minute", 60),
    ("2 minutes", 120),
    ("3 minutes", 180),
)

AUTO_LOCK_OPTIONS: tuple[tuple[str, int | str | None], ...] = (
    ("No auto-lock", None),
    ("Lock when screen off", AUTO_LOCK_SCREEN_OFF),
    ("5 minutes", 5 * 60),
    ("10 minutes", 10 * 60),
    ("15 minutes", 15 * 60),
)

SETTING_KEY_CLIPBOARD_AUTO_CLEAR_INDEX = "clipboard_auto_clear_index"
SETTING_KEY_AUTO_LOCK_INDEX = "auto_lock_index"


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
    initial_value: str = "",
) -> str | None:
    """Runs a blocking modal dialog for text input. Returns the string or None if cancelled."""
    input_str = initial_value[:max_length]
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

        y, x = (h - box_h) // 2, (w - box_w) // 2
        win = curses.newwin(box_h, box_w, y, x)
        win.keypad(True)
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
                input_str = str(generator_func())[:max_length]
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

def _truncate_middle(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    if max_len <= 3:
        return text[:max_len]
    keep_left = (max_len - 3) // 2
    keep_right = max_len - 3 - keep_left
    return f"{text[:keep_left]}...{text[-keep_right:]}"


def _filter_vault_credentials(credentials: list[dict], query: str) -> list[dict]:
    """Filter and rank vault credentials by fuzzy score on service/username."""
    q = query.strip().lower()
    if not q:
        return list(credentials)
    ranked: list[tuple[int, str, str, dict]] = []
    for cred in credentials:
        service = str(cred.get("service", "")).lower()
        username = str(cred.get("username", "")).lower()
        combined = f"{service} {username}".strip()

        scores = [
            s
            for s in (
                _fuzzy_score(q, service),
                _fuzzy_score(q, username),
                _fuzzy_score(q, combined),
            )
            if s is not None
        ]
        if not scores:
            continue

        ranked.append((min(scores), service, username, cred))

    ranked.sort(key=lambda item: (item[0], item[1], item[2]))
    return [item[3] for item in ranked]


def _find_duplicate_credential(
    credentials: list[dict],
    service: str,
    username: str,
    *,
    exclude_id: int | None = None,
) -> dict | None:
    service_key = service.strip().lower()
    username_key = username.strip().lower()
    if not service_key or not username_key:
        return None

    for cred in credentials:
        cred_id = cred.get("id")
        if exclude_id is not None and cred_id == exclude_id:
            continue
        cred_service = str(cred.get("service", "")).strip().lower()
        cred_username = str(cred.get("username", "")).strip().lower()
        if cred_service == service_key and cred_username == username_key:
            return cred

    return None


def _save_credential_duplicate_safe(
    stdscr: "curses._CursesWindow",
    theme: Theme,
    state: AppState,
    *,
    service: str,
    username: str,
    password: str,
    note: str = "",
    note_is_hidden: bool = False,
) -> str:
    """Save credential; prompt to overwrite if a duplicate exists."""
    if not state.storage:
        raise RuntimeError("Vault is unavailable.")

    existing = _find_duplicate_credential(
        state.storage.list_credentials(),
        service,
        username,
    )
    if existing is not None:
        confirm = _run_modal(
            stdscr,
            theme,
            "DUPLICATE FOUND",
            f"{service} / {username} already exists. Type 'overwrite' to replace or Esc to cancel:",
            max_length=20,
        )
        if not confirm or confirm.strip().lower() != "overwrite":
            return "cancelled"

        state.storage.update_credential(existing["id"], service, username, password, note, note_is_hidden)
        state.vault_credentials = state.storage.list_credentials()
        return "overwritten"

    state.storage.save_credential(service, username, password, note, note_is_hidden)
    state.vault_credentials = state.storage.list_credentials()
    return "saved"


def _resolve_start_dir(path_text: str) -> Path:
    if not path_text.strip():
        return Path.cwd()
    candidate = Path(path_text).expanduser()
    if candidate.exists():
        return candidate if candidate.is_dir() else candidate.parent

    parent = candidate.parent
    while parent != parent.parent and not parent.exists():
        parent = parent.parent
    if parent.exists() and parent.is_dir():
        return parent
    return Path.cwd()


def _collect_files_for_fuzzy(root_dir: Path, max_files: int = 5000, max_depth: int = 8) -> list[Path]:
    files: list[Path] = []
    root = root_dir.expanduser()
    if not root.exists() or not root.is_dir():
        return files

    root_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        dir_path = Path(dirpath)
        depth = len(dir_path.parts) - root_depth
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        if depth >= max_depth:
            dirnames[:] = []

        for filename in filenames:
            if filename.startswith("."):
                continue
            files.append(dir_path / filename)
            if len(files) >= max_files:
                return files
    return files


def _fuzzy_score(query: str, text: str) -> int | None:
    q = query.strip().lower()
    if not q:
        return 0
    t = text.lower()

    if q in t:
        return t.index(q) * 2 + (len(t) - len(q))

    q_idx = 0
    gap_penalty = 0
    last_match = -1
    for i, ch in enumerate(t):
        if q_idx >= len(q):
            break
        if ch == q[q_idx]:
            if last_match != -1:
                gap_penalty += i - last_match - 1
            last_match = i
            q_idx += 1
    if q_idx != len(q):
        return None

    return 1000 + gap_penalty + len(t)


def _handle_double_esc_quit(
    *,
    key: int,
    last_esc_at: float | None,
    now: float | None = None,
    window_seconds: float = ESC_QUIT_WINDOW_SECONDS,
) -> tuple[bool, float | None]:
    """Return (should_quit, new_last_esc_at) for double-Esc app exit logic."""
    if key != 27:
        return False, None

    current = time.monotonic() if now is None else now
    if last_esc_at is not None and (current - last_esc_at) <= window_seconds:
        return True, None
    return False, current


def _run_fuzzy_file_picker(
    stdscr: "curses._CursesWindow",
    theme: Theme,
    root_dir: Path,
) -> str | None:
    files = _collect_files_for_fuzzy(root_dir)
    if not files:
        _run_modal(stdscr, theme, "NO FILES", f"No files found under {root_dir}.")
        return None

    query = ""
    selected_idx = 0
    scroll_pos = 0

    while True:
        h, w = stdscr.getmaxyx()
        box_h = min(max(14, int(h * 0.8)), max(12, h - 2))
        box_w = min(max(70, int(w * 0.9)), max(44, w - 2))
        y, x = (h - box_h) // 2, (w - box_w) // 2

        win = curses.newwin(box_h, box_w, y, x)
        win.keypad(True)
        win.erase()
        win.box()

        inner_w = max(10, box_w - 4)
        root_display = _truncate_middle(str(root_dir), max(8, inner_w - 7))
        try:
            win.addstr(0, 2, " FUZZY FILE PICKER ", theme.title)
            win.addstr(1, 2, f"Root: {root_display}"[:inner_w], theme.dim)
        except curses.error:
            pass

        query_display = f"Query: {query}"
        query_display += " "
        if len(query_display) > inner_w:
            query_display = query_display[-inner_w:]
        try:
            win.addstr(2, 2, query_display[:inner_w], curses.A_REVERSE | theme.dim)
        except curses.error:
            pass

        scored: list[tuple[int, str, Path]] = []
        for p in files:
            rel = str(p.relative_to(root_dir))
            score = _fuzzy_score(query, rel)
            if score is None:
                continue
            scored.append((score, rel, p))
        scored.sort(key=lambda item: (item[0], len(item[1]), item[1]))
        matches = scored[:500]

        content_y = 4
        content_h = max(1, box_h - 7)
        selected_idx = max(0, min(selected_idx, max(0, len(matches) - 1)))
        if selected_idx < scroll_pos:
            scroll_pos = selected_idx
        elif selected_idx >= scroll_pos + content_h:
            scroll_pos = selected_idx - content_h + 1
        scroll_pos = max(0, min(scroll_pos, max(0, len(matches) - content_h)))

        if not matches:
            try:
                win.addstr(content_y, 2, "No matches. Keep typing or press Esc.", theme.dim)
            except curses.error:
                pass
        else:
            visible = matches[scroll_pos:scroll_pos + content_h]
            for i, (_, rel, _) in enumerate(visible):
                attr = theme.focus if (scroll_pos + i) == selected_idx else 0
                line = _truncate_middle(rel, inner_w)
                try:
                    win.addstr(content_y + i, 2, line[:inner_w], attr)
                except curses.error:
                    pass

        footer = "Type to search • ↑/↓ select • Enter choose • Backspace edit • Esc cancel"
        try:
            win.addstr(box_h - 2, 2, footer[:inner_w], theme.dim)
        except curses.error:
            pass

        win.refresh()
        key = win.getch()

        if key in (27, ord('q'), ord('Q')):
            return None
        if key in (curses.KEY_UP, ord('k')):
            selected_idx = max(0, selected_idx - 1)
            continue
        if key in (curses.KEY_DOWN, ord('j')):
            selected_idx = min(max(0, len(matches) - 1), selected_idx + 1)
            continue
        if key in (curses.KEY_ENTER, 10, 13):
            if matches:
                return str(matches[selected_idx][2])
            continue
        if key in (curses.KEY_BACKSPACE, 127, 8):
            query = query[:-1]
            selected_idx = 0
            scroll_pos = 0
            continue
        if key == 12:  # Ctrl+L clears query
            query = ""
            selected_idx = 0
            scroll_pos = 0
            continue
        if 32 <= key <= 126:
            query += chr(key)
            selected_idx = 0
            scroll_pos = 0


def _run_file_browser_modal(
    stdscr: "curses._CursesWindow",
    theme: Theme,
    start_dir: Path,
) -> str | None:
    current_dir = start_dir.expanduser()
    if not current_dir.exists() or not current_dir.is_dir():
        current_dir = Path.cwd()

    filter_query = ""
    selected_idx = 0
    scroll_pos = 0

    while True:
        h, w = stdscr.getmaxyx()
        box_h = min(max(14, int(h * 0.8)), max(12, h - 2))
        box_w = min(max(70, int(w * 0.9)), max(44, w - 2))
        y, x = (h - box_h) // 2, (w - box_w) // 2

        win = curses.newwin(box_h, box_w, y, x)
        win.keypad(True)
        win.erase()
        win.box()

        inner_w = max(10, box_w - 4)
        try:
            win.addstr(0, 2, " FILE BROWSER ", theme.title)
            win.addstr(1, 2, _truncate_middle(str(current_dir), inner_w), theme.dim)
        except curses.error:
            pass

        query_line = f"Filter: {filter_query or '(none)'}"
        try:
            win.addstr(2, 2, _truncate_middle(query_line, inner_w), theme.dim)
        except curses.error:
            pass

        try:
            raw_entries = list(current_dir.iterdir())
        except Exception:
            raw_entries = []

        dirs: list[Path] = []
        files: list[Path] = []
        for entry in raw_entries:
            try:
                if entry.is_dir():
                    dirs.append(entry)
                else:
                    files.append(entry)
            except Exception:
                continue

        dirs.sort(key=lambda p: p.name.lower())
        files.sort(key=lambda p: p.name.lower())

        children = dirs + files
        if filter_query.strip():
            q = filter_query.strip().lower()
            children = [p for p in children if q in p.name.lower()]

        items: list[tuple[str, Path, bool]] = []
        if current_dir != current_dir.parent:
            items.append(("[↑] ..", current_dir.parent, True))
        for entry in children:
            if entry.is_dir():
                items.append((f"[D] {entry.name}/", entry, True))
            else:
                items.append((f"[F] {entry.name}", entry, False))

        content_y = 4
        content_h = max(1, box_h - 7)

        selected_idx = max(0, min(selected_idx, max(0, len(items) - 1)))
        if selected_idx < scroll_pos:
            scroll_pos = selected_idx
        elif selected_idx >= scroll_pos + content_h:
            scroll_pos = selected_idx - content_h + 1
        scroll_pos = max(0, min(scroll_pos, max(0, len(items) - content_h)))

        if not items:
            try:
                win.addstr(content_y, 2, "No entries found.", theme.dim)
            except curses.error:
                pass
        else:
            visible = items[scroll_pos:scroll_pos + content_h]
            for i, (label, _, _) in enumerate(visible):
                attr = theme.focus if (scroll_pos + i) == selected_idx else 0
                try:
                    win.addstr(content_y + i, 2, _truncate_middle(label, inner_w), attr)
                except curses.error:
                    pass

        footer = "Enter open/select • s choose dir • Backspace up • / filter • Ctrl+F fuzzy • Esc cancel"
        try:
            win.addstr(box_h - 2, 2, footer[:inner_w], theme.dim)
        except curses.error:
            pass

        win.refresh()
        key = win.getch()

        if key in (27, ord('q'), ord('Q')):
            return None
        if key in (curses.KEY_UP, ord('k')):
            selected_idx = max(0, selected_idx - 1)
            continue
        if key in (curses.KEY_DOWN, ord('j')):
            selected_idx = min(max(0, len(items) - 1), selected_idx + 1)
            continue
        if key in (curses.KEY_BACKSPACE, 127, 8, curses.KEY_LEFT):
            current_dir = current_dir.parent
            selected_idx = 0
            scroll_pos = 0
            continue
        if key in (ord('s'), ord('S')):
            return str(current_dir)
        if key == ord('/'):
            filter_input = _run_modal(
                stdscr,
                theme,
                "FILTER",
                "Filter entries (substring, blank to clear):",
                max_length=120,
            )
            if filter_input is not None:
                filter_query = filter_input.strip()
                selected_idx = 0
                scroll_pos = 0
            continue
        if key in (6, ord('f'), ord('F')):  # Ctrl+F / f
            chosen = _run_fuzzy_file_picker(stdscr, theme, current_dir)
            if chosen:
                return chosen
            continue
        if key in (curses.KEY_ENTER, 10, 13):
            if not items:
                continue
            _, target, is_dir = items[selected_idx]
            if is_dir:
                current_dir = target
                selected_idx = 0
                scroll_pos = 0
            else:
                return str(target)


def _run_path_modal(
    stdscr: "curses._CursesWindow",
    theme: Theme,
    title: str,
    prompt: str,
    *,
    max_length: int = 300,
) -> str | None:
    input_str = ""

    while True:
        h, w = stdscr.getmaxyx()
        min_w = 60
        max_w = max(min_w, w - 4)
        preferred_w = max(74, len(prompt) + 10)
        box_w = min(max_w, preferred_w)
        inner_w = max(10, box_w - 4)

        prompt_lines = textwrap.wrap(
            prompt,
            width=inner_w,
            break_long_words=True,
            break_on_hyphens=False,
        ) or [""]

        input_row = 2 + len(prompt_lines) + 1
        help_row = input_row + 2
        box_h = max(9, help_row + 2)
        box_h = min(max(9, h - 2), box_h)

        max_prompt_lines = max(1, box_h - 7)
        if len(prompt_lines) > max_prompt_lines:
            prompt_lines = prompt_lines[: max_prompt_lines - 1] + ["..."]
            input_row = 2 + len(prompt_lines) + 1
            help_row = input_row + 2

        y, x = (h - box_h) // 2, (w - box_w) // 2
        win = curses.newwin(box_h, box_w, y, x)
        win.keypad(True)
        win.erase()
        win.box()

        try:
            win.addstr(0, 2, f" {title} "[: max(0, box_w - 4)], theme.title)
        except curses.error:
            pass

        for i, line in enumerate(prompt_lines):
            try:
                win.addstr(2 + i, 2, line[:inner_w], theme.accent)
            except curses.error:
                pass

        display = input_str + " "
        if len(display) > inner_w:
            display = display[-inner_w:]
        try:
            win.addstr(input_row, 2, display[:inner_w], curses.A_REVERSE | theme.dim)
        except curses.error:
            pass

        help_line = "Enter confirm • Esc cancel • Ctrl+O browse • Ctrl+F fuzzy"
        try:
            win.addstr(help_row, 2, help_line[:inner_w], theme.dim)
        except curses.error:
            pass

        win.refresh()
        key = win.getch()

        if key == 27:
            return None
        if key in (curses.KEY_ENTER, 10, 13):
            return input_str.strip()
        if key in (curses.KEY_BACKSPACE, 127, 8):
            input_str = input_str[:-1]
            continue
        if key in (15, curses.KEY_F2):  # Ctrl+O / F2
            chosen = _run_file_browser_modal(stdscr, theme, _resolve_start_dir(input_str))
            if chosen:
                input_str = chosen
            continue
        if key in (6, curses.KEY_F3):  # Ctrl+F / F3
            chosen = _run_fuzzy_file_picker(stdscr, theme, _resolve_start_dir(input_str))
            if chosen:
                input_str = chosen
            continue
        if 32 <= key <= 126:
            if len(input_str) < max_length:
                input_str += chr(key)


def _prompt_csv_format(
    stdscr: "curses._CursesWindow",
    theme: Theme,
    *,
    mode: str,
) -> str | None:
    if mode == "import":
        prompt = "Format (auto/generic/bitwarden/apple/nordpass):"
        title = "IMPORT FORMAT"
        normalizer = csv_formats.normalize_import_format
        default_value = "auto"
    else:
        prompt = "Format (generic/bitwarden/apple/nordpass):"
        title = "EXPORT FORMAT"
        normalizer = csv_formats.normalize_export_format
        default_value = "generic"

    while True:
        chosen = _run_modal(
            stdscr,
            theme,
            title,
            f"{prompt} [default: {default_value}]",
            max_length=40,
        )
        if chosen is None:
            return None

        candidate = chosen.strip() or default_value
        try:
            return normalizer(candidate)
        except ValueError as e:
            _run_modal(stdscr, theme, "ERROR", str(e))


def _run_security_settings_modal(
    stdscr: "curses._CursesWindow",
    theme: Theme,
    state: AppState,
) -> None:
    selected_row = 0
    rows = ("clipboard", "auto_lock")

    while True:
        if _maybe_auto_clear_clipboard(state):
            state.message = "Clipboard auto-cleared."
        if _should_auto_lock_now(state):
            reason = _auto_lock_reason_text(state)
            _lock_vault(state)
            _prompt_unlock_vault(stdscr, theme, state, reason=reason)
            return

        h, w = stdscr.getmaxyx()
        box_h = 11
        box_w = min(78, max(52, w - 4))
        y, x = (h - box_h) // 2, (w - box_w) // 2
        inner_w = max(10, box_w - 4)

        win = curses.newwin(box_h, box_w, y, x)
        win.keypad(True)
        win.timeout(250)
        win.erase()
        win.box()

        try:
            win.addstr(0, 2, " SECURITY SETTINGS "[:inner_w], theme.title)
        except curses.error:
            pass

        clip_line = f"Clipboard auto-clear: {_clipboard_auto_clear_label(state)}"
        lock_line = f"Auto-lock: {_auto_lock_label(state)}"
        clip_attr = theme.focus if selected_row == 0 else 0
        lock_attr = theme.focus if selected_row == 1 else 0

        _addstr_safe(win, 2, 2, _truncate_middle(clip_line, inner_w), clip_attr)
        _addstr_safe(win, 4, 2, _truncate_middle(lock_line, inner_w), lock_attr)

        _addstr_safe(
            win,
            box_h - 2,
            2,
            "↑/↓ select • ←/→ change • Space toggle • Enter/Esc close"[:inner_w],
            theme.dim,
        )
        win.refresh()

        key = win.getch()
        if key == -1:
            continue
        _record_user_activity(state)

        if key in (27, curses.KEY_ENTER, 10, 13):
            return
        if key in (curses.KEY_UP, ord("k")):
            selected_row = max(0, selected_row - 1)
            continue
        if key in (curses.KEY_DOWN, ord("j")):
            selected_row = min(len(rows) - 1, selected_row + 1)
            continue
        if key in (curses.KEY_LEFT, ord("h")):
            if selected_row == 0:
                state.clipboard_auto_clear_index = (
                    state.clipboard_auto_clear_index - 1
                ) % len(CLIPBOARD_AUTO_CLEAR_OPTIONS)
            else:
                state.auto_lock_index = (state.auto_lock_index - 1) % len(AUTO_LOCK_OPTIONS)
            _persist_security_settings(state)
            continue
        if key in (curses.KEY_RIGHT, ord("l"), ord(" ")):
            if selected_row == 0:
                state.clipboard_auto_clear_index = (
                    state.clipboard_auto_clear_index + 1
                ) % len(CLIPBOARD_AUTO_CLEAR_OPTIONS)
            else:
                state.auto_lock_index = (state.auto_lock_index + 1) % len(AUTO_LOCK_OPTIONS)
            _persist_security_settings(state)
            continue

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
    
    # Security settings
    clipboard_auto_clear_index: int = 0
    auto_lock_index: int = 0
    clipboard_clear_due_at: float | None = None
    clipboard_clear_expected: str | None = None
    last_activity_at: float = field(default_factory=time.monotonic)
    last_tick_at: float = field(default_factory=time.monotonic)

def _coerce_index(raw: str | None, size: int, default: int = 0) -> int:
    if size <= 0:
        return 0
    try:
        idx = int(raw) if raw is not None else default
    except (TypeError, ValueError):
        idx = default
    return max(0, min(size - 1, idx))


def _clipboard_auto_clear_label(state: AppState) -> str:
    return CLIPBOARD_AUTO_CLEAR_OPTIONS[state.clipboard_auto_clear_index][0]


def _clipboard_auto_clear_seconds(state: AppState) -> int | None:
    return CLIPBOARD_AUTO_CLEAR_OPTIONS[state.clipboard_auto_clear_index][1]


def _auto_lock_label(state: AppState) -> str:
    return AUTO_LOCK_OPTIONS[state.auto_lock_index][0]


def _auto_lock_setting(state: AppState) -> int | str | None:
    return AUTO_LOCK_OPTIONS[state.auto_lock_index][1]


def _persist_security_settings(state: AppState) -> None:
    if not state.storage:
        return
    try:
        state.storage.set_app_setting(
            SETTING_KEY_CLIPBOARD_AUTO_CLEAR_INDEX,
            str(state.clipboard_auto_clear_index),
        )
        state.storage.set_app_setting(
            SETTING_KEY_AUTO_LOCK_INDEX,
            str(state.auto_lock_index),
        )
    except Exception:
        pass


def _load_security_settings(state: AppState) -> None:
    if not state.storage:
        return
    try:
        clip_raw = state.storage.get_app_setting(
            SETTING_KEY_CLIPBOARD_AUTO_CLEAR_INDEX,
            str(state.clipboard_auto_clear_index),
        )
        lock_raw = state.storage.get_app_setting(
            SETTING_KEY_AUTO_LOCK_INDEX,
            str(state.auto_lock_index),
        )
        state.clipboard_auto_clear_index = _coerce_index(
            clip_raw,
            len(CLIPBOARD_AUTO_CLEAR_OPTIONS),
            default=0,
        )
        state.auto_lock_index = _coerce_index(
            lock_raw,
            len(AUTO_LOCK_OPTIONS),
            default=0,
        )
    except Exception:
        state.clipboard_auto_clear_index = 0
        state.auto_lock_index = 0


def _record_user_activity(state: AppState, now: float | None = None) -> None:
    current = time.monotonic() if now is None else now
    state.last_activity_at = current
    state.last_tick_at = current


def _should_auto_lock_now(state: AppState, now: float | None = None) -> bool:
    current = time.monotonic() if now is None else now
    if not state.vault_unlocked:
        state.last_tick_at = current
        return False

    setting = _auto_lock_setting(state)
    should_lock = False
    if setting == AUTO_LOCK_SCREEN_OFF:
        should_lock = (current - state.last_tick_at) >= SCREEN_OFF_LOCK_GAP_SECONDS
    elif isinstance(setting, int):
        should_lock = (current - state.last_activity_at) >= setting

    state.last_tick_at = current
    return should_lock


def _auto_lock_reason_text(state: AppState) -> str:
    setting = _auto_lock_setting(state)
    if setting == AUTO_LOCK_SCREEN_OFF:
        return "Vault auto-locked after screen-off/sleep detection."
    return f"Vault auto-locked after {_auto_lock_label(state)} of inactivity."


def _copy_to_clipboard_with_policy(state: AppState, value: str) -> str:
    pyperclip.copy(value)
    seconds = _clipboard_auto_clear_seconds(state)
    if seconds is None:
        state.clipboard_clear_due_at = None
        state.clipboard_clear_expected = None
        return "Copied to clipboard."

    state.clipboard_clear_due_at = time.monotonic() + seconds
    state.clipboard_clear_expected = value
    return f"Copied to clipboard. Auto-clear in {_clipboard_auto_clear_label(state)}."


def _maybe_auto_clear_clipboard(state: AppState, now: float | None = None) -> bool:
    if state.clipboard_clear_due_at is None:
        return False

    current = time.monotonic() if now is None else now
    if current < state.clipboard_clear_due_at:
        return False

    expected = state.clipboard_clear_expected
    state.clipboard_clear_due_at = None
    state.clipboard_clear_expected = None

    try:
        current_clip = pyperclip.paste()
        if expected is None or current_clip == expected:
            pyperclip.copy("")
    except Exception:
        return False
    return True


def _lock_vault(state: AppState) -> None:
    if state.storage:
        state.storage.close()
    state.vault_unlocked = False
    state.vault_credentials = []
    state.vault_selected_idx = 0
    state.vault_scroll_y = 0


def _prompt_unlock_vault(
    stdscr: "curses._CursesWindow",
    theme: Theme,
    state: AppState,
    *,
    reason: str,
) -> bool:
    if not state.storage:
        state.message = "Vault unavailable."
        return False

    while True:
        pwd = _run_modal(
            stdscr,
            theme,
            "VAULT LOCKED",
            f"{reason} Enter Master Password to unlock (Esc to keep locked):",
            is_password=True,
            max_length=200,
        )
        if pwd is None:
            state.message = "Vault locked."
            return False

        try:
            state.storage.unlock_vault(pwd)
            state.vault_unlocked = True
            state.vault_credentials = state.storage.list_credentials()
            _record_user_activity(state)
            state.message = "Vault unlocked."
            return True
        except InvalidPasswordError:
            _run_modal(stdscr, theme, "ERROR", "Invalid master password.")
        except Exception as e:
            _run_modal(stdscr, theme, "ERROR", f"Unlock failed: {e}")
            state.message = "Vault locked."
            return False


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
    msg = "Resize terminal for dashboard view (recommended: 80x24). Press Esc twice to quit."
    _addstr_safe(stdscr, h // 2, _center_x(stdscr, msg), msg, theme.title)


def _render_footer(stdscr: "curses._CursesWindow", theme: Theme, message: str) -> None:
    h, w = stdscr.getmaxyx()

    msg = message[: max(0, w - 1)]
    
    # Stacked help lines for better readability
    help_lines = [
        "Tab/↑/↓: Move  •  Enter/g: Generate  •  s: Save",
        "t: Security  •  /: Search  •  i/e: CSV  •  Esc×2: Quit",
    ]

    _addstr_safe(stdscr, h - 3, 0, " " * max(0, w - 1), theme.dim)
    _addstr_safe(stdscr, h - 3, 1, msg, theme.accent)

    for i, line in enumerate(help_lines):
        _addstr_safe(stdscr, h - 2 + i, 0, " " * max(0, w - 1), theme.dim)
        _addstr_safe(stdscr, h - 2 + i, 1, line[: max(0, w - 2)], theme.dim)


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

    # Stacked hotkeys for better readability
    hotkey_lines = [
        "g: Generate  s: Save    t: Security",
        "/: Search    v: Vault   a: Add",
        "?: Help     Esc×2: Quit",
    ]
    for line in hotkey_lines:
        _addstr_safe(stdscr, row, x + 2, line[:inner_w], theme.dim)
        row += 1


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


def _run_save_generated_flow(
    stdscr: "curses._CursesWindow",
    theme: Theme,
    state: AppState,
) -> None:
    """Save current generated output by prompting for the missing field(s)."""
    if not state.storage or not state.vault_unlocked:
        _run_modal(stdscr, theme, "ERROR", "Vault is locked or unavailable.")
        state.message = "Save unavailable."
        return

    if not state.output:
        _run_modal(stdscr, theme, "ERROR", "Nothing to save yet. Generate first.")
        state.message = "Nothing to save yet."
        return

    service = _run_modal(stdscr, theme, "SAVE", "Enter Service/Website Name:")
    if not service:
        state.message = "Save cancelled."
        return

    service = service.strip()
    if not service:
        state.message = "Save cancelled."
        return

    try:
        final_username = ""
        final_password = ""

        if state.mode == "username":
            # We generated a username, so we need a password.
            final_username = state.output

            def _gen_pwd():
                return generator.generate_character_password(
                    16, use_letters=True, use_numbers=True, use_special=True
                )

            final_password = _run_modal(
                stdscr,
                theme,
                "SAVE",
                f"Enter Password for {final_username}:",
                is_password=False,
                generator_func=_gen_pwd,
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
                generator_func=_gen_user,
            )

        if final_username and final_password:
            final_username = final_username.strip()
            if not final_username:
                state.message = "Save cancelled."
                return

            note = _run_modal(stdscr, theme, "SAVE", "Note (optional, Enter to skip):", max_length=500)
            note_is_hidden = False
            if note:
                hide_note = _run_modal(stdscr, theme, "SAVE", "Hide note? (y/n) [n]:", max_length=1, initial_value="n")
                note_is_hidden = hide_note and hide_note.lower() == "y"

            result = _save_credential_duplicate_safe(
                stdscr,
                theme,
                state,
                service=service,
                username=final_username,
                password=final_password,
                note=note or "",
                note_is_hidden=note_is_hidden,
            )
            if result == "saved":
                state.message = f"Saved credential for {service}."
            elif result == "overwritten":
                state.message = f"Overwrote credential for {service}."
            else:
                state.message = "Save cancelled."
        else:
            state.message = "Save cancelled."

    except Exception as e:
        state.message = f"Error saving: {e}"


def _run_details_modal(
    stdscr: "curses._CursesWindow",
    theme: Theme,
    state: AppState,
    credential: dict,
) -> None:
    """Runs a modal to show credential details and allow copying."""
    h, w = stdscr.getmaxyx()
    box_h, box_w = 14, 60
    y, x = (h - box_h) // 2, (w - box_w) // 2
    
    win = curses.newwin(box_h, box_w, y, x)
    win.keypad(True)
    win.timeout(250)
    
    while True:
        if _maybe_auto_clear_clipboard(state):
            state.message = "Clipboard auto-cleared."
        if _should_auto_lock_now(state):
            reason = _auto_lock_reason_text(state)
            _lock_vault(state)
            _prompt_unlock_vault(stdscr, theme, state, reason=reason)
            return
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
        
        # Note
        note_text = credential.get('note', '')
        note_is_hidden = credential.get('note_is_hidden', False)
        display_note = "*" * len(note_text) if note_is_hidden and note_text else note_text
        if display_note:
            win.addstr(row, 2, "Note:", label_attr)
            row += 1
            # Wrap note to fit
            import textwrap
            wrapped_note = textwrap.wrap(display_note, width=box_w-14)
            for line in wrapped_note:
                win.addstr(row, 2, line[:box_w-14], val_attr)
                row += 1
        
        win.addstr(row, 2, "Password:", label_attr)
        win.addstr(row, 12, credential['password'][:box_w-14], val_attr)
        row += 2
        
        win.addstr(row, 2, "Created:", label_attr)
        win.addstr(row, 12, str(credential['created_at'])[:box_w-14])
        
        # Footer - stacked on two lines for better readability
        line1 = "c: Copy Pass  u: Copy User"
        if note_text:
            line1 += "  n: Copy Note"
        
        line2_parts = []
        if note_text:
            line2_parts.append("h: Show/Hide Note")
        line2_parts.append("Esc: Close")
        line2 = "  ".join(line2_parts)
        
        win.addstr(box_h - 3, 2, line1[:box_w-4], theme.dim)
        win.addstr(box_h - 2, 2, line2[:box_w-4], theme.dim)
        
        win.refresh()
        
        key = win.getch()
        if key == -1:
            continue
        _record_user_activity(state)
        
        if key in (27, ord('q'), ord('Q')): # Esc/q
            return
            
        elif key in (ord('c'), ord('C')):
            try:
                msg = _copy_to_clipboard_with_policy(state, credential['password'])
                # Quick feedback overlay
                win.addstr(box_h - 2, 2, "       COPIED PASSWORD!       ", theme.ok)
                win.refresh()
                curses.napms(500)
                state.message = msg
            except Exception:
                pass

        elif key in (ord('u'), ord('U')):
            try:
                msg = _copy_to_clipboard_with_policy(state, credential['username'])
                win.addstr(box_h - 2, 2, "       COPIED USERNAME!       ", theme.ok)
                win.refresh()
                curses.napms(500)
                state.message = msg
            except Exception:
                pass

        elif key in (ord('n'), ord('N')):
            if note_text:
                try:
                    msg = _copy_to_clipboard_with_policy(state, note_text)
                    win.addstr(box_h - 2, 2, "        COPIED NOTE!        ", theme.ok)
                    win.refresh()
                    curses.napms(500)
                    state.message = msg
                except Exception:
                    pass
            else:
                win.addstr(box_h - 2, 2, "       NO NOTE TO COPY!      ", theme.warn)
                win.refresh()
                curses.napms(500)

        elif key in (ord('h'), ord('H')):
            if note_text:
                try:
                    cred_id = credential['id']
                    current_hidden = credential.get('note_is_hidden', False)
                    state.storage.update_credential(
                        cred_id,
                        credential['service'],
                        credential['username'],
                        credential['password'],
                        note_text,
                        not current_hidden
                    )
                    state.vault_credentials = state.storage.list_credentials()
                    credential = next((c for c in state.vault_credentials if c['id'] == cred_id), credential)
                    break
                except Exception as e:
                    win.addstr(box_h - 2, 2, f"     ERROR: {str(e)[:20]}    ", theme.warn)
                    win.refresh()
                    curses.napms(1000)
            else:
                win.addstr(box_h - 2, 2, "       NO NOTE TO HIDE!     ", theme.warn)
                win.refresh()
                curses.napms(500)


def _run_vault_modal(
    stdscr: "curses._CursesWindow",
    theme: Theme,
    state: AppState,
    *,
    start_in_search: bool = False,
) -> None:
    """Runs a modal vault manager."""
    if not state.vault_unlocked or not state.storage:
        _run_modal(stdscr, theme, "ERROR", "Vault locked or unavailable.")
        return
        
    # Reload credentials
    state.vault_credentials = state.storage.list_credentials()
    vault_filter = ""
    search_mode = start_in_search
    
    while True:
        if _maybe_auto_clear_clipboard(state):
            state.message = "Clipboard auto-cleared."
        if _should_auto_lock_now(state):
            reason = _auto_lock_reason_text(state)
            _lock_vault(state)
            _prompt_unlock_vault(stdscr, theme, state, reason=reason)
            return
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
        win.timeout(250)
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

        filtered_credentials = _filter_vault_credentials(state.vault_credentials, vault_filter)

        if not filtered_credentials:
            state.vault_selected_idx = 0
            state.vault_scroll_y = 0
        else:
            state.vault_selected_idx = max(0, min(state.vault_selected_idx, len(filtered_credentials) - 1))

        filter_label = vault_filter if vault_filter else "(type to search)"
        filter_prefix = "Search*" if search_mode else "Search"
        filter_line = f"{filter_prefix}: {filter_label}"
        try:
            win.addstr(list_y, 2, _truncate_middle(filter_line, inner_w), theme.dim)
        except curses.error:
            pass
        list_y += 1
        
        # Header
        headers = f"{'Service':<20} {'Username':<20}"
        try:
            win.addstr(list_y, 2, headers[:inner_w], theme.dim | curses.A_UNDERLINE)
        except curses.error:
            pass
            
        list_y += 2
        content_h = max(1, inner_h - 4)  # Reserve space for filter line + footer
        
        if not filtered_credentials:
            try:
                win.addstr(list_y, 2, "No matching credentials.", theme.dim)
            except curses.error:
                pass
        else:
            total = len(filtered_credentials)
            
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
                cred = filtered_credentials[i]
                is_selected = (i == state.vault_selected_idx)
                
                attr = theme.focus if is_selected else 0
                s_serv = cred['service']
                s_user = cred['username']
                
                line = f"{s_serv:<20} {s_user:<20}"
                try:
                    win.addstr(list_y + (i - start), 2, line[:inner_w], attr)
                except curses.error:
                    pass

        # Footer - stacked for readability
        if search_mode:
            footer_lines = [
                "Typing search • Enter: details",
                "↑/↓: select • Backspace: edit • Esc: stop",
            ]
        else:
            footer_lines = [
                "Enter: details  e: edit  c: copy pass  u: copy user",
                "d: delete  /: search  Esc/v: close",
            ]
        try:
            for i, line in enumerate(footer_lines):
                win.addstr(box_h - 3 + i, 2, line[:inner_w], theme.dim)
        except curses.error:
            pass
            
        win.refresh()
        
        key = win.getch()
        if key == -1:
            continue
        _record_user_activity(state)

        if key == 27:  # ESC
            if search_mode:
                search_mode = False
                continue
            return
        
        if key in (ord('v'), ord('V'), ord('q'), ord('Q')): # v/q
            return
            
        if key == ord('/'):
            search_mode = True
            continue

        if search_mode:
            if key in (curses.KEY_BACKSPACE, 127, 8):
                if vault_filter:
                    vault_filter = vault_filter[:-1]
                    state.vault_selected_idx = 0
                    state.vault_scroll_y = 0
                continue
            if key == 12:  # Ctrl+L
                vault_filter = ""
                state.vault_selected_idx = 0
                state.vault_scroll_y = 0
                continue
            if 32 <= key <= 126:
                vault_filter += chr(key)
                state.vault_selected_idx = 0
                state.vault_scroll_y = 0
        if key in (curses.KEY_UP, ord('k')):
            if filtered_credentials:
                state.vault_selected_idx = max(0, state.vault_selected_idx - 1)
        elif key in (curses.KEY_DOWN, ord('j')):
            if filtered_credentials:
                state.vault_selected_idx = min(len(filtered_credentials) - 1, state.vault_selected_idx + 1)
        
        elif key in (ord('e'), ord('E')):
            if filtered_credentials:
                cred = filtered_credentials[state.vault_selected_idx]
                service = _run_modal(
                    stdscr,
                    theme,
                    "EDIT",
                    "Service name:",
                    max_length=120,
                    initial_value=cred["service"],
                )
                if service is None:
                    continue
                username = _run_modal(
                    stdscr,
                    theme,
                    "EDIT",
                    "Username:",
                    max_length=120,
                    initial_value=cred["username"],
                )
                if username is None:
                    continue
                password = _run_modal(
                    stdscr,
                    theme,
                    "EDIT",
                    "Password:",
                    is_password=True,
                    max_length=200,
                    initial_value=cred["password"],
                )
                if password is None:
                    continue

                service = service.strip()
                username = username.strip()
                if not service or not username or not password:
                    _run_modal(stdscr, theme, "ERROR", "Service, username, and password are required.")
                    continue

                try:
                    # Get existing note for the credential
                    existing_note = cred.get("note", "")
                    existing_hidden = cred.get("note_is_hidden", False)
                    note = _run_modal(stdscr, theme, "EDIT", "Note (optional):", max_length=500, initial_value=existing_note)
                    if note is None:
                        continue
                    
                    # Ask if user wants to hide the note
                    hide_option = "y" if existing_hidden else "n"
                    hide_note = _run_modal(
                        stdscr, theme, "EDIT", 
                        f"Hide note? (y/n) [{hide_option}]:", 
                        max_length=1, 
                        initial_value=hide_option
                    )
                    if hide_note is None:
                        continue
                    note_is_hidden = hide_note.lower() == "y"
                    
                    state.storage.update_credential(cred["id"], service, username, password, note, note_is_hidden)
                    state.vault_credentials = state.storage.list_credentials()

                    refreshed_filtered = _filter_vault_credentials(state.vault_credentials, vault_filter)
                    found_idx = next(
                        (i for i, item in enumerate(refreshed_filtered) if item.get("id") == cred["id"]),
                        None,
                    )
                    if found_idx is None:
                        state.vault_selected_idx = max(0, len(refreshed_filtered) - 1)
                    else:
                        state.vault_selected_idx = found_idx
                    state.vault_scroll_y = 0

                    _run_modal(stdscr, theme, "SUCCESS", "Credential updated.")
                except Exception as e:
                    _run_modal(stdscr, theme, "ERROR", f"Update failed: {e}")
        
        elif key in (ord('c'), ord('C')):
            if filtered_credentials:
                cred = filtered_credentials[state.vault_selected_idx]
                try:
                    msg = _copy_to_clipboard_with_policy(state, cred['password'])
                    _run_modal(stdscr, theme, "SUCCESS", msg)
                except Exception as e:
                    _run_modal(stdscr, theme, "ERROR", f"Copy failed: {e}")

        elif key in (ord('u'), ord('U')):
            if filtered_credentials:
                cred = filtered_credentials[state.vault_selected_idx]
                try:
                    msg = _copy_to_clipboard_with_policy(state, cred['username'])
                    _run_modal(stdscr, theme, "SUCCESS", msg)
                except Exception as e:
                    _run_modal(stdscr, theme, "ERROR", f"Copy failed: {e}")

        elif key in (curses.KEY_ENTER, 10, 13):
            if filtered_credentials:
                cred = filtered_credentials[state.vault_selected_idx]
                _run_details_modal(stdscr, theme, state, cred)
        
        elif key in (ord('d'), ord('D')):
            if filtered_credentials:
                cred = filtered_credentials[state.vault_selected_idx]
                confirm = _run_modal(stdscr, theme, "CONFIRM", f"Delete {cred['service']}? (type 'yes'):")
                if confirm and confirm.lower() == 'yes':
                    try:
                        state.storage.delete_credential(cred['id'])
                        state.vault_credentials = state.storage.list_credentials()
                        refreshed_filtered = _filter_vault_credentials(state.vault_credentials, vault_filter)
                        if state.vault_selected_idx >= len(refreshed_filtered):
                            state.vault_selected_idx = max(0, len(refreshed_filtered) - 1)
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
        stdscr.timeout(250)

        words = generator.load_wordlist()
        state = AppState()
        
        # --- Storage Initialization ---
        try:
            state.storage = StorageManager()
        except Exception as e:
            # If we can't create the storage manager (e.g. permission error on folder),
            # we should display it and exit or fallback.
            # Since we are in curses, we can show a modal.
            critical_last_esc_at: float | None = None
            while True:
                stdscr.erase()
                _render_header(stdscr, theme)
                msg = f"Storage Error: {e}"
                _draw_box(stdscr, 10, 5, 5, 70, title="CRITICAL ERROR", border_attr=theme.bad, title_attr=theme.bad)
                _addstr_safe(stdscr, 12, 7, msg, theme.dim)
                _addstr_safe(stdscr, 13, 7, "Press Esc twice to quit", theme.dim)
                stdscr.refresh()
                key = stdscr.getch()
                should_quit, critical_last_esc_at = _handle_double_esc_quit(
                    key=key, last_esc_at=critical_last_esc_at
                )
                if should_quit:
                    return 1
                if key != 27:
                    critical_last_esc_at = None

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
            _load_security_settings(state)
            _record_user_activity(state)

        # Generate something immediately so the dashboard isn't empty.
        _generate(state, words)
        last_esc_quit_at: float | None = None

        while True:
            if _maybe_auto_clear_clipboard(state):
                state.message = "Clipboard auto-cleared."
            if _should_auto_lock_now(state):
                reason = _auto_lock_reason_text(state)
                _lock_vault(state)
                _prompt_unlock_vault(stdscr, theme, state, reason=reason)
                stdscr.clear()
                continue
            stdscr.erase()
            header_end = _render_header(stdscr, theme)
            h, w = stdscr.getmaxyx()

            min_w, min_h = 70, 20
            if w < min_w or h < min_h:
                _render_resize_hint(stdscr, theme)
                _render_footer(stdscr, theme, state.message)
                stdscr.refresh()
                key = stdscr.getch()
                if key == -1:
                    continue
                _record_user_activity(state)
                if key == 27:
                    should_quit, last_esc_quit_at = _handle_double_esc_quit(
                        key=key, last_esc_at=last_esc_quit_at
                    )
                    if should_quit:
                        return 0
                    state.message = "Press Esc again to quit."
                    continue
                last_esc_quit_at = None
                if key in (ord("q"), ord("Q")):
                    state.message = "Press Esc twice to quit."
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
            if key == -1:
                continue
            _record_user_activity(state)
            if key == 27:
                should_quit, last_esc_quit_at = _handle_double_esc_quit(
                    key=key, last_esc_at=last_esc_quit_at
                )
                if should_quit:
                    return 0
                state.message = "Press Esc again to quit."
                continue
            last_esc_quit_at = None
            if key in (ord("q"), ord("Q")):
                state.message = "Press Esc twice to quit."
                continue
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
            save_now = key in (ord("s"), ord("S"))
            quick_vault_search = key == ord("/")
            open_vault = key in (ord("v"), ord("V"))
            open_security_settings = key in (ord("t"), ord("T"))
            import_csv = key in (ord("i"), ord("I"))
            export_csv = key in (ord("e"), ord("E"))
            manual_add = key in (ord("a"), ord("A"))
            show_help = key == ord("?")

            if show_help:
                help_lines = [
                    "GLOBAL HOTKEYS",
                    "g       : Generate new credential",
                    "s       : Save generated credential",
                    "t       : Security settings",
                    "/       : Quick vault search",
                    "v       : Open Vault Explorer",
                    "i       : Import credentials from CSV (choose format)",
                    "e       : Export credentials to CSV (choose format)",
                    "?       : Show this help",
                    "Esc x2  : Quit application",
                    "",
                    "SECURITY OPTIONS",
                    "Clipboard auto-clear: No auto-clear / 15s / 30s / 45s / 1m / 2m / 3m",
                    "Auto-lock: No auto-lock / Lock when screen off / 5m / 10m / 15m",
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
                    "FILE PICKER (during import/export path prompt)",
                    "Ctrl+O  : Open file browser",
                    "Ctrl+F  : Open fuzzy file finder",
                    "F2/F3   : Browser/fuzzy alternatives",
                    "s       : Select current directory (browser mode)",
                    "",
                    "VAULT EXPLORER (inside 'v')",
                    "↑ / ↓   : Navigate list",
                    "Enter   : View details",
                    "e       : Edit entry",
                    "c       : Copy Password",
                    "u       : Copy Username",
                    "d       : Delete entry",
                    "/       : Start live vault search",
                    "Esc     : Close vault",
                ]
                _run_scrollable_modal(stdscr, theme, "HOTKEY LEGEND", help_lines)
                stdscr.clear()
                continue

            if open_security_settings:
                _run_security_settings_modal(stdscr, theme, state)
                state.message = (
                    f"Security updated: clipboard={_clipboard_auto_clear_label(state)}, "
                    f"auto-lock={_auto_lock_label(state)}."
                )
                stdscr.clear()
                continue

            if quick_vault_search:
                _run_vault_modal(stdscr, theme, state, start_in_search=True)
                stdscr.clear()
                continue

            if save_now:
                _run_save_generated_flow(stdscr, theme, state)
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
                    service = service.strip()
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
                    username = username.strip()
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
                    
                    note = _run_modal(stdscr, theme, "ADD", "Note (optional, Enter to skip):", max_length=500)
                    note_is_hidden = False
                    if note:
                        hide_note = _run_modal(stdscr, theme, "ADD", "Hide note? (y/n) [n]:", max_length=1, initial_value="n")
                        note_is_hidden = hide_note and hide_note.lower() == "y"
                    
                    result = _save_credential_duplicate_safe(
                        stdscr,
                        theme,
                        state,
                        service=service,
                        username=username,
                        password=password,
                        note=note or "",
                        note_is_hidden=note_is_hidden,
                    )
                    if result == "saved":
                        state.message = f"Added credential for {service}."
                    elif result == "overwritten":
                        state.message = f"Overwrote credential for {service}."
                    else:
                        state.message = "Add cancelled."
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
                
                selected_export_format = _prompt_csv_format(stdscr, theme, mode="export")
                if selected_export_format is None:
                    state.message = "Export cancelled."
                    stdscr.clear()
                    continue
                file_path = _run_path_modal(
                    stdscr,
                    theme,
                    "EXPORT CSV",
                    "Enter export path (file or directory):",
                    max_length=300,
                )
                if file_path:
                    raw_path = Path(file_path).expanduser()
                    csv_path = raw_path
                    if raw_path.exists() and raw_path.is_dir():
                        default_name = (
                            f"generate-it-{selected_export_format}-"
                            f"{_dt.datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
                        )
                        filename = _run_modal(
                            stdscr,
                            theme,
                            "EXPORT FILENAME",
                            f"Directory selected. Enter file name: [default: {default_name}]",
                            max_length=160,
                        )
                        if filename is None:
                            state.message = "Export cancelled."
                            stdscr.clear()
                            continue

                        filename = filename.strip() or default_name
                        if "/" in filename or "\\" in filename:
                            _run_modal(
                                stdscr,
                                theme,
                                "ERROR",
                                "Use a file name only (no directory separators).",
                            )
                            state.message = "Export cancelled."
                            stdscr.clear()
                            continue

                        if not filename.lower().endswith(".csv"):
                            filename += ".csv"
                        csv_path = raw_path / filename

                    parent_dir = csv_path.parent
                    if not parent_dir.exists() or not parent_dir.is_dir():
                        _run_modal(stdscr, theme, "ERROR", f"Directory not found: {parent_dir}")
                        state.message = "Export cancelled."
                        stdscr.clear()
                        continue
                    
                    # Check if file exists and confirm overwrite
                    if csv_path.exists():
                        confirm = _run_modal(stdscr, theme, "CONFIRM", f"File exists. Overwrite? (type 'yes'):")
                        if not confirm or confirm.lower() != 'yes':
                            state.message = "Export cancelled."
                            stdscr.clear()
                            continue
                    
                    try:
                        exported, skipped = state.storage.export_to_csv(
                            csv_path,
                            export_format=selected_export_format,
                        )
                        
                        if skipped:
                            skip_lines = [f"The following {len(skipped)} credential(s) failed to export:", ""]
                            for item in skipped:
                                skip_lines.append(f"- {item['service']} / {item['username']}: {item['error']}")
                            _run_scrollable_modal(stdscr, theme, "EXPORT WARNING", skip_lines)
                        
                        format_label = csv_formats.EXPORT_FORMAT_LABELS.get(
                            selected_export_format,
                            selected_export_format,
                        )
                        state.message = f"Exported {exported} credential(s) as {format_label} to {csv_path}."
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
                
                selected_import_format = _prompt_csv_format(stdscr, theme, mode="import")
                if selected_import_format is None:
                    state.message = "Import cancelled."
                    stdscr.clear()
                    continue
                file_path = _run_path_modal(
                    stdscr,
                    theme,
                    "IMPORT CSV",
                    "Enter import file path:",
                    max_length=300,
                )
                if file_path:
                    csv_path = Path(file_path).expanduser()
                    
                    if not csv_path.exists():
                        _run_modal(stdscr, theme, "ERROR", f"File not found: {csv_path}")
                        stdscr.clear()
                        continue
                    
                    try:
                        # Preview pass: detect duplicates without importing
                        _, _, preview_issues = state.storage.import_from_csv(
                            csv_path,
                            merge_duplicates=False,
                            dry_run=True,
                            import_format=selected_import_format,
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
                            csv_path,
                            merge_duplicates=merge,
                            dry_run=False,
                            import_format=selected_import_format,
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
                        
                        format_label = csv_formats.IMPORT_FORMAT_LABELS.get(
                            selected_import_format,
                            selected_import_format,
                        )
                        state.message = f"Imported {imported} credential(s) via {format_label}. ({skipped} skipped)"
                        
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
                    _run_save_generated_flow(stdscr, theme, state)
                else:
                    # Enter on sliders generates as a convenience.
                    if activate and focus_id in {"char_length", "word_count", "username_length", "username_word_count"}:
                        _generate(state, words)

        return 0

    try:
        return curses.wrapper(_main)
    except QuitApp:
        return 0
