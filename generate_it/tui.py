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
from typing import Callable
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
from . import tui_files
from . import tui_modal
from . import tui_security
from . import csv_formats
from . import tui_csv
from .storage import StorageManager, InvalidPasswordError
from .tui_state import AppState
from .tui_helpers import (
    _truncate_middle,
    _fuzzy_score,
    _filter_vault_credentials,
    _find_duplicate_credential,
    _estimate_entropy_bits,
    _strength_label,
)

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

def _save_credential_duplicate_safe(
    stdscr: curses.window,
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
        confirm = tui_modal._run_modal(
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
    stdscr: curses.window,
    theme: Theme,
    root_dir: Path,
) -> str | None:
    files = tui_files._collect_files_for_fuzzy(root_dir)
    if not files:
        tui_modal._run_modal(stdscr, theme, "NO FILES", f"No files found under {root_dir}.")
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
    stdscr: curses.window,
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
            filter_input = tui_modal._run_modal(
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
    stdscr: curses.window,
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
    stdscr: curses.window,
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
        chosen = tui_modal._run_modal(
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
            tui_modal._run_modal(stdscr, theme, "ERROR", str(e))

def _run_security_settings_modal(
    stdscr: curses.window,
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
            tui_security._prompt_unlock_vault(stdscr, theme, state, reason=reason)
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

        R._addstr_safe(win, 2, 2, _truncate_middle(clip_line, inner_w), clip_attr)
        R._addstr_safe(win, 4, 2, _truncate_middle(lock_line, inner_w), lock_attr)

        R._addstr_safe(
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

# --- Theme ------------------------------------------------------------------

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
    try:
        pyperclip.copy(value)
    except Exception:
        # Fallback for systems (like headless Linux) without a clipboard manager
        return "Clipboard error: Install 'xclip' or 'xsel'."

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

# --- Rendering --------------------------------------------------------------

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
    stdscr: curses.window,
    theme: Theme,
    state: AppState,
) -> None:
    """Save current generated output by prompting for the missing field(s)."""
    if not state.storage or not state.vault_unlocked:
        tui_modal._run_modal(stdscr, theme, "ERROR", "Vault is locked or unavailable.")
        state.message = "Save unavailable."
        return

    if not state.output:
        tui_modal._run_modal(stdscr, theme, "ERROR", "Nothing to save yet. Generate first.")
        state.message = "Nothing to save yet."
        return

    service = tui_modal._run_modal(stdscr, theme, "SAVE", "Enter Service/Website Name:")
    if not service:
        state.message = "Save cancelled."
        return

    service = service.strip()
    if not service:
        state.message = "Save cancelled."
        return

    try:
        final_username: str | None = ""
        final_password: str | None = ""

        if state.mode == "username":
            # We generated a username, so we need a password.
            final_username = state.output

            def _gen_pwd():
                return generator.generate_character_password(
                    16, use_letters=True, use_numbers=True, use_special=True
                )

            final_password = tui_modal._run_modal(
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

            final_username = tui_modal._run_modal(
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

            note = tui_modal._run_modal(stdscr, theme, "SAVE", "Note (optional, Enter to skip):", max_length=500)
            note_is_hidden = False
            if note:
                hide_note = tui_modal._run_modal(stdscr, theme, "SAVE", "Hide note? (y/n) [n]:", max_length=1, initial_value="n")
                note_is_hidden = bool(hide_note and hide_note.lower() == "y")

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
    stdscr: curses.window,
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
            tui_security._prompt_unlock_vault(stdscr, theme, state, reason=reason)
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
                    if state.storage:
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
    stdscr: curses.window,
    theme: Theme,
    state: AppState,
    *,
    start_in_search: bool = False,
) -> None:
    """Runs a modal vault manager."""
    if not state.vault_unlocked or not state.storage:
        tui_modal._run_modal(stdscr, theme, "ERROR", "Vault locked or unavailable.")
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
            tui_security._prompt_unlock_vault(stdscr, theme, state, reason=reason)
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
                service = tui_modal._run_modal(
                    stdscr,
                    theme,
                    "EDIT",
                    "Service name:",
                    max_length=120,
                    initial_value=cred["service"],
                )
                if service is None:
                    continue
                username = tui_modal._run_modal(
                    stdscr,
                    theme,
                    "EDIT",
                    "Username:",
                    max_length=120,
                    initial_value=cred["username"],
                )
                if username is None:
                    continue
                password = tui_modal._run_modal(
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
                    tui_modal._run_modal(stdscr, theme, "ERROR", "Service, username, and password are required.")
                    continue

                try:
                    # Get existing note for the credential
                    existing_note = cred.get("note", "")
                    existing_hidden = cred.get("note_is_hidden", False)
                    note = tui_modal._run_modal(stdscr, theme, "EDIT", "Note (optional):", max_length=500, initial_value=existing_note)
                    if note is None:
                        continue
                    
                    # Ask if user wants to hide the note
                    hide_option = "y" if existing_hidden else "n"
                    hide_note = tui_modal._run_modal(
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

                    tui_modal._run_modal(stdscr, theme, "SUCCESS", "Credential updated.")
                except Exception as e:
                    tui_modal._run_modal(stdscr, theme, "ERROR", f"Update failed: {e}")
        
        elif key in (ord('c'), ord('C')):
            if filtered_credentials:
                cred = filtered_credentials[state.vault_selected_idx]
                try:
                    msg = _copy_to_clipboard_with_policy(state, cred['password'])
                    tui_modal._run_modal(stdscr, theme, "SUCCESS", msg)
                except Exception as e:
                    tui_modal._run_modal(stdscr, theme, "ERROR", f"Copy failed: {e}")

        elif key in (ord('u'), ord('U')):
            if filtered_credentials:
                cred = filtered_credentials[state.vault_selected_idx]
                try:
                    msg = _copy_to_clipboard_with_policy(state, cred['username'])
                    tui_modal._run_modal(stdscr, theme, "SUCCESS", msg)
                except Exception as e:
                    tui_modal._run_modal(stdscr, theme, "ERROR", f"Copy failed: {e}")

        elif key in (curses.KEY_ENTER, 10, 13):
            if filtered_credentials:
                cred = filtered_credentials[state.vault_selected_idx]
                _run_details_modal(stdscr, theme, state, cred)
        
        elif key in (ord('d'), ord('D')):
            if filtered_credentials:
                cred = filtered_credentials[state.vault_selected_idx]
                confirm = tui_modal._run_modal(stdscr, theme, "CONFIRM", f"Delete {cred['service']}? (type 'yes'):")
                if confirm and confirm.lower() == 'yes':
                    try:
                        state.storage.delete_credential(cred['id'])
                        state.vault_credentials = state.storage.list_credentials()
                        refreshed_filtered = _filter_vault_credentials(state.vault_credentials, vault_filter)
                        if state.vault_selected_idx >= len(refreshed_filtered):
                            state.vault_selected_idx = max(0, len(refreshed_filtered) - 1)
                    except Exception as e:
                        tui_modal._run_modal(stdscr, theme, "ERROR", f"Delete failed: {e}")

# --- Main loop --------------------------------------------------------------

def run() -> int:
    """Run the curses TUI."""

    try:
        locale.setlocale(locale.LC_ALL, "")
    except Exception:
        pass

    def _main(stdscr: curses.window) -> int:
        theme = R._init_theme()

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
                R._render_header(stdscr, theme)
                msg = f"Storage Error: {e}"
                R._draw_box(stdscr, 10, 5, 5, 70, title="CRITICAL ERROR", border_attr=theme.bad, title_attr=theme.bad)
                R._addstr_safe(stdscr, 12, 7, msg, theme.dim)
                R._addstr_safe(stdscr, 13, 7, "Press Esc twice to quit", theme.dim)
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
                R._render_header(stdscr, theme)
                pwd = tui_modal._run_modal(stdscr, theme, "SETUP", "Create Master Password:", is_password=True)
                if pwd is None: # Cancelled
                    return 0
                if len(pwd) < 4:
                    tui_modal._run_modal(stdscr, theme, "ERROR", "Password too short (min 4 chars). Press Enter.")
                    continue
                
                # Confirm password
                pwd2 = tui_modal._run_modal(stdscr, theme, "SETUP", "Confirm Master Password:", is_password=True)
                if pwd2 is None: # Cancelled
                    continue

                if pwd == pwd2:
                    try:
                        state.storage.initialize_vault(pwd)
                        state.vault_unlocked = True
                        break
                    except Exception as e:
                        tui_modal._run_modal(stdscr, theme, "ERROR", f"Init failed: {e}. Press Enter.")
                else:
                    tui_modal._run_modal(stdscr, theme, "ERROR", "Passwords do not match. Press Enter.")
        else:
            # Unlock existing vault
            while True:
                stdscr.erase()
                R._render_header(stdscr, theme)
                pwd = tui_modal._run_modal(stdscr, theme, "LOGIN", "Enter Master Password:", is_password=True)
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
        redraw = True

        while True:
            if _maybe_auto_clear_clipboard(state):
                state.message = "Clipboard auto-cleared."
            if _should_auto_lock_now(state):
                reason = _auto_lock_reason_text(state)
                _lock_vault(state)
                tui_security._prompt_unlock_vault(stdscr, theme, state, reason=reason)
                stdscr.clear()
                redraw = True
                continue
            if redraw:
                stdscr.erase()
                header_end = R._render_header(stdscr, theme)
                h, w = stdscr.getmaxyx()
    
                min_w, min_h = 70, 20
                if w < min_w or h < min_h:
                    R._render_resize_hint(stdscr, theme)
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

                def _render_footer(stdscr: curses.window, theme: Theme, message: str) -> None:
                    h, w = stdscr.getmaxyx()

                    msg = message[: max(0, w - 1)]
    
                    # Stacked help lines for better readability
                    help_lines = [
                        "Tab/↑/↓: Move  •  Enter/g: Generate  •  s: Save",
                        "t: Security  •  /: Search  •  i/e: CSV  •  Esc×2: Quit",
                    ]

                    R._addstr_safe(stdscr, h - 3, 0, " " * max(0, w - 1), theme.dim)
                    R._addstr_safe(stdscr, h - 3, 1, msg, theme.accent)

                    for i, line in enumerate(help_lines):
                        R._addstr_safe(stdscr, h - 2 + i, 0, " " * max(0, w - 1), theme.dim)
                        R._addstr_safe(stdscr, h - 2 + i, 1, line[: max(0, w - 2)], theme.dim)

                # Mode box is always visible
                R._render_mode_box(
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
                R._render_settings_box(
                    stdscr,
                    theme,
                    y=body_y + mode_h + gap,
                    x=0,
                    h=settings_h,
                    w=left_w,
                    state=state,
                    focus_id=focus_id,
                )
                R._render_actions_box(
                    stdscr,
                    theme,
                    y=body_y + mode_h + gap + settings_h + gap,
                    x=0,
                    h=actions_h,
                    w=left_w,
                    state=state,
                    focus_id=focus_id,
                )
    
                R._render_output_box(
                    stdscr,
                    theme,
                    y=body_y,
                    x=right_x,
                    h=output_h,
                    w=right_w,
                    state=state,
                )
                R._render_info_box(
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
            redraw = (key != -1)
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
                tui_modal._run_scrollable_modal(stdscr, theme, "HOTKEY LEGEND", help_lines)
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
                    tui_modal._run_modal(stdscr, theme, "ERROR", "Vault is locked or unavailable.")
                    stdscr.clear()
                    continue
                try:
                    service = tui_modal._run_modal(stdscr, theme, "ADD", "Service name:", max_length=120)
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

                    username = tui_modal._run_modal(
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

                    password = tui_modal._run_modal(
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
                    
                    note = tui_modal._run_modal(stdscr, theme, "ADD", "Note (optional, Enter to skip):", max_length=500)
                    note_is_hidden = False
                    if note:
                        hide_note = tui_modal._run_modal(stdscr, theme, "ADD", "Hide note? (y/n) [n]:", max_length=1, initial_value="n")
                        note_is_hidden = bool(hide_note and hide_note.lower() == "y")
                    
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
                    tui_modal._run_modal(stdscr, theme, "ERROR", f"Add failed: {e}")
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
                    tui_modal._run_modal(stdscr, theme, "ERROR", "Vault is locked or unavailable.")
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
                    tui_csv.export_vault_csv(
                        stdscr,
                        state.storage,
                        file_path,
                        selected_export_format,
                        theme,
                        state,
                    )

                stdscr.clear()
                continue

            # CSV Import
            if import_csv:
                if not state.vault_unlocked or not state.storage:
                    tui_modal._run_modal(stdscr, theme, "ERROR", "Vault is locked or unavailable.")
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
                    tui_csv.import_vault_csv(
                        stdscr,
                        state.storage,
                        file_path,
                        selected_import_format,
                        theme,
                        state,
                    )

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


# Imported last to avoid a circular import: tui_render aliases a few
# state-label helpers (e.g. _selected_category_count) that are defined
# above in this module.
from . import tui_render as R
from .tui_render import Theme
