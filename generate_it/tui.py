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
- p: change master password
- k: rotate DEK (v2)
- m: vault health / prune backups
- ?: hotkey legend
- b: jump focus to mode
"""

from __future__ import annotations

import curses
import locale
import time
from pathlib import Path
import textwrap
import pyperclip
from pyperclip import PyperclipException

from . import generator
from . import tui_files
from . import tui_modal
from . import tui_security
from . import csv_formats
from . import tui_csv
from .storage import StorageManager, InvalidPasswordError, StorageError
from .tui_state import AppState
from .tui_helpers import (
    _truncate_middle,
    _fuzzy_score,
    _filter_vault_credentials,
    _find_duplicate_credential,
)

APP_NAME = "Generate It"
# Single source of truth — see generate_it/constants.py
from .constants import (  # noqa: E402
    AUTO_LOCK_OPTIONS,
    AUTO_LOCK_SCREEN_OFF,
    CLIPBOARD_AUTO_CLEAR_OPTIONS,
    ESC_QUIT_WINDOW_SECONDS,
    SCREEN_OFF_LOCK_GAP_SECONDS,
    SETTING_KEY_AUTO_LOCK_INDEX,
    SETTING_KEY_CLIPBOARD_AUTO_CLEAR_INDEX,
    TUI_CLOCK_REFRESH_S,
    TUI_FRAME_INTERVAL_MS,
    TUI_FRAME_INTERVAL_S,
    TUI_INPUT_TIMEOUT_MS,
    TUI_MIN_HEIGHT,
    TUI_MIN_TERM_HEIGHT,
    TUI_MIN_TERM_WIDTH,
    TUI_MIN_WIDTH,
    TUI_MODAL_TIMEOUT_MS,
)

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
    url: str = "",
) -> str:
    """Save credential; prompt to overwrite if a duplicate exists."""
    if not state.storage:
        raise RuntimeError("Vault is unavailable.")

    existing = state.storage.find_credential_by_identity(service, username)
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
        # Preserve existing url if new url empty.
        existing_url = existing.get("url", "") or ""
        url_to_store = url if url else existing_url
        state.storage.update_credential(existing["id"], service, username, password, note, note_is_hidden, url_to_store)
        state.vault_credentials = state.storage.list_credential_metadata()
        return "overwritten"

    state.storage.save_credential(service, username, password, note, note_is_hidden, url)
    state.vault_credentials = state.storage.list_credential_metadata()
    return "saved"


def _vault_header(inner_w: int) -> str:
    """Return column header; include URL column when width permits."""
    if inner_w >= 70:
        return f"{'Service':<18} {'Username':<18} {'URL':<20}"
    return f"{'Service':<20} {'Username':<20}"


def _vault_row(cred: dict, inner_w: int) -> str:
    """Format a vault row; include URL when width permits (flat helper)."""
    svc = str(cred.get("service", ""))
    usr = str(cred.get("username", ""))
    url = str(cred.get("url", "") or "")
    if inner_w >= 70 and url:
        # 18 + 1 + 18 + 1 + remainder for URL
        url_w = max(12, inner_w - 38)
        svc_col = svc[:18].ljust(18)
        usr_col = usr[:18].ljust(18)
        url_col = _truncate_middle(url, url_w)
        return f"{svc_col} {usr_col} {url_col}"
    return f"{svc:<20} {usr:<20}"


def _get_filtered_vault_credentials(state: AppState, query: str) -> list[dict]:
    """Flat helper: DB-side search for large vaults (2B/60fps), else in-memory fuzzy, reusable."""
    from .constants import _VAULT_FILTER_MAX_RESULTS, _VAULT_PAGE_SIZE

    # Use DB for large vaults to avoid materializing 2B list scan at 60 fps
    if state.storage and state.vault_unlocked:
        try:
            total = len(state.vault_credentials)
        except Exception:
            total = 0
        if total > _VAULT_PAGE_SIZE and query.strip():
            try:
                return state.storage.search_credential_metadata(
                    query, limit=_VAULT_FILTER_MAX_RESULTS
                )
            except StorageError:
                pass
    # Fallback: in-memory fuzzy with streaming cap
    from .constants import _VAULT_FILTER_MAX_RESULTS as _LIMIT

    try:
        return _filter_vault_credentials(state.vault_credentials, query, limit=_LIMIT)
    except TypeError:
        return _filter_vault_credentials(state.vault_credentials, query)


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
    window_cache = tui_modal._WindowCache()
    cached_query: str | None = None
    matches: list[tuple[int, str, Path]] = []

    def _score_files_flat(q: str, file_list: list[Path]) -> list[tuple[int, str, Path]]:
        """Flat helper: score files for streaming, reusable, no hard-coded limit."""
        from .constants import _VAULT_FUZZY_MAX_CANDIDATES as _LIMIT

        scored: list[tuple[int, str, Path]] = []
        for p in file_list:
            rel = str(p.relative_to(root_dir))
            score = _fuzzy_score(q, rel)
            if score is None:
                continue
            scored.append((score, rel, p))
        scored.sort(key=lambda item: (item[0], len(item[1]), item[1]))
        return scored[:_LIMIT]

    while True:
        h, w = stdscr.getmaxyx()
        box_h = min(max(14, int(h * 0.8)), max(12, h - 2))
        box_w = min(max(70, int(w * 0.9)), max(44, w - 2))
        y, x = (h - box_h) // 2, (w - box_w) // 2

        win = window_cache.get(box_h, box_w, y, x)
        win.timeout(TUI_MODAL_TIMEOUT_MS)
        win.erase()
        win.box()

        inner_w = max(10, box_w - 4)
        root_display = _truncate_middle(str(root_dir), max(8, inner_w - 7))
        try:
            win.addstr(0, 2, " FUZZY FILE PICKER ", theme.title)
            win.addstr(1, 2, R._sanitize_terminal_text(f"Root: {root_display}"[:inner_w]), theme.dim)
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

        if cached_query != query:
            matches = _score_files_flat(query, files)
            cached_query = query

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
                    win.addstr(content_y + i, 2, R._sanitize_terminal_text(line[:inner_w]), attr)
                except curses.error:
                    pass

        footer = "Type to search • ↑/↓ select • Enter choose • Backspace edit • Esc cancel"
        try:
            win.addstr(box_h - 2, 2, footer[:inner_w], theme.dim)
        except curses.error:
            pass

        win.refresh()
        key = win.getch()
        if key == -1:
            continue

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
    window_cache = tui_modal._WindowCache()

    while True:
        h, w = stdscr.getmaxyx()
        box_h = min(max(14, int(h * 0.8)), max(12, h - 2))
        box_w = min(max(70, int(w * 0.9)), max(44, w - 2))
        y, x = (h - box_h) // 2, (w - box_w) // 2

        win = window_cache.get(box_h, box_w, y, x)
        win.timeout(TUI_MODAL_TIMEOUT_MS)
        win.erase()
        win.box()

        inner_w = max(10, box_w - 4)
        try:
            win.addstr(0, 2, " FILE BROWSER ", theme.title)
            win.addstr(1, 2, R._sanitize_terminal_text(_truncate_middle(str(current_dir), inner_w)), theme.dim)
        except curses.error:
            pass

        query_line = f"Filter: {filter_query or '(none)'}"
        try:
            win.addstr(2, 2, _truncate_middle(query_line, inner_w), theme.dim)
        except curses.error:
            pass

        try:
            raw_entries = list(current_dir.iterdir())
        except OSError:
            raw_entries = []

        dirs: list[Path] = []
        files: list[Path] = []
        for entry in raw_entries:
            try:
                if entry.is_dir():
                    dirs.append(entry)
                else:
                    files.append(entry)
            except OSError:
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
                    win.addstr(content_y + i, 2, R._sanitize_terminal_text(_truncate_middle(label, inner_w)), attr)
                except curses.error:
                    pass

        footer = "Enter open/select • s choose dir • Backspace up • / filter • Ctrl+F fuzzy • Esc cancel"
        try:
            win.addstr(box_h - 2, 2, footer[:inner_w], theme.dim)
        except curses.error:
            pass

        win.refresh()
        key = win.getch()
        if key == -1:
            continue

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
    window_cache = tui_modal._WindowCache()

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
        win = window_cache.get(box_h, box_w, y, x)
        win.timeout(TUI_MODAL_TIMEOUT_MS)
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
        if key == -1:
            continue

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
        prompt = "Format (generic/spreadsheet-safe/bitwarden/apple/nordpass):"
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
    window_cache = tui_modal._WindowCache()

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

        win = window_cache.get(box_h, box_w, y, x)
        win.timeout(TUI_MODAL_TIMEOUT_MS)
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
    """Flat helper: batch persist security settings, reusable."""
    if not state.storage:
        return
    try:
        state.storage.set_app_settings(
            {
                SETTING_KEY_CLIPBOARD_AUTO_CLEAR_INDEX: str(state.clipboard_auto_clear_index),
                SETTING_KEY_AUTO_LOCK_INDEX: str(state.auto_lock_index),
            }
        )
    except StorageError:
        pass


def _load_security_settings(state: AppState) -> None:
    """Flat helper: batch load security settings, reusable."""
    if not state.storage:
        return
    try:
        raw = state.storage.get_app_settings(
            [SETTING_KEY_CLIPBOARD_AUTO_CLEAR_INDEX, SETTING_KEY_AUTO_LOCK_INDEX],
            {
                SETTING_KEY_CLIPBOARD_AUTO_CLEAR_INDEX: str(state.clipboard_auto_clear_index),
                SETTING_KEY_AUTO_LOCK_INDEX: str(state.auto_lock_index),
            },
        )
        clip_raw = raw.get(SETTING_KEY_CLIPBOARD_AUTO_CLEAR_INDEX)
        lock_raw = raw.get(SETTING_KEY_AUTO_LOCK_INDEX)
        state.clipboard_auto_clear_index = _coerce_index(
            clip_raw,
            len(CLIPBOARD_AUTO_CLEAR_OPTIONS),
            default=2,
        )
        state.auto_lock_index = _coerce_index(
            lock_raw,
            len(AUTO_LOCK_OPTIONS),
            default=2,
        )
    except StorageError:
        state.clipboard_auto_clear_index = 2
        state.auto_lock_index = 2

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

def _should_render_frame(now: float, last_render_at: float) -> bool:
    """Flat helper: check if a 60 fps frame is due, reusable."""
    return (now - last_render_at) >= TUI_FRAME_INTERVAL_S


def _should_refresh_clock(now: float, last_clock_at: float) -> bool:
    """Flat helper: clock needs 1 Hz update, reusable."""
    return (now - last_clock_at) >= TUI_CLOCK_REFRESH_S


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
    except PyperclipException:
        return False
    return True

def _revoke_clipboard(state: AppState) -> None:
    """Clear clipboard if it still contains the application's secret.

    If the clipboard has been changed by the user since we copied to it,
    we do NOT clear it — we respect newer clipboard content.
    """
    expected = state.clipboard_clear_expected
    state.clipboard_clear_due_at = None
    state.clipboard_clear_expected = None

    if expected is None:
        return

    try:
        current_clip = pyperclip.paste()
        if current_clip == expected:
            pyperclip.copy("")
    except PyperclipException:
        pass


def _lock_vault(state: AppState) -> None:
    _revoke_clipboard(state)
    if state.storage:
        state.storage.close()
    state.vault_unlocked = False
    state.output = ""
    state.vault_credentials = []
    state.vault_selected_idx = 0
    state.vault_scroll_y = 0
    state.revealed_secret = None
    state.revealed_secret_id = None
    # Clear caches that may retain sensitive material (passwords, service
    # names) or user file-system traces after lock — defense in depth for
    # memory retention.  Wordlist and file-picker caches are not secret
    # per se, but their contents (which wordlists/files the user browsed)
    # are sensitive on a shared machine and are evicted on lock.
    try:
        from . import tui_render as _R
        _R._OUTPUT_WRAP_CACHE.clear()
        _R._ENTROPY_CACHE.clear()
    except Exception:
        pass
    try:
        from .identity import clear_identity_cache
        clear_identity_cache()
    except Exception:
        pass
    try:
        from . import generator as _gen
        _gen.clear_wordlist_cache()
    except Exception:
        pass
    try:
        from . import tui_files as _tf
        _tf.clear_file_picker_cache()
    except Exception:
        pass


def _render_footer(stdscr: curses.window, theme: Theme, message: str) -> None:
    """Flat helper: render footer bar, reusable, no hard-coded inline widths."""
    h, w = stdscr.getmaxyx()
    msg = message[: max(0, w - 1)]
    combined = "Tab/↑/↓: Move • Enter/g: Generate • s: Save • t: Security • p: Pass • k: DEK • m: Health • /:Search • i/e:CSV • v:Vault • a:Add • Esc×2:Quit"
    R._addstr_safe(stdscr, h - 2, 0, " " * max(0, w - 1), theme.dim)
    R._addstr_safe(stdscr, h - 2, 1, msg, theme.accent)
    R._addstr_safe(stdscr, h - 1, 0, " " * max(0, w - 1), theme.dim)
    R._addstr_safe(stdscr, h - 1, 1, combined[: max(0, w - 2)], theme.dim)


def _render_dashboard(
    stdscr: curses.window,
    theme: Theme,
    state: AppState,
    words: list[str],
    header_end: int,
) -> None:
    """Flat helper: render all dashboard boxes, reusable for 60 fps streaming."""
    h, w = stdscr.getmaxyx()
    footer_h = 2
    body_y = header_end
    body_h = max(1, h - body_y - footer_h)
    gap = 1
    left_w = max(34, min((w - gap) // 2, w - gap - 30))
    right_x = left_w + gap
    right_w = max(1, w - right_x)
    mode_h = 6
    actions_h = 7
    settings_h = max(6, body_h - mode_h - actions_h - 2 * gap)
    info_h = 8
    output_h = max(6, body_h - info_h - gap)
    info_h = max(6, body_h - output_h - gap)
    focus_items = _get_cached_focus_items(state)
    state.focus_index = max(0, min(state.focus_index, len(focus_items) - 1))
    focus_id = focus_items[state.focus_index]
    R._render_mode_box(stdscr, theme, y=body_y, x=0, h=mode_h, w=left_w, state=state, focus_id=focus_id)
    R._render_settings_box(stdscr, theme, y=body_y + mode_h + gap, x=0, h=settings_h, w=left_w, state=state, focus_id=focus_id)
    R._render_actions_box(stdscr, theme, y=body_y + mode_h + gap + settings_h + gap, x=0, h=actions_h, w=left_w, state=state, focus_id=focus_id)
    R._render_output_box(stdscr, theme, y=body_y, x=right_x, h=output_h, w=right_w, state=state)
    R._render_info_box(stdscr, theme, y=body_y + output_h + gap, x=right_x, h=info_h, w=right_w, state=state, wordlist_size=len(words))
    _render_footer(stdscr, theme, state.message)

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


def _get_cached_focus_items(state: AppState) -> list[str]:
    key = (
        state.mode,
        state.username_style,
        state.vault_unlocked,
        bool(state.output),
    )
    if state.focus_items_cache_key != key:
        state.focus_items_cache_key = key
        state.focus_items_cache = tuple(_focus_items(state))
    return list(state.focus_items_cache)


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
                is_password=True,
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

            url = tui_modal._run_modal(stdscr, theme, "SAVE", "URL (optional, Enter to skip):", max_length=500)
            url = (url or "").strip()
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
                url=url or "",
            )
            if result == "saved":
                state.message = f"Saved credential for {service}."
            elif result == "overwritten":
                state.message = f"Overwrote credential for {service}."
            else:
                state.message = "Save cancelled."
        else:
            state.message = "Save cancelled."

    except StorageError as e:
        state.message = f"Error saving: {e}"

def _run_details_modal(
    stdscr: curses.window,
    theme: Theme,
    state: AppState,
    credential: dict,
) -> None:
    """Runs a modal to show credential details and allow copying."""
    h, w = stdscr.getmaxyx()
    box_h, box_w = 16, 60
    y, x = (h - box_h) // 2, (w - box_w) // 2
    
    win = curses.newwin(box_h, box_w, y, x)
    win.keypad(True)
    win.timeout(TUI_MODAL_TIMEOUT_MS)
    feedback_text = ""
    feedback_attr = theme.dim
    feedback_until = 0.0
    password_revealed = False

    try:
        # Load secret on demand
        if state.storage and state.revealed_secret_id != credential['id']:
            state.revealed_secret = state.storage.get_credential_secret(credential['id'])
            state.revealed_secret_id = credential['id']
        
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
            win.addstr(row, 12, R._sanitize_terminal_text(credential['service'][:box_w-14]), val_attr)
            row += 2

            win.addstr(row, 2, "Username:", label_attr)
            win.addstr(row, 12, R._sanitize_terminal_text(credential['username'][:box_w-14]), val_attr)
            row += 2

            # URL if present
            url_text = state.revealed_secret.get('url', '') if state.revealed_secret else credential.get('url', '')
            if url_text:
                win.addstr(row, 2, "URL:", label_attr)
                win.addstr(row, 12, R._sanitize_terminal_text(url_text[:box_w-14]), val_attr)
                row += 2
            
            # Note
            note_text = state.revealed_secret.get('note', '') if state.revealed_secret else ''
            note_is_hidden = state.revealed_secret.get('note_is_hidden', False) if state.revealed_secret else False
            display_note = "*" * len(note_text) if note_is_hidden and note_text else note_text
            if display_note:
                win.addstr(row, 2, "Note:", label_attr)
                row += 1
                # Wrap note to fit
                import textwrap
                wrapped_note = textwrap.wrap(display_note, width=box_w-14)
                max_rows = max(0, box_h - row - 6)
                visible_note = wrapped_note[:max_rows]
                if len(visible_note) < len(wrapped_note):
                    marker = " [truncated]"
                    if visible_note:
                        visible_note[-1] = visible_note[-1][: max(0, box_w - 14 - len(marker))] + marker
                    else:
                        visible_note = [marker]
                for line in visible_note:
                    win.addstr(row, 2, R._sanitize_terminal_text(line[:box_w-14]), val_attr)
                    row += 1

            win.addstr(row, 2, "Password:", label_attr)
            if state.revealed_secret:
                if password_revealed:
                    win.addstr(row, 12, R._sanitize_terminal_text(state.revealed_secret['password'][:box_w-14]), val_attr)
                else:
                    masked = "*" * min(len(state.revealed_secret['password']), 20)
                    win.addstr(row, 12, masked[:box_w-14], val_attr)
            row += 2
            
            win.addstr(row, 2, "Created:", label_attr)
            win.addstr(row, 12, R._sanitize_terminal_text(str(credential['created_at'])[:box_w-14]))
            
            # Footer - stacked on two lines for better readability
            line1 = "c: Copy Pass  u: Copy User"
            if url_text:
                line1 += "  o: Copy URL"
            if note_text:
                line1 += "  n: Copy Note"
            line1 += "  r: Hide" if password_revealed else "  r: Reveal"
            
            line2_parts = []
            if note_text:
                line2_parts.append("h: Show/Hide Note")
            line2_parts.append("Esc: Close")
            line2 = "  ".join(line2_parts)
            
            footer_text = line2
            footer_attr = theme.dim
            if feedback_text and time.monotonic() < feedback_until:
                footer_text = feedback_text
                footer_attr = feedback_attr
            win.addstr(box_h - 3, 2, R._sanitize_terminal_text(line1[:box_w-4]), theme.dim)
            win.addstr(box_h - 2, 2, R._sanitize_terminal_text(footer_text[:box_w-4]), footer_attr)
            
            win.refresh()
            
            key = win.getch()
            if key == -1:
                continue
            _record_user_activity(state)
            
            if key in (27, ord('q'), ord('Q')): # Esc/q
                return
                
            elif key in (ord('r'), ord('R')):
                password_revealed = not password_revealed
                
            elif key in (ord('c'), ord('C')):
                try:
                    if state.revealed_secret:
                        msg = tui_flow._copy_to_clipboard_with_policy(state, state.revealed_secret['password'])
                        feedback_text = "       COPIED PASSWORD!       "
                        feedback_attr = theme.ok
                        feedback_until = time.monotonic() + 0.5
                        state.message = msg
                except (StorageError, PyperclipException):
                    feedback_text = "    CLIPBOARD COPY FAILED    "
                    feedback_attr = theme.warn
                    feedback_until = time.monotonic() + 1.5

            elif key in (ord('u'), ord('U')):
                try:
                    msg = tui_flow._copy_to_clipboard_with_policy(state, credential['username'])
                    feedback_text = "       COPIED USERNAME!       "
                    feedback_attr = theme.ok
                    feedback_until = time.monotonic() + 0.5
                    state.message = msg
                except (StorageError, PyperclipException):
                    feedback_text = "    CLIPBOARD COPY FAILED    "
                    feedback_attr = theme.warn
                    feedback_until = time.monotonic() + 1.5

            elif key in (ord('n'), ord('N')):
                if note_text:
                    try:
                        msg = tui_flow._copy_to_clipboard_with_policy(state, note_text)
                        feedback_text = "        COPIED NOTE!        "
                        feedback_attr = theme.ok
                        feedback_until = time.monotonic() + 0.5
                        state.message = msg
                    except (StorageError, PyperclipException):
                        feedback_text = "    CLIPBOARD COPY FAILED    "
                        feedback_attr = theme.warn
                        feedback_until = time.monotonic() + 1.5
                else:
                    feedback_text = "       NO NOTE TO COPY!      "
                    feedback_attr = theme.warn
                    feedback_until = time.monotonic() + 0.5

            elif key in (ord('o'), ord('O')):
                url_to_copy = url_text
                if url_to_copy:
                    try:
                        msg = tui_flow._copy_to_clipboard_with_policy(state, url_to_copy)
                        feedback_text = "        COPIED URL!        "
                        feedback_attr = theme.ok
                        feedback_until = time.monotonic() + 0.5
                        state.message = msg
                    except (StorageError, PyperclipException):
                        feedback_text = "    CLIPBOARD COPY FAILED    "
                        feedback_attr = theme.warn
                        feedback_until = time.monotonic() + 1.5
                else:
                    feedback_text = "       NO URL TO COPY!      "
                    feedback_attr = theme.warn
                    feedback_until = time.monotonic() + 0.5

            elif key in (ord('h'), ord('H')):
                if note_text:
                    try:
                        cred_id = credential['id']
                        current_hidden = note_is_hidden
                        if state.storage and state.revealed_secret:
                            # Preserve url on hide toggle
                            url_to_preserve = url_text if 'url_text' in locals() else (state.revealed_secret.get('url', '') or credential.get('url',''))
                            state.storage.update_credential(
                                cred_id,
                                credential['service'],
                                credential['username'],
                                state.revealed_secret['password'],
                                state.revealed_secret['note'],
                                not current_hidden,
                                url_to_preserve,
                            )
                            state.vault_credentials = state.storage.list_credential_metadata()
                            state.revealed_secret['note_is_hidden'] = not current_hidden
                        credential = next((c for c in state.vault_credentials if c['id'] == cred_id), credential)
                        break
                    except StorageError as e:
                        feedback_text = f"     ERROR: {R._sanitize_terminal_text(str(e))[:20]}    "
                        feedback_attr = theme.warn
                        feedback_until = time.monotonic() + 1.0
                else:
                    feedback_text = "       NO NOTE TO HIDE!     "
                    feedback_attr = theme.warn
                    feedback_until = time.monotonic() + 0.5
    finally:
        state.revealed_secret = None
        state.revealed_secret_id = None

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
    state.vault_credentials = state.storage.list_credential_metadata()
    vault_filter = ""
    search_mode = start_in_search
    window_cache = tui_modal._WindowCache()
    cached_filter_key: tuple[int, str] | None = None
    filtered_credentials: list[dict] = []
    
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
        win = window_cache.get(box_h, box_w, y, x)
        win.timeout(TUI_MODAL_TIMEOUT_MS)
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

        filter_key = (id(state.vault_credentials), vault_filter)
        if cached_filter_key != filter_key:
            # Flat helper: choose DB vs in-memory path for 2B/60fps, reusable.
            filtered_credentials = _get_filtered_vault_credentials(
                state, vault_filter
            )
            cached_filter_key = filter_key

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
        headers = _vault_header(inner_w)
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
                line = _vault_row(cred, inner_w)
                try:
                    win.addstr(list_y + (i - start), 2, R._sanitize_terminal_text(line[:inner_w]), attr)
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
                "Enter: details  e: edit  c: copy pass  u: copy user  o: copy url",
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
                continue
        if key in (curses.KEY_UP, ord('k')):
            if filtered_credentials:
                state.vault_selected_idx = max(0, state.vault_selected_idx - 1)
        elif key in (curses.KEY_DOWN, ord('j')):
            if filtered_credentials:
                state.vault_selected_idx = min(len(filtered_credentials) - 1, state.vault_selected_idx + 1)
        
        elif key in (ord('e'), ord('E')):
            if filtered_credentials:
                cred = filtered_credentials[state.vault_selected_idx]
                try:
                    secret = state.storage.get_credential_secret(cred["id"])
                except StorageError as e:
                    tui_modal._run_modal(stdscr, theme, "ERROR", f"Cannot load credential: {e}")
                    continue
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
                    initial_value=secret.get("password", ""),
                )
                if password is None:
                    continue

                service = service.strip()
                username = username.strip()
                if not service or not username or not password:
                    tui_modal._run_modal(stdscr, theme, "ERROR", "Service, username, and password are required.")
                    continue

                try:
                    existing_url = secret.get("url", "") or cred.get("url", "")
                    url = tui_modal._run_modal(stdscr, theme, "EDIT", "URL (optional):", max_length=500, initial_value=existing_url)
                    if url is None:
                        continue
                    url = url.strip()
                    # Get existing note for the credential
                    existing_note = secret.get("note", "")
                    existing_hidden = secret.get("note_is_hidden", False)
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
                    
                    state.storage.update_credential(cred["id"], service, username, password, note, note_is_hidden, url)
                    state.vault_credentials = state.storage.list_credential_metadata()

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
                except StorageError as e:
                    tui_modal._run_modal(stdscr, theme, "ERROR", f"Update failed: {e}")
        
        elif key in (ord('c'), ord('C')):
            if filtered_credentials:
                cred = filtered_credentials[state.vault_selected_idx]
                try:
                    if state.storage:
                        secret = state.storage.get_credential_secret(cred['id'])
                        msg = tui_flow._copy_to_clipboard_with_policy(state, secret['password'])
                        tui_modal._run_modal(stdscr, theme, "SUCCESS", msg)
                except (StorageError, PyperclipException) as e:
                    tui_modal._run_modal(stdscr, theme, "ERROR", f"Copy failed: {e}")

        elif key in (ord('u'), ord('U')):
            if filtered_credentials:
                cred = filtered_credentials[state.vault_selected_idx]
                try:
                    msg = tui_flow._copy_to_clipboard_with_policy(state, cred['username'])
                    tui_modal._run_modal(stdscr, theme, "SUCCESS", msg)
                except (StorageError, PyperclipException) as e:
                    tui_modal._run_modal(stdscr, theme, "ERROR", f"Copy failed: {e}")

        elif key in (ord('o'), ord('O')):
            if filtered_credentials:
                cred = filtered_credentials[state.vault_selected_idx]
                url_val = cred.get("url") or ""
                if not url_val and state.storage:
                    try:
                        secret = state.storage.get_credential_secret(cred["id"])
                        url_val = secret.get("url", "") or ""
                    except StorageError:
                        url_val = ""
                if url_val:
                    try:
                        msg = tui_flow._copy_to_clipboard_with_policy(state, url_val)
                        tui_modal._run_modal(stdscr, theme, "SUCCESS", msg)
                    except (StorageError, PyperclipException) as e:
                        tui_modal._run_modal(stdscr, theme, "ERROR", f"Copy failed: {e}")
                else:
                    tui_modal._run_modal(stdscr, theme, "ERROR", "No URL to copy.")

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
                        state.vault_credentials = state.storage.list_credential_metadata()
                        refreshed_filtered = _filter_vault_credentials(state.vault_credentials, vault_filter)
                        if state.vault_selected_idx >= len(refreshed_filtered):
                            state.vault_selected_idx = max(0, len(refreshed_filtered) - 1)
                    except StorageError as e:
                        tui_modal._run_modal(stdscr, theme, "ERROR", f"Delete failed: {e}")

# --- Main loop --------------------------------------------------------------

def run() -> int:
    """Run the curses TUI."""

    try:
        locale.setlocale(locale.LC_ALL, "")
    except locale.Error:
        pass

    def _main(stdscr: curses.window) -> int:
        theme = R._init_theme()

        try:
            curses.curs_set(0)
        except curses.error:
            pass

        stdscr.keypad(True)
        stdscr.timeout(TUI_INPUT_TIMEOUT_MS)

        h, w = stdscr.getmaxyx()
        if h < TUI_MIN_TERM_HEIGHT or w < TUI_MIN_TERM_WIDTH:
            stdscr.addstr(0, 0, "Terminal too small for Generate-It. Minimum: 40x10.")
            stdscr.refresh()
            curses.napms(2000)
            return 1

        words = generator.load_wordlist()
        state = AppState()
        
        # --- Storage Initialization ---
        try:
            state.storage = StorageManager()
        except (StorageError, OSError) as e:
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
                should_quit, critical_last_esc_at = tui_flow._handle_double_esc_quit(
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
                stdscr.touchwin()
                R._render_header(stdscr, theme)
                pwd = tui_modal._run_modal(stdscr, theme, "SETUP", "Create Master Password:", is_password=True)
                if pwd is None: # Cancelled
                    return 0

                # Confirm password
                pwd2 = tui_modal._run_modal(stdscr, theme, "SETUP", "Confirm Master Password:", is_password=True)
                if pwd2 is None: # Cancelled
                    continue

                if pwd == pwd2:
                    try:
                        state.storage.initialize_vault_v2(pwd)
                        state.vault_unlocked = True
                        break
                    except StorageError as e:
                        tui_modal._run_modal(stdscr, theme, "ERROR", f"Init failed: {e}. Press Enter.")
                    finally:
                        # Minimize lifetime of plaintext passwords in memory.
                        try:
                            # Overwrite local references (CPython strings are immutable;
                            # this at least drops the reference promptly).
                            pwd = "\x00" * len(pwd)  # type: ignore[assignment]
                            pwd2 = "\x00" * len(pwd2)  # type: ignore[assignment]
                        except Exception:
                            pass
                        try:
                            del pwd, pwd2
                        except Exception:
                            pass
                else:
                    tui_modal._run_modal(stdscr, theme, "ERROR", "Passwords do not match. Press Enter.")
                    # Clear promptly on mismatch as well.
                    try:
                        pwd = "\x00" * len(pwd)  # type: ignore[assignment]
                        pwd2 = "\x00" * len(pwd2)  # type: ignore[assignment]
                    except Exception:
                        pass
                    try:
                        del pwd, pwd2
                    except Exception:
                        pass
        else:
            # Sync persisted lockout (survives restarts) into in-memory state
            # before the first unlock attempt.
            try:
                tui_security._sync_persistent_lockout_from_storage(state)
            except Exception:
                pass
            # Unlock existing vault
            while True:
                stdscr.erase()
                R._render_header(stdscr, theme)
                pwd = tui_modal._run_modal(stdscr, theme, "LOGIN", "Enter Master Password:", is_password=True)
                if pwd is None: # Cancelled
                    return 0
                
                setattr(state, tui_security._UNLOCK_RETRY_FLAG, False)
                setattr(state, tui_security._UNLOCK_CANCELLED_FLAG, False)
                try:
                    unlocked = tui_security._try_unlock_vault(stdscr, theme, state, pwd)
                finally:
                    retry = getattr(state, tui_security._UNLOCK_RETRY_FLAG, False)
                    cancelled = getattr(state, tui_security._UNLOCK_CANCELLED_FLAG, False)
                    delattr(state, tui_security._UNLOCK_RETRY_FLAG)
                    delattr(state, tui_security._UNLOCK_CANCELLED_FLAG)
                    # Minimize lifetime — clear plaintext pwd promptly.
                    try:
                        pwd = "\x00" * len(pwd)  # type: ignore[assignment]
                    except Exception:
                        pass
                    try:
                        del pwd
                    except Exception:
                        pass
                if unlocked:
                    break
                if cancelled:
                    return 0
                if retry:
                    continue

        # Load initial credentials
        if state.vault_unlocked and state.storage:
            state.vault_credentials = state.storage.list_credential_metadata()
            _load_security_settings(state)
            _record_user_activity(state)

        # Generate something immediately so the dashboard isn't empty.
        _generate(state, words)
        last_esc_quit_at: float | None = None
        redraw = True
        last_render_at = 0.0
        last_clock_at = time.monotonic()

        while True:
            now = time.monotonic()
            if _maybe_auto_clear_clipboard(state):
                state.message = "Clipboard auto-cleared."
                redraw = True
            if _should_auto_lock_now(state):
                reason = _auto_lock_reason_text(state)
                _lock_vault(state)
                tui_security._prompt_unlock_vault(stdscr, theme, state, reason=reason)
                stdscr.clear()
                redraw = True
                last_render_at = 0.0
                continue
            needs_render = redraw or _should_render_frame(now, last_render_at) or _should_refresh_clock(now, last_clock_at)
            if needs_render:
                stdscr.erase()
                header_end = R._render_header(stdscr, theme)
                h, w = stdscr.getmaxyx()
                if w < TUI_MIN_WIDTH or h < TUI_MIN_HEIGHT:
                    R._render_resize_hint(stdscr, theme)
                    _render_footer(stdscr, theme, state.message)
                    stdscr.refresh()
                    last_render_at = now
                    if _should_refresh_clock(now, last_clock_at):
                        last_clock_at = now
                    # Stream input at 60 fps — poll without blocking
                    key = stdscr.getch()
                    if key == -1:
                        continue
                    redraw = True
                    _record_user_activity(state)
                    if key == 27:
                        should_quit, last_esc_quit_at = tui_flow._handle_double_esc_quit(
                            key=key, last_esc_at=last_esc_quit_at
                        )
                        if should_quit:
                            _revoke_clipboard(state)
                            return 0
                        state.message = "Press Esc again to quit."
                        continue
                    last_esc_quit_at = None
                    if key in (ord("q"), ord("Q")):
                        state.message = "Press Esc twice to quit."
                    continue
                _render_dashboard(stdscr, theme, state, words, header_end)
                stdscr.refresh()
                last_render_at = now
                if _should_refresh_clock(now, last_clock_at):
                    last_clock_at = now
                redraw = False

            key = stdscr.getch()
            if key == -1:
                continue
            redraw = True
            _record_user_activity(state)
            if key == 27:
                should_quit, last_esc_quit_at = tui_flow._handle_double_esc_quit(
                    key=key, last_esc_at=last_esc_quit_at
                )
                if should_quit:
                    _revoke_clipboard(state)
                    return 0
                state.message = "Press Esc again to quit."
                continue
            last_esc_quit_at = None
            if key in (ord("q"), ord("Q")):
                state.message = "Press Esc twice to quit."
                continue
                return 0
            if key == curses.KEY_RESIZE:
                redraw = True
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
            change_password = key in (ord("p"), ord("P"))
            rotate_dek = key in (ord("k"), ord("K"))
            vault_health = key in (ord("m"), ord("M"))
            show_help = key == ord("?")

            if show_help:
                help_lines = [
                    "GLOBAL HOTKEYS",
                    "g       : Generate new credential",
                    "s       : Save generated credential",
                    "t       : Security settings",
                    "p       : Change master password",
                    "k       : Rotate DEK (v2 vaults)",
                    "m       : Vault health & backups",
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

            if change_password:
                tui_security.prompt_change_master_password(stdscr, theme, state)
                stdscr.clear()
                continue

            if rotate_dek:
                tui_security.prompt_rotate_dek(stdscr, theme, state)
                stdscr.clear()
                continue

            if vault_health:
                tui_security.prompt_vault_health(stdscr, theme, state)
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
                    
                    url = tui_modal._run_modal(stdscr, theme, "ADD", "URL (optional, Enter to skip):", max_length=500)
                    url = (url or "").strip()
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
                        url=url or "",
                    )
                    if result == "saved":
                        state.message = f"Added credential for {service}."
                    elif result == "overwritten":
                        state.message = f"Overwrote credential for {service}."
                    else:
                        state.message = "Add cancelled."
                except StorageError as e:
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
                    focus_items = _get_cached_focus_items(state)
                    state.focus_index = max(0, min(state.focus_index, len(focus_items) - 1))
                elif focus_id == "mode_words":
                    state.mode = "words"
                    state.message = "Mode: words"
                    focus_items = _get_cached_focus_items(state)
                    state.focus_index = max(0, min(state.focus_index, len(focus_items) - 1))
                elif focus_id == "mode_username":
                    state.mode = "username"
                    state.message = "Mode: username"
                    focus_items = _get_cached_focus_items(state)
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
                    focus_items = _get_cached_focus_items(state)
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

        _revoke_clipboard(state)
        return 0

    try:
        return curses.wrapper(_main)
    except QuitApp:
        return 0


# Imported last to avoid a circular import: tui_render now redefines a few
# state-label helpers (e.g. _selected_category_count) locally rather
# than importing them from this module.
from . import tui_render as R
from . import tui_flow

# Re-exported so existing callers (including tests) that reference
# tui._handle_double_esc_quit keep working after the verbatim move into
# tui_flow.
_handle_double_esc_quit = tui_flow._handle_double_esc_quit
from .tui_render import Theme
