"""CSV export/import logic for the Generate It TUI.

This module encapsulates the inline CSV export/import blocks that used to live
inside ``tui._main``. The behavior is identical to the original inline code;
these are thin wrappers around ``StorageManager`` plus the relevant ``tui_modal``
prompts.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path
from typing import TYPE_CHECKING, Tuple

from .logging import get_logger

_log = get_logger("tui")

import curses

from . import csv_formats
from . import tui_modal
from .storage import StorageManager, StorageError
from .tui_state import AppState

if TYPE_CHECKING:
    from .tui_render import Theme


def export_vault_csv(
    stdscr: curses.window,
    storage: StorageManager,
    path: str,
    export_format: str,
    theme: "Theme",
    state: AppState,
) -> None:
    """Export the vault to a CSV file at ``path``.

    Mirrors the inline export block that previously lived in ``tui._main``:
    resolves a directory-vs-file path, confirms overwrite, calls
    ``storage.export_to_csv``, surfaces any skipped rows, and updates
    ``state.message``.
    """
    raw_path = Path(path).expanduser()
    csv_path = raw_path
    if raw_path.exists() and raw_path.is_dir():
        default_name = (
            f"generate-it-{export_format}-"
            f"{_dt.datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
        )
        filename = tui_modal._run_modal(
            stdscr,
            theme,
            "EXPORT FILENAME",
            f"Directory selected. Enter file name: [default: {default_name}]",
            max_length=160,
        )
        if filename is None:
            state.message = "Export cancelled."
            return

        filename = filename.strip() or default_name
        if "/" in filename or "\\" in filename:
            tui_modal._run_modal(
                stdscr,
                theme,
                "ERROR",
                "Use a file name only (no directory separators).",
            )
            state.message = "Export cancelled."
            return

        if not filename.lower().endswith(".csv"):
            filename += ".csv"
        csv_path = raw_path / filename

    parent_dir = csv_path.parent
    if not parent_dir.exists() or not parent_dir.is_dir():
        tui_modal._run_modal(stdscr, theme, "ERROR", f"Directory not found: {parent_dir}")
        state.message = "Export cancelled."
        return

    # Check if file exists and confirm overwrite
    if csv_path.exists():
        confirm = tui_modal._run_modal(stdscr, theme, "CONFIRM", f"File exists. Overwrite? (type 'yes'):")
        if not confirm or confirm.lower() != 'yes':
            state.message = "Export cancelled."
            return

    try:
        exported, skipped = storage.export_to_csv(
            csv_path,
            export_format=export_format,
        )

        if skipped:
            skip_lines = [f"The following {len(skipped)} credential(s) failed to export:", ""]
            for item in skipped:
                skip_lines.append(f"- {item['service']} / {item['username']}: {item['error']}")
            tui_modal._run_scrollable_modal(stdscr, theme, "EXPORT WARNING", skip_lines)

        format_label = csv_formats.EXPORT_FORMAT_LABELS.get(
            export_format,
            export_format,
        )
        state.message = f"Exported {exported} credential(s) as {format_label} to {csv_path}."
        if skipped:
            state.message += f" ({len(skipped)} skipped)"
        _log.info("exported %d credentials to %s", exported, csv_path)
    except StorageError as e:
        tui_modal._run_modal(stdscr, theme, "ERROR", f"Export failed: {e}")
        state.message = "Export failed."


def import_vault_csv(
    stdscr: curses.window,
    storage: StorageManager,
    path: str,
    import_format: str,
    theme: "Theme",
    state: AppState,
) -> Tuple[int, int, list]:
    """Import credentials from a CSV file at ``path``.

    Mirrors the inline import block that previously lived in ``tui._main``:
    validates the file, runs a preview pass to detect duplicates and (if any)
    asks whether to merge, performs the import, surfaces results, refreshes the
    vault list, and updates ``state.message``. Returns the result of
    ``storage.import_from_csv`` (imported, skipped, duplicates).
    """
    csv_path = Path(path).expanduser()

    if not csv_path.exists():
        tui_modal._run_modal(stdscr, theme, "ERROR", f"File not found: {csv_path}")
        return (0, 0, [])

    try:
        # Preview pass: detect duplicates without importing
        _, _, preview_issues = storage.import_from_csv(
            csv_path,
            merge_duplicates=False,
            dry_run=True,
            import_format=import_format,
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
            tui_modal._run_scrollable_modal(stdscr, theme, "DUPLICATES FOUND", dup_lines)

            merge_confirm = tui_modal._run_modal(stdscr, theme, "MERGE?", "Type 'yes' to merge/overwrite:")
            if merge_confirm and merge_confirm.lower() == 'yes':
                merge = True

        # Import with merge decision
        imported, skipped_num, duplicates = storage.import_from_csv(
            csv_path,
            merge_duplicates=merge,
            dry_run=False,
            import_format=import_format,
        )

        # Show results
        if duplicates:
            result_lines = ["Import complete:", ""]
            result_lines.append(f"Imported: {imported}")
            result_lines.append(f"Skipped: {skipped_num}")
            if duplicates:
                result_lines.append("")
                result_lines.append("Issues:")
                for item in duplicates:
                    result_lines.append(f"- {item['service']} / {item['username']}: {item['reason']}")
            tui_modal._run_scrollable_modal(stdscr, theme, "IMPORT RESULTS", result_lines)
        else:
            tui_modal._run_modal(stdscr, theme, "SUCCESS", f"Imported {imported} credential(s).")

        format_label = csv_formats.IMPORT_FORMAT_LABELS.get(
            import_format,
            import_format,
        )
        state.message = f"Imported {imported} credential(s) via {format_label}. ({skipped_num} skipped)"
        _log.info("imported %d credentials from %s", imported, csv_path)

        # Refresh vault list
        state.vault_credentials = storage.list_credentials()

        return (imported, skipped_num, duplicates)

    except StorageError as e:
        tui_modal._run_modal(stdscr, theme, "ERROR", f"Import failed: {e}")
        state.message = "Import failed."
        return (0, 0, [])
