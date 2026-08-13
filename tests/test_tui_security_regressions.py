from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from pyperclip import PyperclipException

from generate_it import tui
from generate_it import tui_csv
from generate_it import tui_security
from generate_it.tui_state import AppState


def test_aad_migration_requires_explicit_yes(monkeypatch) -> None:
    storage = MagicMock(_vault_version=2, _aad_version=2)
    state = SimpleNamespace(storage=storage, message="")

    for response in (None, "", "n", "x"):
        monkeypatch.setattr(tui_security.tui_modal, "_run_modal", lambda *args, response=response, **kwargs: response)
        tui_security._maybe_prompt_aad_migration(None, None, state)

    storage.migrate_aad_to_v3.assert_not_called()


def test_aad_migration_runs_only_for_yes(monkeypatch) -> None:
    storage = MagicMock(_vault_version=2, _aad_version=2)
    state = SimpleNamespace(storage=storage, message="")
    monkeypatch.setattr(tui_security.tui_modal, "_run_modal", lambda *args, **kwargs: "YES")

    tui_security._maybe_prompt_aad_migration(None, None, state)

    storage.migrate_aad_to_v3.assert_called_once()


def test_auto_clear_preserves_retry_state_when_clipboard_clear_fails(monkeypatch) -> None:
    state = AppState(clipboard_clear_due_at=10.0, clipboard_clear_expected="secret")
    monkeypatch.setattr(tui.pyperclip, "paste", lambda: "secret")
    monkeypatch.setattr(tui.pyperclip, "copy", MagicMock(side_effect=PyperclipException("backend")))

    assert tui._maybe_auto_clear_clipboard(state, now=10.1) is False
    assert state.clipboard_clear_due_at == 10.0
    assert state.clipboard_clear_expected == "secret"


def test_auto_clear_reports_success_only_after_clear(monkeypatch) -> None:
    state = AppState(clipboard_clear_due_at=10.0, clipboard_clear_expected="secret")
    clipboard = {"value": "secret"}
    monkeypatch.setattr(tui.pyperclip, "paste", lambda: clipboard["value"])
    monkeypatch.setattr(tui.pyperclip, "copy", lambda value: clipboard.update(value=value))

    assert tui._maybe_auto_clear_clipboard(state, now=10.1) is True
    assert state.clipboard_clear_due_at is None
    assert state.clipboard_clear_expected is None
    assert clipboard["value"] == ""


def test_missing_import_path_sets_failure_status(monkeypatch, tmp_path) -> None:
    state = AppState(message="previous success")
    modal = MagicMock()
    monkeypatch.setattr(tui_csv.tui_modal, "_run_modal", modal)

    result = tui_csv.import_vault_csv(None, MagicMock(), str(tmp_path / "missing.csv"), "generic", None, state)

    assert result == (0, 0, [])
    assert state.message == "Import failed. File not found."
    modal.assert_called_once()


def test_startup_unlock_delegates_to_guarded_helper(monkeypatch) -> None:
    source = __import__("inspect").getsource(tui.run)
    assert "state.storage.unlock_vault(pwd)" not in source
    assert "tui_security._try_unlock_vault" in source
