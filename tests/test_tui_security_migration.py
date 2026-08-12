"""Unit tests for tui_security.py migration prompts and modals."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from generate_it import tui_security
from generate_it.storage import CredentialIdentityConflictError, StorageError


def test_maybe_show_identity_conflict_shows_modal_on_conflict(monkeypatch) -> None:
    conflict_err = CredentialIdentityConflictError(
        "Conflict",
        conflicts=[{"service": "GitHub", "username": "dev", "ids": [1, 2]}],
    )
    storage = SimpleNamespace(identity_conflict=conflict_err)
    state = SimpleNamespace(storage=storage, message="")

    modal_lines = []

    def fake_scrollable(stdscr, theme, title, lines):
        modal_lines.extend(lines)

    monkeypatch.setattr(tui_security.tui_modal, "_run_scrollable_modal", fake_scrollable)

    tui_security._maybe_show_identity_conflict(None, None, state)

    assert "Duplicate credentials need attention (vault explorer)." in state.message
    assert any("- #1, 2: GitHub / dev" in line for line in modal_lines)


def test_maybe_show_identity_conflict_noop_when_no_conflict(monkeypatch) -> None:
    storage = SimpleNamespace(identity_conflict=None)
    state = SimpleNamespace(storage=storage, message="")

    called = False

    def fake_scrollable(*a, **k):
        nonlocal called
        called = True

    monkeypatch.setattr(tui_security.tui_modal, "_run_scrollable_modal", fake_scrollable)

    tui_security._maybe_show_identity_conflict(None, None, state)

    assert called is False
    assert state.message == ""


def test_maybe_prompt_aad_migration_success(monkeypatch) -> None:
    mock_storage = MagicMock()
    mock_storage._vault_version = 2
    mock_storage._aad_version = 2  # < 3
    state = SimpleNamespace(storage=mock_storage, message="")

    # User confirms with "y"
    monkeypatch.setattr(tui_security.tui_modal, "_run_modal", lambda *a, **k: "y")

    tui_security._maybe_prompt_aad_migration(None, None, state)

    mock_storage.migrate_aad_to_v3.assert_called_once()
    assert state.message == "Vault upgraded to AAD v3."


def test_maybe_prompt_aad_migration_deferred(monkeypatch) -> None:
    mock_storage = MagicMock()
    mock_storage._vault_version = 2
    mock_storage._aad_version = 2
    state = SimpleNamespace(storage=mock_storage, message="")

    # User declines with "n"
    monkeypatch.setattr(tui_security.tui_modal, "_run_modal", lambda *a, **k: "n")

    tui_security._maybe_prompt_aad_migration(None, None, state)

    mock_storage.migrate_aad_to_v3.assert_not_called()
    assert state.message == "AAD upgrade deferred."


def test_maybe_prompt_aad_migration_handles_failure(monkeypatch) -> None:
    mock_storage = MagicMock()
    mock_storage._vault_version = 2
    mock_storage._aad_version = 2
    mock_storage.migrate_aad_to_v3.side_effect = StorageError("Disk full")
    state = SimpleNamespace(storage=mock_storage, message="")

    monkeypatch.setattr(tui_security.tui_modal, "_run_modal", lambda *a, **k: "y")

    tui_security._maybe_prompt_aad_migration(None, None, state)

    assert state.message == "AAD upgrade failed."
