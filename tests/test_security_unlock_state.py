from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from generate_it import tui, tui_security
from generate_it.storage import StorageError, StorageManager


def test_post_authentication_initialization_failure_clears_unlock_state(monkeypatch) -> None:
    storage = MagicMock()
    storage.unlock_vault.return_value = None
    storage.list_credential_metadata.side_effect = StorageError("metadata failed")
    state = SimpleNamespace(
        storage=storage,
        vault_unlocked=False,
        vault_credentials=[],
        message="",
        failed_unlock_attempts=0,
        lockout_until=None,
    )
    monkeypatch.setattr(tui_security.tui_modal, "_run_modal", lambda *args, **kwargs: None)

    assert tui_security._try_unlock_vault(None, None, state, "correct") is False
    assert state.vault_unlocked is False
    assert state.vault_credentials == []
    # The storage manager must be closed (locked) on post-auth failure, not
    # just the UI state marked locked.
    storage.close.assert_called_once()


def test_post_auth_failure_closes_real_storage_manager(tmp_path: Path, monkeypatch) -> None:
    """A real (unmocked) storage manager is locked on post-auth init failure.

    After ``unlock_vault`` succeeds the DEK/UUID/version are live; a failing
    ``list_credential_metadata`` must tear that state down so no later path
    can consult storage directly while the UI reports the vault locked.
    """
    db_path = tmp_path / "vault.db"
    master = "A-Strong-Passw0rd!"
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault_v2(master)
    storage.save_credential("GitHub", "octocat", "secret")
    storage.close()

    storage2 = StorageManager(db_path=db_path)
    state = tui.AppState(storage=storage2)
    monkeypatch.setattr(tui_security.tui_modal, "_run_modal", lambda *args, **kwargs: None)
    monkeypatch.setattr(tui_security.tui, "_record_user_activity", lambda state: None)
    monkeypatch.setattr(tui_security, "_maybe_show_identity_conflict", lambda *a: None)
    monkeypatch.setattr(tui_security, "_maybe_prompt_aad_migration", lambda *a: None)
    monkeypatch.setattr(
        storage2, "list_credential_metadata",
        MagicMock(side_effect=StorageError("metadata failed")),
    )

    assert tui_security._try_unlock_vault(None, None, state, master) is False
    assert state.vault_unlocked is False

    # Both the UI and the storage manager are locked.
    assert storage2._dek is None
    assert storage2._vault_uuid is None
    assert storage2._vault_version is None
    assert storage2._fernet is None
    storage2.close()