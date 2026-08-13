from __future__ import annotations

import pytest

from generate_it.exceptions import StorageError
from generate_it.storage import StorageManager, WeakMasterPasswordError


def test_explicit_empty_rekey_password_is_rejected(tmp_path) -> None:
    storage = StorageManager(db_path=tmp_path / "vault.db")
    storage.initialize_vault("A-Strong-Passw0rd!")

    with pytest.raises(WeakMasterPasswordError):
        storage.migrate_v1_to_v2(
            "A-Strong-Passw0rd!", new_master_password=""
        )

    assert storage._vault_version == 1
    storage.close()


def test_backup_replace_failure_removes_temporary_backup(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "vault.db"
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault("A-Strong-Passw0rd!")
    backup_path = db_path.with_suffix(".db.v1.bak")
    backup_path.mkdir()

    original_replace = __import__("os").replace

    def fail_backup_replace(source: str, destination: str) -> None:
        if destination == str(backup_path):
            raise IsADirectoryError(destination)
        original_replace(source, destination)

    monkeypatch.setattr("generate_it.storage.core.os.replace", fail_backup_replace)

    with pytest.raises(IsADirectoryError):
        storage.migrate_v1_to_v2("A-Strong-Passw0rd!")

    assert list(tmp_path.glob(".*.v1.bak")) == []
    storage.close()
