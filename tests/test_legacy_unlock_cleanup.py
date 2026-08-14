from __future__ import annotations

import pytest

from generate_it.exceptions import StorageError
from generate_it.storage import StorageManager


@pytest.mark.parametrize("initializer", ["initialize_vault", "initialize_vault_v2"])
def test_unlock_failure_clears_authenticated_state(tmp_path, monkeypatch, initializer: str) -> None:
    db_path = tmp_path / f"{initializer}.db"
    storage = StorageManager(db_path=db_path)
    getattr(storage, initializer)("A-Strong-Passw0rd!")
    storage.close()

    reopened = StorageManager(db_path=db_path)
    monkeypatch.setattr(
        reopened,
        "_ensure_identity_schema",
        lambda: (_ for _ in ()).throw(StorageError("migration failed")),
    )

    try:
        with pytest.raises(StorageError, match="migration failed"):
            reopened.unlock_vault("A-Strong-Passw0rd!")

        assert reopened._vault_version is None
        assert reopened._fernet is None
        assert reopened._dek is None
        assert reopened._vault_uuid is None
        assert reopened._db_connection is None
    finally:
        reopened.close()


def test_failed_v1_unlock_can_be_retried_with_fresh_manager(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "vault.db"
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault("A-Strong-Passw0rd!")
    storage.close()

    failed = StorageManager(db_path=db_path)
    monkeypatch.setattr(
        failed,
        "_ensure_identity_schema",
        lambda: (_ for _ in ()).throw(StorageError("migration failed")),
    )
    with pytest.raises(StorageError):
        failed.unlock_vault("A-Strong-Passw0rd!")
    failed.close()

    retried = StorageManager(db_path=db_path)
    retried.unlock_vault("A-Strong-Passw0rd!")
    assert retried._vault_version == 1
    retried.close()
