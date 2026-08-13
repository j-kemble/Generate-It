from __future__ import annotations

import pytest

from generate_it.exceptions import StorageError
from generate_it.storage import StorageManager


def test_v2_unlock_failure_clears_authenticated_state(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "vault.db"
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault_v2("A-Strong-Passw0rd!")
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
    finally:
        reopened.close()
