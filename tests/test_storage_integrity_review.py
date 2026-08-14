from __future__ import annotations

import sqlite3

import pytest

from generate_it.exceptions import StorageError
from generate_it.storage import StorageManager


def test_v1_unlock_clears_state_when_identity_setup_fails(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "vault.db"
    initial = StorageManager(db_path=db_path)
    initial.initialize_vault("A-Strong-Passw0rd!")
    initial.close()

    reopened = StorageManager(db_path=db_path)
    monkeypatch.setattr(
        reopened,
        "_ensure_identity_schema",
        lambda: (_ for _ in ()).throw(StorageError("identity setup failed")),
    )
    with pytest.raises(StorageError, match="identity setup failed"):
        reopened.unlock_vault("A-Strong-Passw0rd!")
    assert reopened._vault_version is None
    assert reopened._fernet is None
    assert reopened._db_connection is None
    reopened.close()


def test_v2_malformed_config_has_storage_error_contract(tmp_path) -> None:
    db_path = tmp_path / "vault.db"
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault_v2("A-Strong-Passw0rd!")
    storage.close()

    connection = sqlite3.connect(db_path)
    connection.execute("UPDATE config SET value=NULL WHERE key='kdf_salt'")
    connection.commit()
    connection.close()

    reopened = StorageManager(db_path=db_path)
    with pytest.raises(StorageError, match="configuration|KDF|metadata"):
        reopened.unlock_vault("A-Strong-Passw0rd!")
    reopened.close()


def test_retry_identity_index_recomputes_stale_keys(tmp_path) -> None:
    db_path = tmp_path / "vault.db"
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault("A-Strong-Passw0rd!")
    credential_id = storage.save_credential("Service", "User", "password")
    connection = storage._get_conn()
    connection.execute("UPDATE credentials SET service_key='stale', username_key='stale' WHERE id=?", (credential_id,))
    connection.execute("DROP INDEX idx_credentials_identity")
    connection.commit()

    storage._ensure_identity_schema()

    assert storage.find_credential_by_identity("service", "user") is not None
    storage.close()
