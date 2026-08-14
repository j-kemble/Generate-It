from __future__ import annotations

import sqlite3

import pytest

from generate_it._crypto_v2 import MAX_NOTE_BYTES
from generate_it.exceptions import StorageError
from generate_it.storage import StorageManager


def _tamper(db_path, column: str, value) -> None:
    connection = sqlite3.connect(db_path)
    connection.execute(f"UPDATE credentials SET {column}=? WHERE id=1", (value,))
    connection.commit()
    connection.close()


@pytest.mark.parametrize("initializer", ["initialize_vault", "initialize_vault_v2"])
def test_empty_optional_note_blob_is_corruption_not_absent(tmp_path, initializer: str) -> None:
    db_path = tmp_path / f"{initializer}.db"
    storage = StorageManager(db_path=db_path)
    getattr(storage, initializer)("A-Strong-Passw0rd!")
    storage.save_credential("Service", "user", "password")
    _tamper(db_path, "encrypted_note", b"")

    listed = storage.list_credentials()
    assert listed[0]["password"] == "<DECRYPTION_ERROR>"
    assert listed[0]["note"] == "<DECRYPTION_ERROR>"
    exported, skipped = storage.export_to_csv(tmp_path / f"{initializer}.csv")
    assert exported == 0
    assert skipped[0]["error"] == "Unable to decrypt credential"
    with pytest.raises(StorageError, match="Unable to decrypt credential"):
        storage.get_credential_secret(1)
    storage.close()


def test_malformed_legacy_note_migration_raises_storage_error(tmp_path) -> None:
    db_path = tmp_path / "vault.db"
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault("A-Strong-Passw0rd!")
    storage.save_credential("Service", "user", "password", note="note")
    _tamper(db_path, "encrypted_note", b"x" * 100)

    with pytest.raises(StorageError, match="Failed to decrypt v1 note"):
        storage.migrate_v1_to_v2("A-Strong-Passw0rd!")
    storage.close()


def test_oversized_legacy_note_migration_normalizes_limit_error(tmp_path) -> None:
    db_path = tmp_path / "vault.db"
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault("A-Strong-Passw0rd!")
    storage.save_credential("Service", "user", "password", note="note")
    assert storage._fernet is not None
    oversized_note = storage._fernet.encrypt(
        b"n" * (MAX_NOTE_BYTES + 1)
    )
    _tamper(db_path, "encrypted_note", oversized_note)

    with pytest.raises(StorageError, match="note plaintext exceeds"):
        storage.migrate_v1_to_v2("A-Strong-Passw0rd!")
    storage.close()
