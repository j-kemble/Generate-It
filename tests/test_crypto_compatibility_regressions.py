from __future__ import annotations

import sqlite3

import pytest

from generate_it._crypto_v2 import MAX_NOTE_BYTES, MAX_PASSWORD_BYTES
from generate_it.storage import StorageError, StorageManager


def test_v1_migration_accepts_note_larger_than_password_limit(tmp_path) -> None:
    db_path = tmp_path / "vault.db"
    note = "n" * (MAX_PASSWORD_BYTES + 1024)
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault("A-Strong-Passw0rd!")
    storage.save_credential("Service", "user", "password", note=note)

    storage.migrate_v1_to_v2("A-Strong-Passw0rd!")

    assert storage.get_credential_secret(1)["note"] == note
    storage.close()


def test_aad_migration_accepts_note_larger_than_password_limit(tmp_path) -> None:
    db_path = tmp_path / "vault.db"
    note = "n" * (MAX_PASSWORD_BYTES + 1024)
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault_v2("A-Strong-Passw0rd!")
    storage._aad_version = 2
    storage.save_credential("Service", "user", "password", note=note)
    storage._aad_version = 2

    storage.migrate_aad_to_v3()

    assert storage.get_credential_secret(1)["note"] == note
    storage.close()


@pytest.mark.parametrize("initializer", ["initialize_vault", "initialize_vault_v2"])
def test_update_rejects_oversized_fields_without_changing_existing_credential(
    tmp_path, initializer: str
) -> None:
    storage = StorageManager(db_path=tmp_path / f"{initializer}.db")
    getattr(storage, initializer)("A-Strong-Passw0rd!")
    credential_id = storage.save_credential("Service", "user", "password", note="note")

    with pytest.raises(StorageError, match="password plaintext exceeds"):
        storage.update_credential(
            credential_id, "Service", "user", "p" * (MAX_PASSWORD_BYTES + 1), "note"
        )
    with pytest.raises(StorageError, match="note plaintext exceeds"):
        storage.update_credential(
            credential_id, "Service", "user", "password", "n" * (MAX_NOTE_BYTES + 1)
        )

    assert storage.get_credential_secret(credential_id) == {
        "password": "password",
        "note": "note",
        "note_is_hidden": False,
    }
    storage.close()


def test_malformed_v2_ciphertext_is_reported_as_decryption_error(tmp_path) -> None:
    db_path = tmp_path / "vault.db"
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault_v2("A-Strong-Passw0rd!")
    credential_id = storage.save_credential("Service", "user", "password")
    connection = sqlite3.connect(db_path)
    connection.execute(
        "UPDATE credentials SET encrypted_password=? WHERE id=?",
        (b"x" * 27, credential_id),
    )
    connection.commit()
    connection.close()

    credentials = storage.list_credentials()
    assert credentials[0]["password"] == "<DECRYPTION_ERROR>"
    storage.close()
