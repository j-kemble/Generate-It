from __future__ import annotations

import sqlite3

import pytest
from cryptography.fernet import Fernet

from generate_it.storage import StorageManager, WeakMasterPasswordError


def _replace_v1_password(db_path, old_password: str, new_password: str) -> None:
    storage = StorageManager(db_path=db_path)
    connection = sqlite3.connect(db_path)
    row = connection.execute("SELECT value FROM config WHERE key='salt'").fetchone()
    old_salt = row[0]
    old_key = storage._derive_key(old_password, old_salt, 480_000)
    new_salt = b"t" * 32
    new_key = storage._derive_key(new_password, new_salt, 480_000)
    old_fernet = Fernet(old_key)
    new_fernet = Fernet(new_key)
    rows = connection.execute(
        "SELECT id, encrypted_password, encrypted_note FROM credentials"
    ).fetchall()
    for credential_id, encrypted_password, encrypted_note in rows:
        password = old_fernet.decrypt(encrypted_password)
        note = old_fernet.decrypt(encrypted_note) if encrypted_note else None
        connection.execute(
            "UPDATE credentials SET encrypted_password=?, encrypted_note=? WHERE id=?",
            (new_fernet.encrypt(password), new_fernet.encrypt(note) if note else None, credential_id),
        )
    verification = new_fernet.encrypt(b"VERIFICATION_TOKEN")
    connection.execute("UPDATE config SET value=? WHERE key='salt'", (new_salt,))
    connection.execute(
        "UPDATE config SET value=? WHERE key='verification'", (verification,)
    )
    connection.commit()
    connection.close()
    storage.close()


def test_weak_legacy_password_requires_explicit_rekey(tmp_path) -> None:
    db_path = tmp_path / "vault.db"
    initial = StorageManager(db_path=db_path)
    initial.initialize_vault("A-Strong-Passw0rd!")
    initial.close()
    _replace_v1_password(db_path, "A-Strong-Passw0rd!", "A" * 64)

    storage = StorageManager(db_path=db_path)
    storage.unlock_vault("A" * 64)

    with pytest.raises(WeakMasterPasswordError, match="new master password|Master password"):
        storage.migrate_v1_to_v2("A" * 64)

    assert storage._vault_version == 1
    storage.close()


def test_weak_legacy_password_can_migrate_with_validated_rekey(tmp_path) -> None:
    db_path = tmp_path / "vault.db"
    initial = StorageManager(db_path=db_path)
    initial.initialize_vault("A-Strong-Passw0rd!")
    initial.save_credential("GitHub", "dev", "secret")
    initial.close()
    _replace_v1_password(db_path, "A-Strong-Passw0rd!", "A" * 64)

    storage = StorageManager(db_path=db_path)
    storage.unlock_vault("A" * 64)
    storage.migrate_v1_to_v2("A" * 64, new_master_password="New-Strong-Passw0rd!")
    storage.close()

    reopened = StorageManager(db_path=db_path)
    reopened.unlock_vault("New-Strong-Passw0rd!")
    assert reopened._vault_version == 2
    assert reopened.list_credentials()[0]["password"] == "secret"
    reopened.close()


def test_rekey_requires_authentic_legacy_password(tmp_path) -> None:
    db_path = tmp_path / "vault.db"
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault("A-Strong-Passw0rd!")
    storage.close()

    reopened = StorageManager(db_path=db_path)
    reopened.unlock_vault("A-Strong-Passw0rd!")
    with pytest.raises(Exception, match="does not match"):
        reopened.migrate_v1_to_v2(
            "Wrong-Password-1!", new_master_password="New-Strong-Passw0rd!"
        )
    assert reopened._vault_version == 1
    reopened.close()
