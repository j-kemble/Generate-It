"""Tests for Phase 4: AAD v3 serialization, disambiguation, and migration."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from generate_it._crypto_v2 import (
    make_associated_data_v2,
    make_associated_data_v3,
    encrypt_field,
    decrypt_field,
)
from generate_it.storage import StorageManager, StorageError


def test_aad_v3_disambiguates_concatenations() -> None:
    """Pairs like ("ab", "c") and ("a", "bc") produce DIFFERENT associated
    data in AAD v3, whereas in AAD v2 they produced identical bytes."""
    vault_uuid = b"V" * 16
    cred_uuid = b"C" * 16

    v2_pair1 = make_associated_data_v2(vault_uuid, cred_uuid, "password", "ab", "c")
    v2_pair2 = make_associated_data_v2(vault_uuid, cred_uuid, "password", "a", "bc")
    # Proof of AAD v2 flaw:
    assert v2_pair1 == v2_pair2

    # AAD v3 fix: explicit length prefixes differentiate them.
    v3_pair1 = make_associated_data_v3(vault_uuid, cred_uuid, "password", "ab", "c")
    v3_pair2 = make_associated_data_v3(vault_uuid, cred_uuid, "password", "a", "bc")
    assert v3_pair1 != v3_pair2


def test_aad_v3_encrypt_decrypt_roundtrip() -> None:
    dek = b"D" * 32
    vault_uuid = b"V" * 16
    cred_uuid = b"C" * 16

    ad = make_associated_data_v3(vault_uuid, cred_uuid, "password", "GitHub", "DevUser")
    ct = encrypt_field(dek, ad, "my-secret-password")

    decrypted = decrypt_field(dek, ad, ct)
    assert decrypted == "my-secret-password"

    # Metadata tampering fails decryption
    ad_tampered = make_associated_data_v3(vault_uuid, cred_uuid, "password", "GitHub-Tampered", "DevUser")
    with pytest.raises(Exception):
        decrypt_field(dek, ad_tampered, ct)


def test_new_vault_uses_aad_v3(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"
    master = "A-Strong-Passw0rd!"

    storage = StorageManager(db_path=db_path)
    storage.initialize_vault_v2(master)
    assert storage._aad_version == 4

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT value FROM config WHERE key='aad_version'").fetchone()
    conn.close()
    assert row is not None
    assert row[0].decode() if isinstance(row[0], bytes) else str(row[0]) == "4"

    storage.close()


def test_migrate_aad_v1_or_v2_to_v3(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"
    master = "A-Strong-Passw0rd!"

    # Create v2 vault and force aad_version = 2
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault_v2(master)

    # Save credentials under AAD v2
    storage._aad_version = 2
    conn = storage._get_conn()
    conn.execute("UPDATE config SET value='2' WHERE key='aad_version'")
    conn.commit()

    c1 = storage.save_credential("ServiceA", "userA", "secretA", note="noteA")
    c2 = storage.save_credential("ServiceB", "userB", "secretB")
    storage.close()

    # Reopen and migrate to the current AAD (v4)
    storage2 = StorageManager(db_path=db_path)
    storage2.unlock_vault(master)
    assert storage2._aad_version == 2

    storage2.migrate_aad_to_v3()
    assert storage2._aad_version == 4

    # Decryption works under AAD v4
    creds = storage2.list_credentials()
    assert len(creds) == 2
    p_map = {c["service"]: c["password"] for c in creds}
    assert p_map["ServiceA"] == "secretA"
    assert p_map["ServiceB"] == "secretB"

    storage2.close()

    # Backup file exists
    assert (db_path.with_suffix(db_path.suffix + ".aad_v2.bak")).exists()


def test_aad_v3_migration_rollback_on_failure(tmp_path: Path) -> None:
    db_path = tmp_path / "vault.db"
    master = "A-Strong-Passw0rd!"

    storage = StorageManager(db_path=db_path)
    storage.initialize_vault_v2(master)
    storage.save_credential("ServiceA", "userA", "secretA")
    storage.close()

    # Reopen at AAD v2 and tamper with ciphertext to force migration decryption failure
    storage2 = StorageManager(db_path=db_path)
    storage2.unlock_vault(master)
    # Force _aad_version back to 2 in-memory to test migration from 2
    storage2._aad_version = 2

    conn = storage2._get_conn()
    conn.execute("UPDATE credentials SET encrypted_password = ? WHERE id = 1", (b"invalid-ciphertext",))
    conn.commit()

    with pytest.raises(StorageError):
        storage2.migrate_aad_to_v3()

    assert storage2._aad_version == 2
    storage2.close()
