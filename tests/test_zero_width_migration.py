from __future__ import annotations

from pathlib import Path

from generate_it._crypto_v2 import (
    AEAD_AES_256_GCM,
    MAX_NOTE_BYTES,
    MAX_PASSWORD_BYTES,
    encrypt_field,
    make_associated_data_v3,
)
from generate_it.identity import canonical_identity, canonical_identity_stripped
from generate_it.storage import StorageManager


def _legacy_aad_v3(storage, cred_uuid, field, svc, usr, dek, plaintext: str) -> bytes:
    """Encrypt with legacy AAD v3 (frozen canonical_identity) and return the ciphertext."""
    ad = make_associated_data_v3(storage._vault_uuid, cred_uuid, field, svc, usr)
    return encrypt_field(
        dek,
        ad,
        plaintext,
        aead_algorithm=AEAD_AES_256_GCM,
        max_plaintext_bytes=MAX_PASSWORD_BYTES if field == "password" else MAX_NOTE_BYTES,
        field_name=field,
    )


def test_zero_width_migration_reencrypts_and_repairs_lookup(tmp_path: Path) -> None:
    """A legacy v3 vault with zero-width identity chars is migrated on unlock.

    Simulates a vault created by the old code: aad_version=3, ciphertext
    bound to AAD v3 with frozen canonical identity (preserving zero-width
    format chars), and stored service_key/username_key containing those
    chars.  After unlock the automatic zero-width migration must:

    * Rewrite stored keys to stripped canonical form.
    * Re-encrypt every credential field with AAD v4 (stripped canonical).
    * Set aad_version=4 in config so all future crypto uses stripped AAD.
    * Produce a backup file (non-destructive).
    * Allow find_credential_by_identity and get_credential_secret to
      succeed with the same raw service string that was used to create the
      original (zero-width-bearing) credential.
    """
    db_path = tmp_path / "zw.db"
    master = "A-Strong-Passw0rd!"
    raw_service = "Gmail\u200b"
    raw_username = "user"
    note = "test note"

    import uuid

    # --- Create a v2 vault and force it to look like a legacy v3 vault ---
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault_v2(master)
    # Force aad_version=3 in config and memory (mimics legacy vault)
    storage._aad_version = 3
    conn = storage._get_conn()
    conn.execute("UPDATE config SET value='3' WHERE key='aad_version'")
    conn.commit()
    # Insert a legacy row with zero-width identity keys
    cred_uuid = uuid.uuid4().bytes
    dek = storage._dek
    vault_uuid = storage._vault_uuid  # noqa: F841 (used via storage attrs below)

    pw_ct = _legacy_aad_v3(
        storage, cred_uuid, "password", raw_service, raw_username, dek, "secret",
    )
    nt_ct = _legacy_aad_v3(
        storage, cred_uuid, "note", raw_service, raw_username, dek, note,
    )

    legacy_svc_key = canonical_identity(raw_service)       # frozen → "gmail\u200b"
    legacy_usr_key = canonical_identity(raw_username)

    conn.execute(
        "INSERT INTO credentials (credential_uuid, service, username,"
        " encrypted_password, encrypted_note, note_is_hidden,"
        " service_key, username_key)"
        " VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
        (cred_uuid, raw_service, raw_username, pw_ct, nt_ct,
         legacy_svc_key, legacy_usr_key),
    )
    conn.commit()
    storage.close()

    # --- Reopen: unlock must trigger automatic migration ---
    storage2 = StorageManager(db_path=db_path)
    storage2.unlock_vault(master)

    # Post-migration assertions
    assert storage2._aad_version == 4, "AAD version should be bumped to 4"
    assert canonical_identity_stripped(raw_service) == "gmail"

    found = storage2.find_credential_by_identity(raw_service, raw_username)
    assert found is not None, "Credential should be findable by original zero-width service"
    assert found["service"] == raw_service

    secret = storage2.get_credential_secret(found["id"])
    assert secret["password"] == "secret"
    assert secret["note"] == note

    # Stored keys are now stripped
    conn2 = storage2._get_conn()
    row = conn2.execute(
        "SELECT service_key, username_key FROM credentials WHERE id=?",
        (found["id"],),
    ).fetchone()
    assert row["service_key"] == "gmail"
    assert row["username_key"] == "user"

    storage2.close()

    # Backup file was created
    backup_path = db_path.with_suffix(db_path.suffix + ".identity_zw.bak")
    assert backup_path.exists(), "zero-width migration must create a backup"


def test_new_vault_writes_and_reads_with_stripped_aad(tmp_path: Path) -> None:
    """New v2 vaults use AAD v4 and stripped keys from creation."""
    db_path = tmp_path / "new_v4.db"
    master = "A-Strong-Passw0rd!"
    raw_service = "Gmail\u200b"
    raw_username = "user"

    storage = StorageManager(db_path=db_path)
    storage.initialize_vault_v2(master)
    assert storage._aad_version == 4

    storage.save_credential(raw_service, raw_username, "secret")
    found = storage.find_credential_by_identity(raw_service, raw_username)
    assert found is not None
    secret = storage.get_credential_secret(found["id"])
    assert secret["password"] == "secret"
    storage.close()


def test_clean_v3_vault_migrates_to_v4_on_unlock(tmp_path: Path) -> None:
    """A clean v3 vault without zero-width chars is upgraded to v4 on unlock.

    AAD-version migration is decoupled from identity-key rewriting: a v2
    vault at AAD v3 reaches the current AAD v4 on every unlock even when no
    key needs rewriting (here there are no zero-width characters at all, so
    ``rows_to_rewrite`` is empty).  Re-encrypting with the stripped
    canonicalizer is a no-op change for clean identities, so decryption and
    lookup remain valid while ``aad_version`` advances to 4.
    """
    db_path = tmp_path / "clean_v3.db"
    master = "A-Strong-Passw0rd!"

    # Simulate a clean v3 vault (new vaults default to v4).
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault_v2(master)
    storage._aad_version = 3
    conn = storage._get_conn()
    conn.execute("UPDATE config SET value='3' WHERE key='aad_version'")
    conn.commit()
    storage.save_credential("GitHub", "octocat", "secret")  # no zero-width
    storage.close()

    storage2 = StorageManager(db_path=db_path)
    storage2.unlock_vault(master)
    # The intended final format is v4 — a v3 vault must not stay stranded.
    assert storage2._aad_version == 4
    cfg_row = storage2._get_conn().execute(
        "SELECT value FROM config WHERE key='aad_version'"
    ).fetchone()
    assert int(cfg_row[0]) == 4
    found = storage2.find_credential_by_identity("GitHub", "octocat")
    assert found is not None
    assert storage2.get_credential_secret(found["id"])["password"] == "secret"
    storage2.close()


def test_aad_v3_with_already_stripped_keys_migrates_to_v4(tmp_path: Path) -> None:
    """A v3 vault whose keys are already stripped still migrates to v4.

    A legacy v3 vault can carry zero-width-bearing service/username values
    while its stored identity keys already equal the stripped canonical form
    (e.g. a prior/partial migration, or a vault that wrote stripped keys
    while still encrypting with AAD v3).  In that state ``rows_to_rewrite``
    is empty, so the old code returned early and stranded the vault at AAD
    v3.  AAD-version migration must be an independent trigger: the vault is
    re-encrypted to v4 and decryption stays valid.
    """
    db_path = tmp_path / "stripped_v3.db"
    master = "A-Strong-Passw0rd!"
    raw_service = "Gmail\u200b"
    raw_username = "user"
    note = "test note"

    import uuid

    storage = StorageManager(db_path=db_path)
    storage.initialize_vault_v2(master)
    storage._aad_version = 3
    conn = storage._get_conn()
    conn.execute("UPDATE config SET value='3' WHERE key='aad_version'")
    conn.commit()

    # Encrypt a row with legacy AAD v3 (frozen canonicalization preserving
    # the zero-width char), but store the identity keys ALREADY stripped.
    cred_uuid = uuid.uuid4().bytes
    dek = storage._dek
    pw_ct = _legacy_aad_v3(
        storage, cred_uuid, "password", raw_service, raw_username, dek, "secret",
    )
    nt_ct = _legacy_aad_v3(
        storage, cred_uuid, "note", raw_service, raw_username, dek, note,
    )
    stripped_svc_key = canonical_identity_stripped(raw_service)  # "gmail"
    stripped_usr_key = canonical_identity_stripped(raw_username)  # "user"
    conn.execute(
        "INSERT INTO credentials (credential_uuid, service, username,"
        " encrypted_password, encrypted_note, note_is_hidden,"
        " service_key, username_key) VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
        (cred_uuid, raw_service, raw_username, pw_ct, nt_ct,
         stripped_svc_key, stripped_usr_key),
    )
    conn.commit()
    storage.close()

    storage2 = StorageManager(db_path=db_path)
    storage2.unlock_vault(master)
    assert storage2._aad_version == 4, "v3 vault with already-stripped keys must reach v4"
    # On-disk config reflects the migration, not just in-memory state.
    on_disk = storage2._get_conn().execute(
        "SELECT value FROM config WHERE key='aad_version'"
    ).fetchone()
    assert int(on_disk[0]) == 4

    found = storage2.find_credential_by_identity(raw_service, raw_username)
    assert found is not None, "Credential must remain findable by original zero-width service"
    secret = storage2.get_credential_secret(found["id"])
    assert secret["password"] == "secret"
    assert secret["note"] == note

    row = storage2._get_conn().execute(
        "SELECT service_key FROM credentials WHERE id=?", (found["id"],)
    ).fetchone()
    assert row["service_key"] == "gmail"

    backup_path = db_path.with_suffix(db_path.suffix + ".identity_zw.bak")
    assert backup_path.exists()
    storage2.close()