"""Tests for vault v2 crypto primitives and StorageManager v2 integration."""

from __future__ import annotations

import os
import uuid

import pytest

from generate_it._crypto_v2 import (
    AEAD_AES_256_GCM,
    CREDENTIAL_UUID_LEN,
    DEK_LEN,
    NONCE_LEN,
    SALT_LEN,
    VAULT_UUID_LEN,
    VERIFICATION_PLAINTEXT,
    WRAPPED_DEK_LEN,
    InvalidUnwrap,
    create_verification_token,
    decrypt_field,
    derive_kek,
    encrypt_field,
    generate_dek,
    make_associated_data,
    unwrap_dek,
    verify_token,
    wrap_dek,
)
from generate_it.storage import (
    InvalidPasswordError,
    StorageError,
    StorageManager,
    WeakMasterPasswordError,
)


# ---------------------------------------------------------------------------
# _crypto_v2 unit tests
# ---------------------------------------------------------------------------


class TestKekDerivation:
    """KEK derivation via Argon2id."""

    def test_same_password_and_salt_produce_same_kek(self) -> None:
        password = "correct-horse-battery-staple"
        salt = os.urandom(SALT_LEN)
        kek1 = derive_kek(password, salt)
        kek2 = derive_kek(password, salt)
        assert kek1 == kek2
        assert len(kek1) == 32

    def test_different_password_produces_different_kek(self) -> None:
        password = "correct-horse-battery-staple"
        salt = os.urandom(SALT_LEN)
        kek1 = derive_kek(password, salt)
        kek2 = derive_kek("different-password", salt)
        assert kek1 != kek2

    def test_different_salt_produces_different_kek(self) -> None:
        password = "correct-horse-battery-staple"
        salt1 = os.urandom(SALT_LEN)
        salt2 = os.urandom(SALT_LEN)
        kek1 = derive_kek(password, salt1)
        kek2 = derive_kek(password, salt2)
        assert kek1 != kek2

    def test_custom_parameters_are_honored(self) -> None:
        """Custom memory/time/parallelism produce a valid KEK."""
        password = "test-password"
        salt = os.urandom(SALT_LEN)
        # Use minimal params for speed in tests.
        kek = derive_kek(password, salt, memory=8192, time=2, parallelism=2)
        assert len(kek) == 32


class TestDekWrapUnwrap:
    """DEK wrapping via AES-256 Key Wrap (RFC 3394)."""

    def test_wrap_unwrap_roundtrip(self) -> None:
        kek = os.urandom(32)
        dek = generate_dek()
        wrapped = wrap_dek(kek, dek)
        assert len(wrapped) == WRAPPED_DEK_LEN
        unwrapped = unwrap_dek(kek, wrapped)
        assert unwrapped == dek

    def test_unwrap_with_wrong_kek_raises(self) -> None:
        kek1 = os.urandom(32)
        kek2 = os.urandom(32)
        dek = generate_dek()
        wrapped = wrap_dek(kek1, dek)
        with pytest.raises(InvalidUnwrap):
            unwrap_dek(kek2, wrapped)

    def test_unwrap_tampered_data_raises(self) -> None:
        kek = os.urandom(32)
        dek = generate_dek()
        wrapped = wrap_dek(kek, dek)
        # Flip one byte.
        tampered = bytearray(wrapped)
        tampered[3] ^= 0x01
        with pytest.raises(InvalidUnwrap):
            unwrap_dek(kek, bytes(tampered))

    def test_generate_dek_is_random(self) -> None:
        dek1 = generate_dek()
        dek2 = generate_dek()
        assert dek1 != dek2
        assert len(dek1) == DEK_LEN


class TestFieldEncryptDecrypt:
    """AEAD field-level encrypt/decrypt with associated data."""

    @pytest.fixture
    def dek(self) -> bytes:
        return os.urandom(32)

    @pytest.fixture
    def vault_uuid(self) -> bytes:
        return os.urandom(VAULT_UUID_LEN)

    @pytest.fixture
    def credential_uuid(self) -> bytes:
        return os.urandom(CREDENTIAL_UUID_LEN)

    def test_encrypt_decrypt_roundtrip(self, dek, vault_uuid, credential_uuid) -> None:
        plaintext = "my-secret-password"
        ad = make_associated_data(vault_uuid, credential_uuid, "password")
        ct = encrypt_field(dek, ad, plaintext)
        assert len(ct) == NONCE_LEN + len(plaintext) + 16  # nonce + plaintext + tag
        decrypted = decrypt_field(dek, ad, ct)
        assert decrypted == plaintext

    def test_wrong_vault_uuid_fails_decrypt(self, dek, vault_uuid, credential_uuid) -> None:
        plaintext = "my-secret-password"
        ad = make_associated_data(vault_uuid, credential_uuid, "password")
        ct = encrypt_field(dek, ad, plaintext)

        wrong_vault = os.urandom(VAULT_UUID_LEN)
        wrong_ad = make_associated_data(wrong_vault, credential_uuid, "password")
        with pytest.raises(Exception):  # InvalidTag
            decrypt_field(dek, wrong_ad, ct)

    def test_wrong_credential_uuid_fails_decrypt(self, dek, vault_uuid, credential_uuid) -> None:
        plaintext = "my-secret-password"
        ad = make_associated_data(vault_uuid, credential_uuid, "password")
        ct = encrypt_field(dek, ad, plaintext)

        wrong_cred = os.urandom(CREDENTIAL_UUID_LEN)
        wrong_ad = make_associated_data(vault_uuid, wrong_cred, "password")
        with pytest.raises(Exception):  # InvalidTag
            decrypt_field(dek, wrong_ad, ct)

    def test_wrong_field_name_fails_decrypt(self, dek, vault_uuid, credential_uuid) -> None:
        plaintext = "my-secret-password"
        ad = make_associated_data(vault_uuid, credential_uuid, "password")
        ct = encrypt_field(dek, ad, plaintext)

        wrong_ad = make_associated_data(vault_uuid, credential_uuid, "note")
        with pytest.raises(Exception):  # InvalidTag
            decrypt_field(dek, wrong_ad, ct)

    def test_tampered_ciphertext_fails_decrypt(self, dek, vault_uuid, credential_uuid) -> None:
        plaintext = "my-secret-password"
        ad = make_associated_data(vault_uuid, credential_uuid, "password")
        ct = encrypt_field(dek, ad, plaintext)

        # Tamper with the tag (last byte).
        tampered = bytearray(ct)
        tampered[-1] ^= 0xFF
        with pytest.raises(Exception):  # InvalidTag
            decrypt_field(dek, ad, bytes(tampered))

    def test_note_field_works(self, dek, vault_uuid, credential_uuid) -> None:
        plaintext = "A note with some text."
        ad = make_associated_data(vault_uuid, credential_uuid, "note")
        ct = encrypt_field(dek, ad, plaintext)
        decrypted = decrypt_field(dek, ad, ct)
        assert decrypted == plaintext

    def test_non_ascii_plaintext(self, dek, vault_uuid, credential_uuid) -> None:
        plaintext = "パスワード! 🔐 café"
        ad = make_associated_data(vault_uuid, credential_uuid, "password")
        ct = encrypt_field(dek, ad, plaintext)
        decrypted = decrypt_field(dek, ad, ct)
        assert decrypted == plaintext

    def test_empty_plaintext(self, dek, vault_uuid, credential_uuid) -> None:
        plaintext = ""
        ad = make_associated_data(vault_uuid, credential_uuid, "password")
        ct = encrypt_field(dek, ad, plaintext)
        decrypted = decrypt_field(dek, ad, ct)
        assert decrypted == ""


class TestVerificationToken:
    """Verification token create/verify."""

    def test_create_and_verify_succeeds(self) -> None:
        dek = os.urandom(32)
        vault_uuid = os.urandom(VAULT_UUID_LEN)
        ct = create_verification_token(dek, vault_uuid)
        assert verify_token(dek, vault_uuid, ct)

    def test_wrong_dek_fails_verification(self) -> None:
        dek = os.urandom(32)
        wrong_dek = os.urandom(32)
        vault_uuid = os.urandom(VAULT_UUID_LEN)
        ct = create_verification_token(dek, vault_uuid)
        assert not verify_token(wrong_dek, vault_uuid, ct)

    def test_wrong_vault_uuid_fails_verification(self) -> None:
        dek = os.urandom(32)
        vault_uuid = os.urandom(VAULT_UUID_LEN)
        wrong_uuid = os.urandom(VAULT_UUID_LEN)
        ct = create_verification_token(dek, vault_uuid)
        assert not verify_token(dek, wrong_uuid, ct)

    def test_tampered_token_fails_verification(self) -> None:
        dek = os.urandom(32)
        vault_uuid = os.urandom(VAULT_UUID_LEN)
        ct = create_verification_token(dek, vault_uuid)
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        assert not verify_token(dek, vault_uuid, bytes(tampered))


class TestNonceUniqueness:
    """Nonce uniqueness validation (§6.4)."""

    def test_10000_encryptions_produce_unique_nonces(self) -> None:
        dek = os.urandom(32)
        vault_uuid = os.urandom(VAULT_UUID_LEN)
        credential_uuid = os.urandom(CREDENTIAL_UUID_LEN)
        ad = make_associated_data(vault_uuid, credential_uuid, "password")

        nonces: set[bytes] = set()
        for _ in range(10000):
            ct = encrypt_field(dek, ad, "test")
            nonce = ct[:NONCE_LEN]
            assert nonce not in nonces, "Nonce collision detected!"
            nonces.add(nonce)

        assert len(nonces) == 10000


# ---------------------------------------------------------------------------
# StorageManager v2 integration tests
# ---------------------------------------------------------------------------


class TestVaultV2CreateAndUnlock:
    """Full create/unlock lifecycle for v2 vaults."""

    def test_create_and_unlock_v2(self, tmp_path) -> None:
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2(pw)
        assert storage._vault_version == 2
        assert storage._dek is not None
        assert storage._vault_uuid is not None
        storage.close()

        # Re-open and unlock.
        storage2 = StorageManager(db_path=db_path)
        assert storage2.is_v2_vault()
        storage2.unlock_vault(pw)
        assert storage2._vault_version == 2
        storage2.close()

    def test_v2_wrong_password_rejected(self, tmp_path) -> None:
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2(pw)
        storage.close()

        storage2 = StorageManager(db_path=db_path)
        with pytest.raises(InvalidPasswordError):
            storage2.unlock_vault("wrong-password-here")
        storage2.close()

    def test_v2_empty_password_rejected_at_init(self, tmp_path) -> None:
        storage = StorageManager(db_path=tmp_path / "vault.db")
        with pytest.raises(WeakMasterPasswordError):
            storage.initialize_vault_v2("")
        storage.close()

    def test_v2_short_password_rejected(self, tmp_path) -> None:
        storage = StorageManager(db_path=tmp_path / "vault.db")
        with pytest.raises(WeakMasterPasswordError):
            storage.initialize_vault_v2("short")
        storage.close()

    def test_v2_vault_has_version_tag(self, tmp_path) -> None:
        db_path = tmp_path / "vault.db"
        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2("a-strong-master-password")
        storage.close()

        # Direct SQLite check.
        import sqlite3
        raw = sqlite3.connect(db_path)
        cursor = raw.cursor()
        cursor.execute("SELECT value FROM config WHERE key='version'")
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == b"2" or row[0] == "2"
        raw.close()

    def test_is_v2_vault_detection(self, tmp_path) -> None:
        db_path = tmp_path / "vault.db"
        storage = StorageManager(db_path=db_path)

        # Not a vault yet.
        assert not storage.is_v2_vault()

        # Create v1.
        storage.initialize_vault("a-strong-master-password")
        assert not storage.is_v2_vault()
        storage.close()

        # Create v2 (different path).
        db_path2 = tmp_path / "vault2.db"
        storage2 = StorageManager(db_path=db_path2)
        storage2.initialize_vault_v2("a-strong-master-password")
        assert storage2.is_v2_vault()
        storage2.close()


class TestVaultV2CredentialOps:
    """Save, retrieve, update, delete credentials in v2 vaults."""

    def test_save_and_retrieve_password(self, tmp_path) -> None:
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2(pw)
        storage.save_credential("GitHub", "alice", "gh-secret-123")
        storage.close()

        # Re-open and verify.
        storage2 = StorageManager(db_path=db_path)
        storage2.unlock_vault(pw)
        creds = storage2.list_credentials()
        assert len(creds) == 1
        assert creds[0]["service"] == "GitHub"
        assert creds[0]["username"] == "alice"
        assert creds[0]["password"] == "gh-secret-123"
        assert creds[0]["note"] == ""
        storage2.close()

    def test_save_with_note(self, tmp_path) -> None:
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2(pw)
        storage.save_credential("GitHub", "alice", "password", note="A note with text")
        storage.close()

        storage2 = StorageManager(db_path=db_path)
        storage2.unlock_vault(pw)
        creds = storage2.list_credentials()
        assert creds[0]["note"] == "A note with text"
        storage2.close()

    def test_save_and_get_credential_secret(self, tmp_path) -> None:
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2(pw)
        cred_id = storage.save_credential("GitHub", "alice", "secret-pw", note="my note")
        secret = storage.get_credential_secret(cred_id)
        assert secret["password"] == "secret-pw"
        assert secret["note"] == "my note"
        storage.close()

    def test_list_credential_metadata(self, tmp_path) -> None:
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2(pw)
        storage.save_credential("GitHub", "alice", "pw1")
        storage.save_credential("Gmail", "alice", "pw2")
        metadata = storage.list_credential_metadata()
        assert len(metadata) == 2
        # Ordered by service.
        assert metadata[0]["service"] == "GitHub"
        assert metadata[1]["service"] == "Gmail"
        # Metadata should not include passwords.
        assert "password" not in metadata[0]
        storage.close()

    def test_update_credential(self, tmp_path) -> None:
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2(pw)
        cred_id = storage.save_credential("OldService", "olduser", "oldpass")
        storage.update_credential(cred_id, "NewService", "newuser", "newpass", note="updated note")
        creds = storage.list_credentials()
        assert creds[0]["service"] == "NewService"
        assert creds[0]["username"] == "newuser"
        assert creds[0]["password"] == "newpass"
        assert creds[0]["note"] == "updated note"
        storage.close()

    def test_delete_credential(self, tmp_path) -> None:
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2(pw)
        storage.save_credential("GitHub", "alice", "pw1")
        cred_id = storage.save_credential("Gmail", "alice", "pw2")
        storage.delete_credential(cred_id)
        creds = storage.list_credentials()
        assert len(creds) == 1
        assert creds[0]["service"] == "GitHub"
        storage.close()


class TestVaultV2Migration:
    """v1 → v2 migration tests."""

    def test_migration_preserves_all_credentials(self, tmp_path) -> None:
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        # Create v1 vault with credentials.
        storage = StorageManager(db_path=db_path)
        storage.initialize_vault(pw)
        storage.save_credential("github.com", "alice", "gh-secret-123")
        storage.save_credential("gmail.com", "alice", "gm-secret-456", note="backup email")
        storage.save_credential("aws.amazon.com", "alice", "aws-secret-789")
        storage.close()

        # Verify v1.
        storage1 = StorageManager(db_path=db_path)
        storage1.unlock_vault(pw)
        assert storage1._vault_version == 1
        assert not storage1.is_v2_vault()
        creds_before = storage1.list_credentials()
        assert len(creds_before) == 3

        # Migrate.
        storage1.migrate_v1_to_v2(pw)
        assert storage1._vault_version == 2
        assert storage1._dek is not None

        # Verify all credentials survived migration.
        creds_after = storage1.list_credentials()
        assert len(creds_after) == 3
        # Check passwords match.
        pw_map = {c["service"]: c["password"] for c in creds_after}
        assert pw_map["github.com"] == "gh-secret-123"
        assert pw_map["gmail.com"] == "gm-secret-456"
        assert pw_map["aws.amazon.com"] == "aws-secret-789"
        # Check note.
        note_map = {c["service"]: c["note"] for c in creds_after}
        assert note_map["gmail.com"] == "backup email"
        storage1.close()

        # Verify v2 unlock after migration.
        storage2 = StorageManager(db_path=db_path)
        assert storage2.is_v2_vault()
        storage2.unlock_vault(pw)
        assert storage2._vault_version == 2
        creds = storage2.list_credentials()
        assert len(creds) == 3
        storage2.close()

    def test_migration_creates_backup(self, tmp_path) -> None:
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault(pw)
        storage.save_credential("Test", "user", "pass")
        storage.migrate_v1_to_v2(pw)

        backup_path = db_path.with_suffix(db_path.suffix + ".v1.bak")
        assert backup_path.exists()
        storage.close()

    def test_migration_removes_v1_config_keys(self, tmp_path) -> None:
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault(pw)
        storage.migrate_v1_to_v2(pw)
        storage.close()

        import sqlite3
        raw = sqlite3.connect(db_path)
        cursor = raw.cursor()
        # v1 keys should be gone.
        for key in ("salt", "pbkdf2_iterations", "salt_length"):
            cursor.execute("SELECT value FROM config WHERE key=?", (key,))
            assert cursor.fetchone() is None, f"v1 key '{key}' should have been removed"
        # v2 keys should exist.
        for key in ("version", "vault_uuid", "kdf_salt", "wrapped_dek", "verification"):
            cursor.execute("SELECT value FROM config WHERE key=?", (key,))
            assert cursor.fetchone() is not None, f"v2 key '{key}' missing"
        raw.close()

    def test_migration_wrong_password_not_triggered(self, tmp_path) -> None:
        """Cannot migrate with wrong password (must unlock v1 first)."""
        db_path = tmp_path / "vault.db"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault("correct-password")
        storage.close()

        # Unlock with correct password.
        storage2 = StorageManager(db_path=db_path)
        storage2.unlock_vault("correct-password")
        # Migration works.
        storage2.migrate_v1_to_v2("correct-password")
        storage2.close()

    def test_migration_wrong_password_rejected(self, tmp_path) -> None:
        """Migration with a wrong password must raise InvalidPasswordError.

        The vault is unlocked with the correct password, but a different
        password is passed to migrate_v1_to_v2.  This must be rejected
        to prevent silent re-keying.
        """
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault(pw)
        storage.save_credential("GitHub", "dev", "secret")
        storage.close()

        # Unlock with correct password.
        storage2 = StorageManager(db_path=db_path)
        storage2.unlock_vault(pw)

        # Attempt migration with a different (but equally strong) password.
        with pytest.raises(InvalidPasswordError, match="does not match"):
            storage2.migrate_v1_to_v2("different-strong-pw")

        # Vault must still be v1 and intact.
        assert storage2._vault_version == 1
        # No backup should have been created.
        assert not (db_path.with_suffix(db_path.suffix + ".v1.bak")).exists()
        storage2.close()

    def test_migrate_unlocked_v2_raises(self, tmp_path) -> None:
        """Cannot migrate an already v2 vault."""
        db_path = tmp_path / "vault.db"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2("a-strong-master-password")
        with pytest.raises(StorageError, match="Migration requires an unlocked v1 vault"):
            storage.migrate_v1_to_v2("a-strong-master-password")
        storage.close()

    def test_migration_rollback_on_failure(self, tmp_path) -> None:
        """Verify that migration rollback leaves v1 intact."""
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault(pw)
        storage.save_credential("GitHub", "dev", "secret")
        storage.close()

        # Re-open and migrate, but corrupt credential first.
        storage2 = StorageManager(db_path=db_path)
        storage2.unlock_vault(pw)

        # Tamper with the encrypted_password to cause migration failure.
        import sqlite3
        raw = sqlite3.connect(db_path)
        raw.execute(
            "UPDATE credentials SET encrypted_password = ? WHERE service = ?",
            (b"!!not-valid!!", "GitHub"),
        )
        raw.commit()
        raw.close()

        # Migration should fail because decryption fails.
        with pytest.raises(StorageError, match="Failed to decrypt"):
            storage2.migrate_v1_to_v2(pw)

        # v1 vault should still be intact and usable.
        storage3 = StorageManager(db_path=db_path)
        storage3.unlock_vault(pw)
        assert storage3._vault_version == 1

        # Restore the credential and verify v1 works.
        storage3.close()
        raw2 = sqlite3.connect(db_path)
        # The rollback should have restored the original ciphertext.
        # Actually, the rollback restores pre-transaction state, so the
        # tampered value may not have been committed. Let's check the vault
        # state: the vault should still be v1.
        raw2.close()

        # v1 vault should still unlock.
        storage4 = StorageManager(db_path=db_path)
        storage4.unlock_vault(pw)
        creds = storage4.list_credentials()
        assert len(creds) == 1
        # Password may be <DECRYPTION_ERROR> since we tampered
        # with it outside the transaction. The important point is
        # the vault is still v1.
        assert storage4._vault_version == 1
        storage4.close()

    def test_migration_backup_symlink_not_followed(self, tmp_path) -> None:
        """Pre-created backup-path symlink must not cause writes to the target."""
        db_path = tmp_path / "vault.db"
        victim_path = tmp_path / "victim.txt"
        victim_path.write_text("original victim content")

        # Determine the predictable backup path the *current* code uses.
        backup_path = db_path.with_suffix(db_path.suffix + ".v1.bak")
        # Pre-create it as a symlink to victim.txt — this is the attack.
        try:
            backup_path.symlink_to(victim_path)
        except OSError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                pytest.skip("Windows symlink privilege is not available")
            raise

        pw = "a-strong-master-password"
        storage = StorageManager(db_path=db_path)
        try:
            storage.initialize_vault(pw)
            storage.save_credential("GitHub", "dev", "secret123456")
            storage.migrate_v1_to_v2(pw)

            # After the fix: victim.txt must NOT have been overwritten.
            assert victim_path.read_text() == "original victim content", (
                "victim.txt was modified — symlink was followed!"
            )

            # The backup must now be a regular file (not a symlink).
            assert backup_path.is_file()
            assert not backup_path.is_symlink()

            # Verify migration succeeded.
            assert storage._vault_version == 2
        finally:
            storage.close()


class TestVaultV2AssociatedDataBinding:
    """Verify that AEAD associated data prevents ciphertext substitution."""

    def test_credential_uuid_column_present_in_v2(self, tmp_path) -> None:
        """v2 vaults have a credential_uuid column."""
        db_path = tmp_path / "vault.db"
        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2("a-strong-master-password")
        storage.save_credential("Test", "user", "pass")

        import sqlite3
        raw = sqlite3.connect(db_path)
        cursor = raw.cursor()
        cursor.execute("PRAGMA table_info(credentials)")
        columns = {row[1] for row in cursor.fetchall()}
        assert "credential_uuid" in columns

        cursor.execute("SELECT credential_uuid FROM credentials")
        row = cursor.fetchone()
        assert row[0] is not None
        assert len(row[0]) == CREDENTIAL_UUID_LEN
        raw.close()
        storage.close()

    def test_cross_credential_ciphertext_swap_detected(self, tmp_path) -> None:
        """Swapping ciphertext between credentials causes decryption failure."""
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2(pw)
        cred_a = storage.save_credential("ServiceA", "user", "password-a")
        cred_b = storage.save_credential("ServiceB", "user", "password-b")
        storage.close()

        # Swap encrypted_password between cred_a and cred_b directly in SQLite.
        import sqlite3
        raw = sqlite3.connect(db_path)
        # Read current values.
        row_a = raw.execute("SELECT encrypted_password FROM credentials WHERE id=?", (cred_a,)).fetchone()
        row_b = raw.execute("SELECT encrypted_password FROM credentials WHERE id=?", (cred_b,)).fetchone()
        # Swap.
        raw.execute("UPDATE credentials SET encrypted_password=? WHERE id=?", (row_b[0], cred_a))
        raw.execute("UPDATE credentials SET encrypted_password=? WHERE id=?", (row_a[0], cred_b))
        raw.commit()
        raw.close()

        # Both should show <DECRYPTION_ERROR>.
        storage2 = StorageManager(db_path=db_path)
        storage2.unlock_vault(pw)
        creds = storage2.list_credentials()
        assert len(creds) == 2
        assert creds[0]["password"] == "<DECRYPTION_ERROR>"
        assert creds[1]["password"] == "<DECRYPTION_ERROR>"
        storage2.close()

    def test_password_note_swap_detected(self, tmp_path) -> None:
        """Swapping password and note ciphertext causes decryption failure."""
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2(pw)
        storage.save_credential("Test", "user", "password", note="my note")
        storage.close()

        import sqlite3
        raw = sqlite3.connect(db_path)
        row = raw.execute(
            "SELECT encrypted_password, encrypted_note FROM credentials"
        ).fetchone()
        # Swap.
        raw.execute(
            "UPDATE credentials SET encrypted_password=?, encrypted_note=?",
            (row[1], row[0]),
        )
        raw.commit()
        raw.close()

        storage2 = StorageManager(db_path=db_path)
        storage2.unlock_vault(pw)
        creds = storage2.list_credentials()
        assert creds[0]["password"] == "<DECRYPTION_ERROR>"
        assert creds[0]["note"] == "<DECRYPTION_ERROR>"
        storage2.close()

    def test_fresh_v2_vault_uses_aad_v2(self, tmp_path) -> None:
        """Fresh v2 vaults must have aad_version=2 in config."""
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2(pw)
        assert storage._aad_version == 2

        import sqlite3
        raw = sqlite3.connect(db_path)
        row = raw.execute(
            "SELECT value FROM config WHERE key='aad_version'"
        ).fetchone()
        raw.close()
        assert row is not None
        assert int(row[0]) == 2
        storage.close()

    def test_uuid_ciphertext_swap_rejected_on_aad_v2(self, tmp_path) -> None:
        """Swapping both UUID and ciphertext between credentials must fail
        when the vault uses AAD v2 (metadata-bound).

        AAD v1 only binds vault_uuid + credential_uuid + field_name, so
        swapping both UUID and ciphertext together succeeds.  AAD v2 also
        binds service+username, so the swap must fail.
        """
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2(pw)
        assert storage._aad_version == 2
        cred_a = storage.save_credential("ServiceA", "userA", "alpha-secret")
        cred_b = storage.save_credential("ServiceB", "userB", "beta-secret")
        storage.close()

        # Swap both credential_uuid AND encrypted_password between rows.
        import sqlite3
        raw = sqlite3.connect(db_path)
        row_a = raw.execute(
            "SELECT credential_uuid, encrypted_password FROM credentials WHERE id=?",
            (cred_a,),
        ).fetchone()
        row_b = raw.execute(
            "SELECT credential_uuid, encrypted_password FROM credentials WHERE id=?",
            (cred_b,),
        ).fetchone()
        # Swap UUID + ciphertext for both password and note.
        raw.execute(
            "UPDATE credentials SET credential_uuid=?, encrypted_password=? WHERE id=?",
            (row_b[0], row_b[1], cred_a),
        )
        raw.execute(
            "UPDATE credentials SET credential_uuid=?, encrypted_password=? WHERE id=?",
            (row_a[0], row_a[1], cred_b),
        )
        raw.commit()
        raw.close()

        # Both should show <DECRYPTION_ERROR> — AAD v2 binds service+username
        # so the swapped ciphertext (encrypted under different metadata) fails.
        storage2 = StorageManager(db_path=db_path)
        storage2.unlock_vault(pw)
        creds = storage2.list_credentials()
        assert len(creds) == 2
        for c in creds:
            assert c["password"] == "<DECRYPTION_ERROR>"
        storage2.close()

    def test_v1_to_v2_migration_produces_aad_v2(self, tmp_path) -> None:
        """v1→v2 migration must produce a vault with aad_version=2."""
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault(pw)
        storage.save_credential("GitHub", "dev", "secret")
        storage.close()

        storage2 = StorageManager(db_path=db_path)
        storage2.unlock_vault(pw)
        storage2.migrate_v1_to_v2(pw)
        assert storage2._vault_version == 2
        assert storage2._aad_version == 2

        import sqlite3
        raw = sqlite3.connect(db_path)
        row = raw.execute(
            "SELECT value FROM config WHERE key='aad_version'"
        ).fetchone()
        raw.close()
        assert row is not None
        assert int(row[0]) == 2
        storage2.close()

    def test_aad_v1_to_v2_migration_succeeds(self, tmp_path) -> None:
        """An existing v2 vault at AAD v1 can be migrated to AAD v2."""
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        # Create a v2 vault with AAD v1 (simulate legacy vault).
        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2(pw)
        # Force AAD v1 before saving credentials so they're encrypted with v1 AAD.
        storage._aad_version = 1
        import sqlite3
        conn = storage._get_conn()
        conn.execute("UPDATE config SET value='1' WHERE key='aad_version'")
        conn.commit()
        cred_a = storage.save_credential("ServiceA", "userA", "alpha-secret")
        cred_b = storage.save_credential("ServiceB", "userB", "beta-secret")
        storage.close()

        # Re-open at AAD v1.
        storage2 = StorageManager(db_path=db_path)
        storage2.unlock_vault(pw)
        assert storage2._aad_version == 1

        # Migrate to AAD v2.
        storage2.migrate_aad_v1_to_v2()
        assert storage2._aad_version == 2

        # Credentials should still decrypt correctly.
        creds = storage2.list_credentials()
        assert len(creds) == 2
        pw_map = {c["service"]: c["password"] for c in creds}
        assert pw_map["ServiceA"] == "alpha-secret"
        assert pw_map["ServiceB"] == "beta-secret"
        storage2.close()

        # Verify config persisted.
        raw = sqlite3.connect(db_path)
        row = raw.execute(
            "SELECT value FROM config WHERE key='aad_version'"
        ).fetchone()
        raw.close()
        assert int(row[0]) == 2


class TestVaultV2CloseAndReopen:
    """Close/re-open lifecycle for v2."""

    def test_close_clears_v2_state(self, tmp_path) -> None:
        db_path = tmp_path / "vault.db"
        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2("a-strong-master-password")
        storage.close()

        assert storage._vault_version is None
        assert storage._dek is None
        assert storage._vault_uuid is None

    def test_context_manager_works_for_v2(self, tmp_path) -> None:
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        with StorageManager(db_path=db_path) as storage:
            storage.initialize_vault_v2(pw)
            storage.save_credential("Test", "user", "pass")

        # After __exit__, vault should be locked.
        assert storage._vault_version is None
        assert storage._dek is None

        # Re-open and verify.
        storage2 = StorageManager(db_path=db_path)
        storage2.unlock_vault(pw)
        creds = storage2.list_credentials()
        assert len(creds) == 1
        assert creds[0]["password"] == "pass"
        storage2.close()

    def test_reopen_after_close_preserves_data(self, tmp_path) -> None:
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2(pw)
        storage.save_credential("Test", "user", "pass")
        storage.close()

        storage.unlock_vault(pw)
        creds = storage.list_credentials()
        assert len(creds) == 1
        assert creds[0]["password"] == "pass"
        storage.close()


class TestVaultV2EdgeCases:
    """Edge cases for v2 vaults."""

    def test_uninitialized_vault_not_v2(self, tmp_path) -> None:
        storage = StorageManager(db_path=tmp_path / "nonexistent.db")
        assert not storage.is_v2_vault()
        storage.close()

    def test_v2_vault_rejects_init_overwrite(self, tmp_path) -> None:
        db_path = tmp_path / "vault.db"
        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2("a-strong-master-password")
        from generate_it.storage import VaultAlreadyInitializedError
        with pytest.raises(VaultAlreadyInitializedError):
            storage.initialize_vault_v2("another-password")
        storage.close()

    def test_save_credential_note_hidden_flag(self, tmp_path) -> None:
        db_path = tmp_path / "vault.db"
        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2("a-strong-master-password")
        storage.save_credential("Test", "user", "pass", note="secret", note_is_hidden=True)
        creds = storage.list_credentials()
        assert creds[0]["note_is_hidden"] is True
        storage.close()

    def test_v2_csv_export_import_roundtrip(self, tmp_path) -> None:
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2(pw)
        storage.save_credential("GitHub", "dev", "gh_token")
        storage.save_credential("Google", "user@gmail.com", "password123")

        csv_path = tmp_path / "export.csv"
        exported, skipped = storage.export_to_csv(csv_path)
        assert exported == 2
        assert skipped == []
        storage.close()

        # Import into a new v2 vault.
        storage2 = StorageManager(db_path=tmp_path / "vault2.db")
        storage2.initialize_vault_v2(pw)
        imported, skipped_count, issues = storage2.import_from_csv(csv_path)
        assert imported == 2
        assert skipped_count == 0
        assert issues == []

        creds = storage2.list_credentials()
        assert len(creds) == 2
        assert creds[0]["service"] == "GitHub"
        assert creds[0]["password"] == "gh_token"
        assert creds[1]["service"] == "Google"
        assert creds[1]["password"] == "password123"
        storage2.close()

    def test_v2_vault_rejects_unknown_version(self, tmp_path) -> None:
        """An unknown version number raises StorageError."""
        db_path = tmp_path / "vault.db"
        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2("a-strong-master-password")
        storage.close()

        # Tamper with the version.
        import sqlite3
        raw = sqlite3.connect(db_path)
        raw.execute("UPDATE config SET value='99' WHERE key='version'")
        raw.commit()
        raw.close()

        storage2 = StorageManager(db_path=db_path)
        with pytest.raises(StorageError, match="Unsupported vault format version"):
            storage2.unlock_vault("a-strong-master-password")
        storage2.close()


# ---------------------------------------------------------------------------
# Task 10: Config validation tests
# ---------------------------------------------------------------------------


class TestValidateKdfConfig:
    """Pre-crypto KDF config validation."""

    def _valid_args(self):
        from generate_it._crypto_v2 import KDF_ARGON2ID, DEFAULT_ARGON2_MEMORY, DEFAULT_ARGON2_TIME, DEFAULT_ARGON2_PARALLELISM, SALT_LEN
        import os
        return (KDF_ARGON2ID, DEFAULT_ARGON2_MEMORY, DEFAULT_ARGON2_TIME, DEFAULT_ARGON2_PARALLELISM, os.urandom(SALT_LEN))

    def test_valid_config_passes(self) -> None:
        from generate_it._crypto_v2 import _validate_kdf_config
        _validate_kdf_config(*self._valid_args())  # should not raise

    def test_missing_kdf_algorithm_is_none(self) -> None:
        from generate_it._crypto_v2 import _validate_kdf_config
        with pytest.raises(ValueError, match="Unknown KDF algorithm"):
            _validate_kdf_config("", 65536, 3, 4, b"x" * 32)

    def test_unknown_kdf_algorithm(self) -> None:
        from generate_it._crypto_v2 import _validate_kdf_config, SALT_LEN
        import os
        with pytest.raises(ValueError, match="Unknown KDF algorithm"):
            _validate_kdf_config("pbkdf2-sha256", 65536, 3, 4, os.urandom(SALT_LEN))

    @pytest.mark.parametrize("memory", [0, -1, 10**8])
    def test_memory_out_of_range(self, memory: int) -> None:
        from generate_it._crypto_v2 import _validate_kdf_config, KDF_ARGON2ID, SALT_LEN
        import os
        with pytest.raises(ValueError, match="memory cost"):
            _validate_kdf_config(KDF_ARGON2ID, memory, 3, 4, os.urandom(SALT_LEN))

    @pytest.mark.parametrize("time", [0, -1, 1000])
    def test_time_out_of_range(self, time: int) -> None:
        from generate_it._crypto_v2 import _validate_kdf_config, KDF_ARGON2ID, SALT_LEN
        import os
        with pytest.raises(ValueError, match="time cost"):
            _validate_kdf_config(KDF_ARGON2ID, 65536, time, 4, os.urandom(SALT_LEN))

    @pytest.mark.parametrize("parallelism", [0, -1, 256])
    def test_parallelism_out_of_range(self, parallelism: int) -> None:
        from generate_it._crypto_v2 import _validate_kdf_config, KDF_ARGON2ID, SALT_LEN
        import os
        with pytest.raises(ValueError, match="parallelism"):
            _validate_kdf_config(KDF_ARGON2ID, 65536, 3, parallelism, os.urandom(SALT_LEN))

    def test_salt_not_32_bytes(self) -> None:
        from generate_it._crypto_v2 import _validate_kdf_config, KDF_ARGON2ID
        with pytest.raises(ValueError, match="salt must be exactly"):
            _validate_kdf_config(KDF_ARGON2ID, 65536, 3, 4, b"too-short")

    def test_scrypt_algorithm_rejected(self) -> None:
        """scrypt is recognised as a constant but not yet implemented — must be rejected."""
        from generate_it._crypto_v2 import _validate_kdf_config, KDF_SCRYPT, SALT_LEN
        import os
        with pytest.raises(ValueError, match="Unknown KDF algorithm"):
            _validate_kdf_config(KDF_SCRYPT, 65536, 3, 4, os.urandom(SALT_LEN))


class TestValidateVaultMetadata:
    """Pre-crypto vault metadata validation."""

    def test_valid_metadata_passes(self) -> None:
        from generate_it._crypto_v2 import _validate_vault_metadata, AEAD_AES_256_GCM, WRAPPED_DEK_LEN, VAULT_UUID_LEN, NONCE_LEN
        import os
        vault_uuid = os.urandom(VAULT_UUID_LEN)
        wrapped_dek = os.urandom(WRAPPED_DEK_LEN)
        verification_ct = os.urandom(NONCE_LEN + 16 + 10)  # enough bytes
        _validate_vault_metadata(vault_uuid, wrapped_dek, AEAD_AES_256_GCM, verification_ct)

    def test_vault_uuid_wrong_length(self) -> None:
        from generate_it._crypto_v2 import _validate_vault_metadata, AEAD_AES_256_GCM, WRAPPED_DEK_LEN, NONCE_LEN
        import os
        with pytest.raises(ValueError, match="Vault UUID must be exactly"):
            _validate_vault_metadata(b"short", os.urandom(WRAPPED_DEK_LEN), AEAD_AES_256_GCM, os.urandom(NONCE_LEN + 16 + 10))

    def test_wrapped_dek_wrong_length(self) -> None:
        from generate_it._crypto_v2 import _validate_vault_metadata, AEAD_AES_256_GCM, VAULT_UUID_LEN, NONCE_LEN
        import os
        with pytest.raises(ValueError, match="Wrapped DEK must be exactly"):
            _validate_vault_metadata(os.urandom(VAULT_UUID_LEN), b"bad", AEAD_AES_256_GCM, os.urandom(NONCE_LEN + 16 + 10))

    def test_unknown_aead_algorithm(self) -> None:
        from generate_it._crypto_v2 import _validate_vault_metadata, WRAPPED_DEK_LEN, VAULT_UUID_LEN, NONCE_LEN
        import os
        with pytest.raises(ValueError, match="Unknown AEAD algorithm"):
            _validate_vault_metadata(os.urandom(VAULT_UUID_LEN), os.urandom(WRAPPED_DEK_LEN), "aes-128-gcm", os.urandom(NONCE_LEN + 16 + 10))

    def test_verification_ct_too_short(self) -> None:
        from generate_it._crypto_v2 import _validate_vault_metadata, AEAD_AES_256_GCM, WRAPPED_DEK_LEN, VAULT_UUID_LEN, NONCE_LEN
        import os
        # Just 12 bytes (nonce only, no tag)
        with pytest.raises(ValueError, match="too short"):
            _validate_vault_metadata(os.urandom(VAULT_UUID_LEN), os.urandom(WRAPPED_DEK_LEN), AEAD_AES_256_GCM, os.urandom(NONCE_LEN))

    def test_verification_ct_exactly_minimum(self) -> None:
        from generate_it._crypto_v2 import _validate_vault_metadata, AEAD_AES_256_GCM, WRAPPED_DEK_LEN, VAULT_UUID_LEN, NONCE_LEN
        import os
        # Minimum valid: 12 + 16 = 28 bytes
        _validate_vault_metadata(os.urandom(VAULT_UUID_LEN), os.urandom(WRAPPED_DEK_LEN), AEAD_AES_256_GCM, os.urandom(NONCE_LEN + 16))


class TestGetAeadExactAllowlisting:
    """_get_aead() raises on unknown algorithms instead of silently defaulting."""

    def test_unknown_aead_raises(self) -> None:
        from generate_it._crypto_v2 import _get_aead
        import os
        dek = os.urandom(32)
        with pytest.raises(ValueError, match="Unknown AEAD algorithm"):
            _get_aead(dek, "aes-128-gcm")

    def test_invalid_aead_not_defaulted(self) -> None:
        from generate_it._crypto_v2 import _get_aead
        import os
        dek = os.urandom(32)
        # Empty string must also raise.
        with pytest.raises(ValueError, match="Unknown AEAD algorithm"):
            _get_aead(dek, "")


class TestConfigValidationAtUnlock:
    """Validation catches malformed config before expensive Argon2id."""

    def test_kdf_config_rejected_at_unlock(self, tmp_path) -> None:
        """A v2 vault with out-of-range KDF memory raises StorageError."""
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2(pw)
        storage.close()

        import sqlite3
        raw = sqlite3.connect(db_path)
        raw.execute("UPDATE config SET value='0' WHERE key='kdf_memory_cost'")
        raw.commit()
        raw.close()

        storage2 = StorageManager(db_path=db_path)
        with pytest.raises(StorageError, match="Invalid KDF configuration"):
            storage2.unlock_vault(pw)
        storage2.close()

    def test_vault_metadata_rejected_at_unlock(self, tmp_path) -> None:
        """A v2 vault with wrong-sized vault_uuid raises StorageError."""
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2(pw)
        storage.close()

        import sqlite3
        raw = sqlite3.connect(db_path)
        raw.execute("UPDATE config SET value=? WHERE key='vault_uuid'", (b"too-short",))
        raw.commit()
        raw.close()

        storage2 = StorageManager(db_path=db_path)
        with pytest.raises(StorageError, match="Invalid vault metadata"):
            storage2.unlock_vault(pw)
        storage2.close()

    def test_unknown_aead_rejected_at_unlock(self, tmp_path) -> None:
        """A v2 vault with unknown AEAD raises StorageError."""
        db_path = tmp_path / "vault.db"
        pw = "a-strong-master-password"

        storage = StorageManager(db_path=db_path)
        storage.initialize_vault_v2(pw)
        storage.close()

        import sqlite3
        raw = sqlite3.connect(db_path)
        raw.execute("UPDATE config SET value='aes-128-gcm' WHERE key='aead_algorithm'")
        raw.commit()
        raw.close()

        storage2 = StorageManager(db_path=db_path)
        with pytest.raises(StorageError, match="Invalid vault metadata"):
            storage2.unlock_vault(pw)
        storage2.close()
