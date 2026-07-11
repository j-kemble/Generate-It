"""Security regression tests for the storage layer master password policy."""

from __future__ import annotations

import pytest
import os
import stat

from generate_it.storage import StorageError


class TestInitializeRejectsWeakPasswords:
    """Task 1.5: Master password policy enforcement in initialize_vault()."""

    def test_initialize_rejects_empty_password(self, temp_storage) -> None:
        with pytest.raises(StorageError) as exc:
            temp_storage.initialize_vault("")
        assert any(
            word in str(exc.value).lower()
            for word in ("weak", "empty")
        )

    def test_initialize_rejects_short_password(self, temp_storage) -> None:
        with pytest.raises(StorageError) as exc:
            temp_storage.initialize_vault("short")  # 5 chars
        assert any(
            word in str(exc.value).lower()
            for word in ("12", "characters")
        )

    def test_initialize_rejects_4char_password(self, temp_storage) -> None:
        with pytest.raises(StorageError):
            temp_storage.initialize_vault("1234")

    def test_initialize_rejects_common_password(self, temp_storage) -> None:
        with pytest.raises(StorageError):
            temp_storage.initialize_vault("password")

    def test_initialize_accepts_strong_password(self, temp_storage) -> None:
        temp_storage.initialize_vault("a-strong-master-password-for-tests")
        assert temp_storage.vault_exists()

    def test_initialize_accepts_long_passphrase(self, temp_storage) -> None:
        long_pass = "correct horse battery staple with extra words"
        temp_storage.initialize_vault(long_pass)
        assert temp_storage.vault_exists()

    def test_legacy_vault_unlock_unchanged(self, temp_storage_initialized) -> None:
        # Pre-existing vault still unlocks
        creds = temp_storage_initialized.list_credentials()
        assert isinstance(creds, list)


class TestVaultPermissions:
    """Task 2.1: Vault file and directory permissions must be owner-only."""

    def test_data_directory_is_0700(self, tmp_path):
        """Custom data directory must be created with 0700 permissions."""
        from generate_it.storage import StorageManager
        data_dir = tmp_path / "secure_data"
        db_path = data_dir / "vault.db"
        # Only test on POSIX
        if not hasattr(os, "chmod"):
            pytest.skip("POSIX permissions not supported on this platform")

        storage = StorageManager(db_path=db_path)
        try:
            mode = stat.S_IMODE(os.stat(data_dir).st_mode)
            assert mode == 0o700, f"Expected 0700, got {oct(mode)}"
        finally:
            storage.close()

    def test_database_is_0600_after_creation(self, tmp_path):
        """Database file must be 0600 after vault initialization."""
        if not hasattr(os, "chmod"):
            pytest.skip("POSIX permissions not supported on this platform")

        from generate_it.storage import StorageManager
        db_path = tmp_path / "vault.db"
        storage = StorageManager(db_path=db_path)
        try:
            storage.initialize_vault("a-strong-master-password")
            mode = stat.S_IMODE(os.stat(db_path).st_mode)
            assert mode == 0o600, f"Expected 0600, got {oct(mode)}"
        finally:
            storage.close()

    def test_existing_overly_permissive_db_is_tightened(self, tmp_path):
        """An existing 0644 database must be tightened to 0600 on open."""
        if not hasattr(os, "chmod"):
            pytest.skip("POSIX permissions not supported on this platform")

        from generate_it.storage import StorageManager
        db_path = tmp_path / "vault.db"
        storage = StorageManager(db_path=db_path)
        storage.initialize_vault("a-strong-master-password")
        storage.close()

        # Make it world-readable
        os.chmod(str(db_path), 0o644)
        mode_before = stat.S_IMODE(os.stat(db_path).st_mode)
        assert mode_before == 0o644

        # Reopen — must tighten
        storage2 = StorageManager(db_path=db_path)
        try:
            storage2.unlock_vault("a-strong-master-password")
            mode_after = stat.S_IMODE(os.stat(db_path).st_mode)
            assert mode_after == 0o600, f"Expected 0600 after reopen, got {oct(mode_after)}"
        finally:
            storage2.close()


class TestExportSecurity:
    """Task 2.2: Export operations must be atomic and private."""

    def test_new_export_is_0600(self, tmp_path):
        """New exports must be created with 0600 permissions."""
        if not hasattr(os, "chmod"):
            pytest.skip("POSIX permissions not supported on this platform")

        from generate_it.storage import StorageManager
        db_path = tmp_path / "vault.db"
        csv_path = tmp_path / "export.csv"

        storage = StorageManager(db_path=db_path)
        try:
            storage.initialize_vault("a-strong-master-password")
            storage.save_credential("GitHub", "dev", "secret123456")
            exported, skipped = storage.export_to_csv(csv_path)
            assert exported == 1
            assert skipped == []

            mode = stat.S_IMODE(os.stat(csv_path).st_mode)
            assert mode == 0o600, f"Export permissions: expected 0600, got {oct(mode)}"
        finally:
            storage.close()

    def test_export_rejects_symlink(self, tmp_path):
        """Export must reject symlink targets."""
        from generate_it.storage import StorageManager, StorageError
        db_path = tmp_path / "vault.db"
        real_csv = tmp_path / "real.csv"
        symlink_csv = tmp_path / "link.csv"
        real_csv.write_text("")  # Create the real file
        symlink_csv.symlink_to(real_csv)

        storage = StorageManager(db_path=db_path)
        try:
            storage.initialize_vault("a-strong-master-password")
            storage.save_credential("GitHub", "dev", "secret123456")
            with pytest.raises(StorageError, match="symlink"):
                storage.export_to_csv(symlink_csv)
        finally:
            storage.close()

    def test_export_rejects_non_regular_file(self, tmp_path):
        """Export must reject non-regular file targets like directories."""
        from generate_it.storage import StorageManager, StorageError
        db_path = tmp_path / "vault.db"
        dir_path = tmp_path / "adir"
        dir_path.mkdir()

        storage = StorageManager(db_path=db_path)
        try:
            storage.initialize_vault("a-strong-master-password")
            storage.save_credential("GitHub", "dev", "secret123456")
            with pytest.raises(StorageError, match="regular file"):
                storage.export_to_csv(dir_path)
        finally:
            storage.close()


class TestKdfValidation:
    """Task 4.2: Malformed KDF parameters must be rejected, not silently ignored."""

    def test_absent_kdf_params_use_legacy(self, tmp_path):
        """Vaults without persisted params unlock with legacy defaults."""
        from generate_it.storage import StorageManager
        import sqlite3
        import os
        db_path = tmp_path / "vault.db"
        storage = StorageManager(db_path=db_path)

        # Build a vault whose verification token was actually derived at
        # legacy 100k, then manually delete the pbkdf2_iterations row to
        # simulate the stored form of a real pre-persistence vault.
        password = "legacy-vault-without-params"
        salt = os.urandom(32)
        key = storage._derive_key(password, salt, 100_000)
        fernet = __import__("cryptography.fernet", fromlist=["Fernet"]).Fernet(key)
        verification = fernet.encrypt(b"VERIFICATION_TOKEN")

        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE config (key TEXT PRIMARY KEY, value BLOB)")
        conn.execute("INSERT INTO config (key, value) VALUES (?, ?)", ("salt", salt))
        conn.execute("INSERT INTO config (key, value) VALUES (?, ?)", ("verification", verification))
        conn.commit()
        conn.close()

        storage.close()

        # pbkdf2_iterations is absent -> falls back to legacy 100_000.
        storage2 = StorageManager(db_path=db_path)
        try:
            storage2.unlock_vault(password)
            assert storage2._fernet is not None
        finally:
            storage2.close()

    def test_zero_iterations_rejected(self, tmp_path):
        """Zero iterations must be rejected as corruption."""
        from generate_it.storage import StorageManager, StorageError
        import sqlite3
        db_path = tmp_path / "vault.db"
        storage = StorageManager(db_path=db_path)
        storage.initialize_vault("a-strong-master-password")
        storage.close()

        raw = sqlite3.connect(db_path)
        raw.execute("UPDATE config SET value='0' WHERE key='pbkdf2_iterations'")
        raw.commit()
        raw.close()

        storage2 = StorageManager(db_path=db_path)
        try:
            with pytest.raises(StorageError, match="pbkdf2"):
                storage2.unlock_vault("a-strong-master-password")
        finally:
            storage2.close()

    def test_negative_iterations_rejected(self, tmp_path):
        """Negative iterations must be rejected."""
        from generate_it.storage import StorageManager, StorageError
        import sqlite3
        db_path = tmp_path / "vault.db"
        storage = StorageManager(db_path=db_path)
        storage.initialize_vault("a-strong-master-password")
        storage.close()

        raw = sqlite3.connect(db_path)
        raw.execute("UPDATE config SET value='-100' WHERE key='pbkdf2_iterations'")
        raw.commit()
        raw.close()

        storage2 = StorageManager(db_path=db_path)
        try:
            with pytest.raises(StorageError, match="pbkdf2"):
                storage2.unlock_vault("a-strong-master-password")
        finally:
            storage2.close()

    def test_malformed_iterations_rejected(self, tmp_path):
        """Malformed iteration values must raise StorageError."""
        from generate_it.storage import StorageManager, StorageError
        import sqlite3
        db_path = tmp_path / "vault.db"
        storage = StorageManager(db_path=db_path)
        storage.initialize_vault("a-strong-master-password")
        storage.close()

        raw = sqlite3.connect(db_path)
        raw.execute("UPDATE config SET value='not_a_number' WHERE key='pbkdf2_iterations'")
        raw.commit()
        raw.close()

        storage2 = StorageManager(db_path=db_path)
        try:
            with pytest.raises(StorageError, match="malformed"):
                storage2.unlock_vault("a-strong-master-password")
        finally:
            storage2.close()

    def test_excessive_iterations_rejected(self, tmp_path):
        """Excessive iteration count must be rejected."""
        from generate_it.storage import StorageManager, StorageError
        import sqlite3
        db_path = tmp_path / "vault.db"
        storage = StorageManager(db_path=db_path)
        storage.initialize_vault("a-strong-master-password")
        storage.close()

        raw = sqlite3.connect(db_path)
        raw.execute("UPDATE config SET value='50000000' WHERE key='pbkdf2_iterations'")
        raw.commit()
        raw.close()

        storage2 = StorageManager(db_path=db_path)
        try:
            with pytest.raises(StorageError, match="exceed"):
                storage2.unlock_vault("a-strong-master-password")
        finally:
            storage2.close()
