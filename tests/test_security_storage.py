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
