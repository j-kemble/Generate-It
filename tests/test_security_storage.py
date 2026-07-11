"""Security regression tests for the storage layer master password policy."""

from __future__ import annotations

import pytest

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
