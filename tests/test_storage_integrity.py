"""Vault-integrity regression tests."""

from __future__ import annotations

import pytest

from generate_it.storage import StorageError, StorageManager


def test_initialize_existing_vault_preserves_original_credentials(tmp_path) -> None:
    db_path = tmp_path / "vault.db"
    original_password = "original-master-password"

    original = StorageManager(db_path=db_path)
    original.initialize_vault(original_password)
    original.save_credential("GitHub", "dev", "original-secret")
    original.close()

    attempted_reinitialization = StorageManager(db_path=db_path)
    try:
        with pytest.raises(StorageError) as error:
            attempted_reinitialization.initialize_vault("replacement-master-password")
    finally:
        attempted_reinitialization.close()

    assert type(error.value).__name__ == "VaultAlreadyInitializedError"

    recovered = StorageManager(db_path=db_path)
    try:
        recovered.unlock_vault(original_password)
        credentials = recovered.list_credentials()
    finally:
        recovered.close()

    assert len(credentials) == 1
    assert credentials[0]["service"] == "GitHub"
    assert credentials[0]["username"] == "dev"
    assert credentials[0]["password"] == "original-secret"
    assert credentials[0]["note"] == ""
