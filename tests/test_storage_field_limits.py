from __future__ import annotations

import pytest

from generate_it._crypto_v2 import MAX_NOTE_BYTES, MAX_PASSWORD_BYTES
from generate_it.storage import StorageError, StorageManager


@pytest.mark.parametrize("initializer", ["initialize_vault", "initialize_vault_v2"])
def test_save_rejects_oversized_password_for_each_vault_version(
    tmp_path, initializer: str
) -> None:
    storage = StorageManager(db_path=tmp_path / f"{initializer}.db")
    try:
        getattr(storage, initializer)("A-Strong-Passw0rd!")
        with pytest.raises(StorageError, match="password plaintext exceeds 1024 bytes"):
            storage.save_credential("Service", "user", "p" * (MAX_PASSWORD_BYTES + 1))
    finally:
        storage.close()


@pytest.mark.parametrize("initializer", ["initialize_vault", "initialize_vault_v2"])
def test_save_rejects_oversized_note_for_each_vault_version(
    tmp_path, initializer: str
) -> None:
    storage = StorageManager(db_path=tmp_path / f"{initializer}.db")
    try:
        getattr(storage, initializer)("A-Strong-Passw0rd!")
        with pytest.raises(StorageError, match="note plaintext exceeds 65536 bytes"):
            storage.save_credential("Service", "user", "password", "n" * (MAX_NOTE_BYTES + 1))
    finally:
        storage.close()
