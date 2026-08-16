from __future__ import annotations

import pytest

from generate_it._crypto_v2 import MAX_NOTE_BYTES, MAX_PASSWORD_BYTES
from generate_it.storage import StorageError, StorageManager


@pytest.mark.parametrize("initializer", ["initialize_vault", "initialize_vault_v2"])
def test_save_accepts_password_at_byte_limit(tmp_path, initializer: str) -> None:
    storage = StorageManager(db_path=tmp_path / f"{initializer}.db")
    try:
        getattr(storage, initializer)("A-Strong-Passw0rd!")
        storage.save_credential("Service", "user", "p" * MAX_PASSWORD_BYTES)
    finally:
        storage.close()


@pytest.mark.parametrize("initializer", ["initialize_vault", "initialize_vault_v2"])
def test_save_rejects_password_above_byte_limit(tmp_path, initializer: str) -> None:
    storage = StorageManager(db_path=tmp_path / f"{initializer}.db")
    try:
        getattr(storage, initializer)("A-Strong-Passw0rd!")
        with pytest.raises(StorageError, match="password exceeds 1024 bytes"):
            storage.save_credential("Service", "user", "p" * (MAX_PASSWORD_BYTES + 1))
    finally:
        storage.close()


@pytest.mark.parametrize("initializer", ["initialize_vault", "initialize_vault_v2"])
def test_save_accepts_note_at_byte_limit(tmp_path, initializer: str) -> None:
    storage = StorageManager(db_path=tmp_path / f"{initializer}.db")
    try:
        getattr(storage, initializer)("A-Strong-Passw0rd!")
        storage.save_credential("Service", "user", "password", "n" * MAX_NOTE_BYTES)
    finally:
        storage.close()


@pytest.mark.parametrize("initializer", ["initialize_vault", "initialize_vault_v2"])
def test_save_rejects_note_above_byte_limit(tmp_path, initializer: str) -> None:
    storage = StorageManager(db_path=tmp_path / f"{initializer}.db")
    try:
        getattr(storage, initializer)("A-Strong-Passw0rd!")
        with pytest.raises(StorageError, match="note exceeds 65536 bytes"):
            storage.save_credential("Service", "user", "password", "n" * (MAX_NOTE_BYTES + 1))
    finally:
        storage.close()


def test_initialize_vault_rejects_oversized_master_password(tmp_path) -> None:
    storage = StorageManager(db_path=tmp_path / "master.db")
    try:
        with pytest.raises(StorageError, match="password exceeds 1024 bytes"):
            storage.initialize_vault_v2("P" * (MAX_PASSWORD_BYTES + 1))
    finally:
        storage.close()


def test_multibyte_values_are_checked_by_encoded_byte_length(temp_storage_initialized) -> None:
    with pytest.raises(StorageError, match="password exceeds 1024 bytes"):
        temp_storage_initialized.save_credential("Service", "user", "é" * (MAX_PASSWORD_BYTES // 2 + 1))

    with pytest.raises(StorageError, match="note exceeds 65536 bytes"):
        temp_storage_initialized.save_credential("Other", "user", "password", "é" * (MAX_NOTE_BYTES // 2 + 1))


def test_update_rejects_oversized_fields(temp_storage_initialized) -> None:
    cred_id = temp_storage_initialized.save_credential("Service", "user", "password")
    with pytest.raises(StorageError, match="password exceeds 1024 bytes"):
        temp_storage_initialized.update_credential(
            cred_id, "Service", "user", "p" * (MAX_PASSWORD_BYTES + 1)
        )
    with pytest.raises(StorageError, match="note exceeds 65536 bytes"):
        temp_storage_initialized.update_credential(
            cred_id, "Service", "user", "password", "n" * (MAX_NOTE_BYTES + 1)
        )


@pytest.mark.parametrize("response", ["y", "Y", "yes", " YES "])
def test_aad_migration_requires_explicit_yes(monkeypatch, response: str) -> None:
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from generate_it import tui_security

    storage = MagicMock(_vault_version=2, _aad_version=2)
    state = SimpleNamespace(storage=storage, message="")
    monkeypatch.setattr(tui_security.tui_modal, "_run_modal", lambda *args, **kwargs: response)
    tui_security._maybe_migrate_aad_v4(None, None, state)
    storage.migrate_aad_to_v4.assert_called_once()


@pytest.mark.parametrize("response", [None, "", "n", "no", "anything"])
def test_aad_migration_cancels_without_explicit_yes(monkeypatch, response: str | None) -> None:
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from generate_it import tui_security

    storage = MagicMock(_vault_version=2, _aad_version=2)
    state = SimpleNamespace(storage=storage, message="")
    monkeypatch.setattr(tui_security.tui_modal, "_run_modal", lambda *args, **kwargs: response)
    tui_security._maybe_migrate_aad_v4(None, None, state)
    storage.migrate_aad_to_v4.assert_not_called()
    assert state.message == "AAD upgrade deferred."


def test_identity_validation_returns_zero_width_stripped_keys() -> None:
    from generate_it.identity import validate_identity

    assert validate_identity("Gmail\u200b", "user") == ("gmail", "user")
