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


# ── Phase 4, Task 2: context manager lifecycle ──────────────────────

def test_storage_manager_context_closes_and_locks(tmp_path) -> None:
    """``with StorageManager(...)`` closes the database and locks the vault on exit."""
    manager = StorageManager(db_path=tmp_path / "vault.db")
    with manager as storage:
        assert storage is manager
        storage.initialize_vault("master")
        storage.save_credential("GitHub", "dev", "secret")
    assert manager._db_connection is None
    assert manager._fernet is None

    fresh = StorageManager(db_path=tmp_path / "vault.db")
    fresh.unlock_vault("master")
    assert [item["password"] for item in fresh.list_credentials()] == ["secret"]
    fresh.close()


def test_storage_manager_context_does_not_suppress_errors(tmp_path) -> None:
    """``with StorageManager(...)`` closes even when the body raises."""
    manager = StorageManager(db_path=tmp_path / "vault.db")
    with pytest.raises(RuntimeError, match="boom"):
        with manager:
            raise RuntimeError("boom")
    assert manager._db_connection is None
    assert manager._fernet is None


# ── Phase 4, Task 3: centralized decryption + narrow corruption handling ──

def test_list_credentials_corrupted_row_placeholder(tmp_path) -> None:
    """Corrupted ciphertext yields <DECRYPTION_ERROR> placeholders, not a crash."""
    db_path = tmp_path / "vault.db"

    storage = StorageManager(db_path=db_path)
    storage.initialize_vault("master")
    storage.save_credential("GitHub", "dev", "secret", note="a note")
    storage.close()

    # Corrupt the encrypted_password column directly via raw sqlite3.
    import sqlite3
    raw = sqlite3.connect(db_path)
    raw.execute("UPDATE credentials SET encrypted_password = ? WHERE service = ?",
                (b"!!not-valid-fernet-token!!", "GitHub"))
    raw.commit()
    raw.close()

    storage = StorageManager(db_path=db_path)
    storage.unlock_vault("master")
    results = storage.list_credentials()
    storage.close()

    assert len(results) == 1
    assert results[0]["service"] == "GitHub"
    assert results[0]["password"] == "<DECRYPTION_ERROR>"
    assert results[0]["note"] == "<DECRYPTION_ERROR>"


def test_export_to_csv_skips_corrupted_row(tmp_path) -> None:
    """Corrupted ciphertext is skipped during export with a stable, non-leaking label."""
    db_path = tmp_path / "vault.db"
    csv_path = tmp_path / "out.csv"

    storage = StorageManager(db_path=db_path)
    storage.initialize_vault("master")
    storage.save_credential("GitHub", "dev", "secret")
    storage.close()

    import sqlite3
    raw = sqlite3.connect(db_path)
    raw.execute("UPDATE credentials SET encrypted_password = ? WHERE service = ?",
                (b"!!not-valid-fernet-token!!", "GitHub"))
    raw.commit()
    raw.close()

    storage = StorageManager(db_path=db_path)
    storage.unlock_vault("master")
    exported, skipped = storage.export_to_csv(csv_path, export_format="generic")
    storage.close()

    assert exported == 0
    assert len(skipped) == 1
    assert skipped[0]["service"] == "GitHub"
    assert skipped[0]["username"] == "dev"
    assert skipped[0]["error"] == "Unable to decrypt credential"

    # The CSV body must contain only the header row (no data).
    lines = csv_path.read_text().strip().splitlines()
    assert len(lines) == 1  # header only


def test_list_credentials_propagates_unexpected_error(monkeypatch, tmp_path) -> None:
    """Unexpected errors are not swallowed — only known crypto/corruption errors are."""
    db_path = tmp_path / "vault.db"

    storage = StorageManager(db_path=db_path)
    storage.initialize_vault("master")
    storage.save_credential("GitHub", "dev", "secret")
    storage.close()

    # Patch the yet-to-exist internal helper so it raises a non-crypto error.
    monkeypatch.setattr(
        "generate_it.storage.StorageManager._decrypt_credential_fields",
        lambda self, row, fernet: (_ for _ in ()).throw(RuntimeError("unexpected")),
    )

    storage = StorageManager(db_path=db_path)
    storage.unlock_vault("master")
    with pytest.raises(RuntimeError, match="unexpected"):
        storage.list_credentials()
    storage.close()


# ── Phase 4, Task 4: bounded SQLite busy timeout ──────────────────────

def test_storage_connection_uses_busy_timeout(tmp_path) -> None:
    """New connections get a 5-second busy timeout so transient locks wait."""
    storage = StorageManager(db_path=tmp_path / "vault.db")
    try:
        conn = storage._get_conn()
        timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
        assert timeout == 5_000
    finally:
        storage.close()


# ── Phase 6, Task 1: centralized credential encryption ─────────────────

def test_encrypt_credential_fields_roundtrip(tmp_path) -> None:
    """Encrypt-then-decrypt yields the original plaintext."""
    storage = StorageManager(db_path=tmp_path / "vault.db")
    storage.initialize_vault("master")

    password_ct, note_ct = storage._encrypt_credential_fields(
        storage._fernet, "my-password", "my-note"
    )
    assert isinstance(password_ct, bytes)
    assert isinstance(note_ct, bytes)

    # Verify roundtrip via the existing decrypt helper
    import sqlite3
    conn = storage._get_conn()
    conn.execute(
        "INSERT INTO credentials (service, username, encrypted_password, encrypted_note)"
        " VALUES (?, ?, ?, ?)",
        ("test", "user", password_ct, note_ct),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM credentials WHERE service='test'").fetchone()
    pw, note = storage._decrypt_credential_fields(row, storage._fernet)
    assert pw == "my-password"
    assert note == "my-note"
    storage.close()


def test_encrypt_credential_fields_empty_note(tmp_path) -> None:
    """Empty note produces None ciphertext (same behavior as current inline)."""
    storage = StorageManager(db_path=tmp_path / "vault.db")
    storage.initialize_vault("master")

    password_ct, note_ct = storage._encrypt_credential_fields(
        storage._fernet, "pw", ""
    )
    assert isinstance(password_ct, bytes)
    assert note_ct is None
    storage.close()
