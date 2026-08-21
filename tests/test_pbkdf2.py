"""Backward-compatibility tests for Phase 2 PBKDF2 hardening.

Covers: new vaults use 480k iterations + 32-byte salt, and legacy vaults
(16-byte salt, no persisted params) still unlock.
"""

import os
import sqlite3

from generate_it.storage import StorageManager


def _read_config(db_path, key):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        cur.execute("SELECT value FROM config WHERE key=?", (key,))
        row = cur.fetchone()
        if row is None:
            return None
        raw = row["value"]
        if isinstance(raw, bytes):
            return raw.decode("utf-8")
        return str(raw)
    finally:
        conn.close()


def test_new_vault_uses_480k_and_32_byte_salt(tmp_path):
    db = tmp_path / "vault.db"
    sm = StorageManager(db_path=db)
    sm.initialize_vault("Correct horse battery staple 1!")

    # Salt length is 32 bytes.
    conn = sqlite3.connect(str(db))
    try:
        raw_salt = conn.execute("SELECT value FROM config WHERE key='salt'").fetchone()[0]
    finally:
        conn.close()
    assert len(raw_salt) == 32

    # Config persists the new parameters.
    assert _read_config(str(db), "pbkdf2_iterations") == "480000"
    assert _read_config(str(db), "salt_length") == "32"

    # The vault unlocks with the correct password.
    sm2 = StorageManager(db_path=db)
    sm2.unlock_vault("Correct horse battery staple 1!")
    assert sm2.vault_exists()


def test_legacy_vault_no_params_unlocks(tmp_path):
    """Hand-built legacy vault: 16-byte salt, no pbkdf2_iterations stored."""
    db = tmp_path / "legacy.db"
    sm = StorageManager(db_path=db)

    password = "Legacy-Pass1!"
    salt = os.urandom(16)
    key = sm._derive_key(password, salt, 100_000)  # legacy vault used 100k
    fernet = __import__("cryptography.fernet", fromlist=["Fernet"]).Fernet(key)
    verification = fernet.encrypt(b"VERIFICATION_TOKEN")

    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE config (key TEXT PRIMARY KEY, value BLOB)")
    conn.execute("INSERT INTO config (key, value) VALUES (?, ?)", ("salt", salt))
    conn.execute("INSERT INTO config (key, value) VALUES (?, ?)", ("verification", verification))
    conn.commit()
    conn.close()

    # pbkdf2_iterations is absent -> falls back to legacy 100_000.
    assert _read_config(str(db), "pbkdf2_iterations") is None

    sm2 = StorageManager(db_path=db)
    sm2.unlock_vault(password)
    assert sm2.vault_exists()


def test_legacy_vault_explicit_100k_unlocks(tmp_path):
    """Legacy vault that explicitly stored pbkdf2_iterations=100000."""
    db = tmp_path / "legacy2.db"
    sm = StorageManager(db_path=db)

    password = "explicit-legacy"
    salt = os.urandom(16)
    key = sm._derive_key(password, salt, 100_000)
    fernet = __import__("cryptography.fernet", fromlist=["Fernet"]).Fernet(key)
    verification = fernet.encrypt(b"VERIFICATION_TOKEN")

    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE config (key TEXT PRIMARY KEY, value BLOB)")
    conn.execute("INSERT INTO config (key, value) VALUES (?, ?)", ("salt", salt))
    conn.execute("INSERT INTO config (key, value) VALUES (?, ?)", ("verification", verification))
    conn.execute("INSERT INTO config (key, value) VALUES (?, ?)", ("pbkdf2_iterations", "100000"))
    conn.commit()
    conn.close()

    assert _read_config(str(db), "pbkdf2_iterations") == "100000"

    sm2 = StorageManager(db_path=db)
    sm2.unlock_vault(password)
    assert sm2.vault_exists()
