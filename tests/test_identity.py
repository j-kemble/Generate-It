"""Unit and integration tests for canonical credential identity (Phase 2)."""

from __future__ import annotations

import sqlite3
import pytest

from generate_it import identity, tui_helpers
from generate_it.storage import (
    CredentialIdentityConflictError,
    StorageError,
    StorageManager,
)


def test_canonical_identity_rules() -> None:
    # 1. NFC normalization: decomposed e + combining acute (U+0065 + U+0301)
    #    equals precomposed é (U+00E9).
    decomposed = "caf\u0065\u0301"
    precomposed = "caf\u00e9"
    assert decomposed != precomposed  # raw strings differ
    assert identity.canonical_identity(decomposed) == identity.canonical_identity(precomposed)

    # 2. German Eszett: "ß" casefolds to "ss".
    assert identity.canonical_identity("GROSS") == identity.canonical_identity("groß")

    # 3. Stripping surrounding whitespace.
    assert identity.canonical_identity("  GitHub  ") == "github"

    # 4. NFC vs NFKC: precomposed accents match decomposed under NFC.
    #    casefold() handles case variations (e.g. "FILE" == "file").
    assert identity.canonical_identity("FILE") == identity.canonical_identity("file")


def test_validate_identity_rejects_empty_components() -> None:
    with pytest.raises(ValueError, match="Service must not be empty"):
        identity.validate_identity("   ", "user")

    with pytest.raises(ValueError, match="Username must not be empty"):
        identity.validate_identity("GitHub", "\u200b")  # zero-width space after strip -> empty or whitespace

    # Valid returns canonical pair.
    assert identity.validate_identity(" GitHub ", " DevUser ") == ("github", "devuser")


def test_save_and_update_reject_empty_canonical_identity(temp_storage_initialized) -> None:
    storage = temp_storage_initialized

    with pytest.raises(StorageError, match="Service must not be empty"):
        storage.save_credential("   ", "user", "pass")

    with pytest.raises(StorageError, match="Username must not be empty"):
        storage.save_credential("GitHub", "   ", "pass")

    cred_id = storage.save_credential("GitHub", "dev", "pass")

    with pytest.raises(StorageError, match="Service must not be empty"):
        storage.update_credential(cred_id, "  ", "dev", "pass2")


def test_duplicate_prevention_on_save_and_update(temp_storage_initialized) -> None:
    storage = temp_storage_initialized
    storage.save_credential("GitHub", "DevUser", "pass1")

    # Case + whitespace + Unicode variants are caught by duplicate check / unique index.
    with pytest.raises(StorageError, match="already exists"):
        storage.save_credential("  github  ", "devuser", "pass2")

    # Updating to a name that collides with ANOTHER credential is rejected.
    id2 = storage.save_credential("GitLab", "devuser", "pass3")
    with pytest.raises(StorageError, match="already exists"):
        storage.update_credential(id2, "GitHub", "devuser", "pass3")

    # Updating a credential to the same canonical identity (self) MUST succeed.
    storage.update_credential(1, "GITHUB", "DEVUSER", "new_pass")
    meta = storage.find_credential_by_identity("github", "devuser")
    assert meta is not None
    assert meta["id"] == 1


def test_import_detects_canonical_duplicates_including_in_csv(temp_storage_initialized, tmp_path) -> None:
    storage = temp_storage_initialized
    storage.save_credential("GitHub", "DevUser", "old_pass")

    csv_path = tmp_path / "import.csv"
    # Row 1 is a canonical duplicate of existing (case+space)
    # Row 2 is new
    # Row 3 is an in-CSV canonical duplicate of Row 2
    csv_path.write_text(
        "name,url,username,password,note\n"
        "  github  ,,devuser,pass1,\n"
        "AWS,,admin,pass2,\n"
        "aws,,  ADMIN  ,pass3,\n",
        encoding="utf-8",
    )

    imported, skipped, duplicates = storage.import_from_csv(csv_path, merge_duplicates=False)
    assert imported == 1  # only AWS row 2
    assert skipped == 2
    assert len(duplicates) == 2

    # Verify database state.
    assert len(storage.list_credential_metadata()) == 2
    aws = storage.find_credential_by_identity("AWS", "admin")
    assert aws is not None


def test_indexes_exist_after_new_vault_and_after_migration(tmp_path) -> None:
    # 1. New vault (v2) has both canonical columns and both indexes right away.
    v2_path = tmp_path / "v2.db"
    s2 = StorageManager(db_path=v2_path)
    s2.initialize_vault_v2("A-Strong-Passw0rd!")

    conn2 = sqlite3.connect(v2_path)
    cur2 = conn2.cursor()
    cur2.execute("SELECT name FROM sqlite_master WHERE type='index'")
    idx_names = {row[0] for row in cur2.fetchall()}
    assert "idx_credentials_identity" in idx_names
    assert "idx_credentials_order" in idx_names
    conn2.close()
    s2.close()

    # 2. Legacy pre-identity v1 vault gets updated on unlock.
    v1_path = tmp_path / "v1.db"
    raw = sqlite3.connect(v1_path)
    raw.execute("""
        CREATE TABLE config (key TEXT PRIMARY KEY, value BLOB);
    """)
    raw.execute("""
        CREATE TABLE credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            encrypted_password BLOB NOT NULL,
            encrypted_note BLOB,
            note_is_hidden INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    # Insert config salt & verification manually so unlock works
    from generate_it.storage import _DEFAULT_PBKDF2_ITERATIONS, _DEFAULT_SALT_LENGTH, os, Fernet
    salt = os.urandom(_DEFAULT_SALT_LENGTH)
    key = s2._derive_key("A-Strong-Passw0rd!", salt, _DEFAULT_PBKDF2_ITERATIONS)
    token = Fernet(key).encrypt(b"VERIFICATION_TOKEN")
    raw.execute("INSERT INTO config VALUES ('salt', ?)", (salt,))
    raw.execute("INSERT INTO config VALUES ('verification', ?)", (token,))
    raw.execute("INSERT INTO config VALUES ('pbkdf2_iterations', ?)", (str(_DEFAULT_PBKDF2_ITERATIONS).encode(),))
    raw.execute("INSERT INTO credentials (service, username, encrypted_password) VALUES ('GitHub', 'dev', ?)", (token,))
    raw.commit()
    raw.close()

    s1 = StorageManager(db_path=v1_path)
    s1.unlock_vault("A-Strong-Passw0rd!")
    assert s1.identity_conflict is None

    raw_check = sqlite3.connect(v1_path)
    cur_check = raw_check.cursor()
    cur_check.execute("PRAGMA table_info(credentials)")
    cols = {r[1] for r in cur_check.fetchall()}
    assert {"service_key", "username_key"}.issubset(cols)

    cur_check.execute("SELECT service_key, username_key FROM credentials WHERE id=1")
    row = cur_check.fetchone()
    assert row == ("github", "dev")

    cur_check.execute("SELECT name FROM sqlite_master WHERE type='index'")
    idx1_names = {r[0] for r in cur_check.fetchall()}
    assert "idx_credentials_identity" in idx1_names
    assert "idx_credentials_order" in idx1_names
    raw_check.close()
    s1.close()

    # Backup file was created during migration.
    assert (v1_path.with_suffix(v1_path.suffix + ".identity.bak")).exists()


def test_legacy_vault_with_canonical_conflicts_defers_unique_index(tmp_path) -> None:
    """Vault with duplicate canonical entries under legacy rules has both
    rows backfilled, but the unique index is deferred non-destructively;
    self.identity_conflict describes the colliding credentials."""
    db_path = tmp_path / "legacy_dupes.db"
    raw = sqlite3.connect(db_path)
    raw.execute("CREATE TABLE config (key TEXT PRIMARY KEY, value BLOB)")
    raw.execute("""
        CREATE TABLE credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            encrypted_password BLOB NOT NULL,
            encrypted_note BLOB,
            note_is_hidden INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    from generate_it.storage import _DEFAULT_PBKDF2_ITERATIONS, _DEFAULT_SALT_LENGTH, os, Fernet
    salt = os.urandom(_DEFAULT_SALT_LENGTH)
    storage = StorageManager(db_path=db_path)
    key = storage._derive_key("A-Strong-Passw0rd!", salt, _DEFAULT_PBKDF2_ITERATIONS)
    token = Fernet(key).encrypt(b"VERIFICATION_TOKEN")
    raw.execute("INSERT INTO config VALUES ('salt', ?)", (salt,))
    raw.execute("INSERT INTO config VALUES ('verification', ?)", (token,))
    raw.execute("INSERT INTO config VALUES ('pbkdf2_iterations', ?)", (str(_DEFAULT_PBKDF2_ITERATIONS).encode(),))
    # Two rows that collide under canonical rules ("github", "dev")
    raw.execute("INSERT INTO credentials (service, username, encrypted_password) VALUES ('GitHub', 'dev', ?)", (token,))
    raw.execute("INSERT INTO credentials (service, username, encrypted_password) VALUES ('  GITHUB  ', 'DEV', ?)", (token,))
    raw.commit()
    raw.close()

    storage.unlock_vault("A-Strong-Passw0rd!")
    assert isinstance(storage.identity_conflict, CredentialIdentityConflictError)
    assert len(storage.identity_conflict.conflicts) == 1
    assert storage.identity_conflict.conflicts[0]["ids"] == [1, 2]

    # Both rows remain intact and usable; unique index was not created.
    assert len(storage.list_credential_metadata()) == 2
    raw2 = sqlite3.connect(db_path)
    cur2 = raw2.cursor()
    cur2.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_credentials_identity'")
    assert cur2.fetchone() is None
    raw2.close()

    # User resolves the conflict by deleting row 2.
    storage.delete_credential(2)
    storage.close()

    # Re-unlock: unique index is created now that the conflict is gone.
    s2 = StorageManager(db_path=db_path)
    s2.unlock_vault("A-Strong-Passw0rd!")
    assert s2.identity_conflict is None
    raw3 = sqlite3.connect(db_path)
    cur3 = raw3.cursor()
    cur3.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_credentials_identity'")
    assert cur3.fetchone() is not None
    raw3.close()
    s2.close()
