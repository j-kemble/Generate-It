import sqlite3
import pytest
from generate_it.storage import StorageManager, InvalidPasswordError, StorageError

@pytest.fixture
def temp_storage(tmp_path):
    # Create a storage manager using a temporary path
    db_path = tmp_path / "test_vault.db"
    storage = StorageManager(db_path=db_path)
    yield storage
    storage.close()

def test_vault_initialization(temp_storage):
    assert not temp_storage.vault_exists()
    
    temp_storage.initialize_vault("masterpass")
    assert temp_storage.vault_exists()
    
    # Verify tables exist
    conn = sqlite3.connect(temp_storage.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='credentials'")
    assert cursor.fetchone() is not None
    conn.close()

def test_vault_unlock(temp_storage):
    temp_storage.initialize_vault("secret")
    
    # Test correct unlock
    # Re-instantiate or just reuse (initialize_vault unlocks it)
    
    # Let's close and re-open to simulate fresh start
    temp_storage.close()
    
    storage2 = StorageManager(db_path=temp_storage.db_path)
    assert storage2.vault_exists()
    
    # Wrong password
    with pytest.raises(InvalidPasswordError):
        storage2.unlock_vault("wrong")
        
    # Correct password
    storage2.unlock_vault("secret")
    assert storage2._fernet is not None

def test_credential_ops(temp_storage):
    temp_storage.initialize_vault("secret")
    
    # Save
    temp_storage.save_credential("Google", "user@gmail.com", "password123")
    temp_storage.save_credential("GitHub", "dev", "gh_token")
    
    # List
    creds = temp_storage.list_credentials()
    assert len(creds) == 2
    assert creds[0]["service"] == "GitHub" # Ordered by service
    assert creds[0]["password"] == "gh_token"
    assert creds[1]["service"] == "Google"
    assert creds[1]["password"] == "password123"
    
    # Delete
    temp_storage.delete_credential(creds[0]["id"])
    creds = temp_storage.list_credentials()
    assert len(creds) == 1
    assert creds[0]["service"] == "Google"


def test_csv_export_import_round_trip(temp_storage, tmp_path):
    # Export from one vault
    temp_storage.initialize_vault("secret")
    temp_storage.save_credential("GitHub", "dev", "gh_token")
    temp_storage.save_credential("Google", "user@gmail.com", "password123")

    csv_path = tmp_path / "export.csv"
    exported, skipped = temp_storage.export_to_csv(csv_path)
    assert exported == 2
    assert skipped == []

    # Import into a new vault
    storage2 = StorageManager(db_path=tmp_path / "vault2.db")
    try:
        storage2.initialize_vault("secret")
        imported, skipped_count, issues = storage2.import_from_csv(csv_path)

        assert imported == 2
        assert skipped_count == 0
        assert issues == []

        creds = storage2.list_credentials()
        assert len(creds) == 2
        # Ordered by service
        assert creds[0]["service"] == "GitHub"
        assert creds[0]["username"] == "dev"
        assert creds[0]["password"] == "gh_token"
        assert creds[1]["service"] == "Google"
        assert creds[1]["username"] == "user@gmail.com"
        assert creds[1]["password"] == "password123"
    finally:
        storage2.close()


def test_csv_import_missing_required_columns_raises(temp_storage, tmp_path):
    temp_storage.initialize_vault("secret")

    # Missing password column
    csv_path = tmp_path / "bad.csv"
    csv_path.write_text("name,username\nGitHub,dev\n", encoding="utf-8")

    with pytest.raises(StorageError, match="CSV missing required columns"):
        temp_storage.import_from_csv(csv_path)


def test_csv_import_duplicate_detection_and_merge(temp_storage, tmp_path):
    temp_storage.initialize_vault("secret")
    temp_storage.save_credential("GitHub", "DevUser", "oldpass")

    csv_path = tmp_path / "dupes.csv"
    csv_path.write_text(
        "name,url,username,password,note\n"
        "github,,devuser,NEWPASS,\n",
        encoding="utf-8",
    )

    # No merge: should skip duplicate
    imported, skipped, issues = temp_storage.import_from_csv(csv_path, merge_duplicates=False)
    assert imported == 0
    assert skipped == 1
    assert len(issues) == 1
    assert "Duplicate" in issues[0]["reason"]

    # Merge: should update existing credential
    imported, skipped, issues = temp_storage.import_from_csv(csv_path, merge_duplicates=True)
    assert imported == 1
    assert skipped == 0
    assert issues == []

    creds = temp_storage.list_credentials()
    assert len(creds) == 1
    assert creds[0]["service"] == "GitHub"
    assert creds[0]["username"] == "DevUser"
    assert creds[0]["password"] == "NEWPASS"
