import os
import sqlite3
import pytest
from pathlib import Path
from generate_it.storage import StorageManager, VaultNotInitializedError, InvalidPasswordError

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
