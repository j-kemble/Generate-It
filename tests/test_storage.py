import csv
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

    temp_storage.initialize_vault("A-Strong-Passw0rd!")
    assert temp_storage.vault_exists()

    # Verify tables exist
    conn = sqlite3.connect(temp_storage.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='credentials'")
    assert cursor.fetchone() is not None
    conn.close()

def test_vault_unlock(temp_storage):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")

    # Test correct unlock
    # Re-instantiate or just reuse (initialize_vault unlocks it)

    # Let's close and re-open to simulate fresh start
    temp_storage.close()

    storage2 = StorageManager(db_path=temp_storage.db_path)
    try:
        assert storage2.vault_exists()

        # Wrong password
        with pytest.raises(InvalidPasswordError):
            storage2.unlock_vault("wrong")

        # Correct password
        storage2.unlock_vault("A-Very-Secret-Key1!")
        assert storage2._fernet is not None
    finally:
        storage2.close()

def test_credential_ops(temp_storage):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")

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


def test_update_credential_updates_fields_and_password(temp_storage):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")
    cred_id = temp_storage.save_credential("GitHub", "old-user", "old-pass")

    temp_storage.update_credential(cred_id, "GitHub-Work", "new-user", "new-pass")

    creds = temp_storage.list_credentials()
    assert len(creds) == 1
    assert creds[0]["id"] == cred_id
    assert creds[0]["service"] == "GitHub-Work"
    assert creds[0]["username"] == "new-user"
    assert creds[0]["password"] == "new-pass"


def test_update_credential_missing_id_raises(temp_storage):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")

    with pytest.raises(StorageError, match="not found"):
        temp_storage.update_credential(999999, "Svc", "user", "pass")


def test_app_setting_round_trip(temp_storage):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")

    assert temp_storage.get_app_setting("clipboard_auto_clear_index") is None
    assert temp_storage.get_app_setting("clipboard_auto_clear_index", "0") == "0"

    temp_storage.set_app_setting("clipboard_auto_clear_index", "3")
    temp_storage.set_app_setting("auto_lock_index", "2")

    assert temp_storage.get_app_setting("clipboard_auto_clear_index") == "3"
    assert temp_storage.get_app_setting("auto_lock_index") == "2"


def test_csv_export_import_round_trip(temp_storage, tmp_path):
    # Export from one vault
    temp_storage.initialize_vault("A-Very-Secret-Key1!")
    temp_storage.save_credential("GitHub", "dev", "gh_token")
    temp_storage.save_credential("Google", "user@gmail.com", "password123")

    csv_path = tmp_path / "export.csv"
    exported, skipped = temp_storage.export_to_csv(csv_path)
    assert exported == 2
    assert skipped == []

    # Import into a new vault
    storage2 = StorageManager(db_path=tmp_path / "vault2.db")
    try:
        storage2.initialize_vault("A-Very-Secret-Key1!")
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
    temp_storage.initialize_vault("A-Very-Secret-Key1!")

    # Missing password column
    csv_path = tmp_path / "bad.csv"
    csv_path.write_text("name,username\nGitHub,dev\n", encoding="utf-8")

    with pytest.raises(StorageError, match="CSV missing required columns"):
        temp_storage.import_from_csv(csv_path)


def test_csv_import_duplicate_detection_and_merge(temp_storage, tmp_path):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")
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


def test_csv_import_bitwarden_auto_detect_and_skip_non_login(temp_storage, tmp_path):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")

    csv_path = tmp_path / "bitwarden.csv"
    csv_path.write_text(
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
        ",0,login,GitHub,,,0,https://github.com,dev,gh_pass,\n"
        ",0,card,Visa,,,0,,,ignored,\n",
        encoding="utf-8",
    )

    imported, skipped, issues = temp_storage.import_from_csv(csv_path, import_format="auto")
    assert imported == 1
    assert skipped == 1
    assert any("Unsupported item type" in issue["reason"] for issue in issues)
    assert issues[0]["service"] == "Visa"

    creds = temp_storage.list_credentials()
    assert len(creds) == 1
    assert creds[0]["service"] == "GitHub"
    assert creds[0]["username"] == "dev"
    assert creds[0]["password"] == "gh_pass"


def test_csv_import_apple_format(temp_storage, tmp_path):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")

    csv_path = tmp_path / "apple.csv"
    csv_path.write_text(
        "Title,URL,Username,Password,Notes,OTPAuth\n"
        "iCloud,https://icloud.com,apple-user,apple-pass,,\n",
        encoding="utf-8",
    )

    imported, skipped, issues = temp_storage.import_from_csv(csv_path, import_format="apple")
    assert imported == 1
    assert skipped == 0
    assert issues == []

    creds = temp_storage.list_credentials()
    assert len(creds) == 1
    assert creds[0]["service"] == "iCloud"
    assert creds[0]["username"] == "apple-user"
    assert creds[0]["password"] == "apple-pass"


def test_csv_import_nordpass_template_format(temp_storage, tmp_path):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")

    csv_path = tmp_path / "nordpass.csv"
    csv_path.write_text(
        "name,url,username,password,note,cardholdername,cardnumber,cvc,expirydate,zipcode,folder,full_name,phone_number,email,address1,address2,city,country,state,type,custom_fields\n"
        "GitLab,https://gitlab.com,git-user,git-pass,,,,,,,,,,,,,,,password,\n"
        "Secure Note Example,,,,This row should be skipped,,,,,,,,,,,,,,,secure_note,\n",
        encoding="utf-8",
    )

    imported, skipped, issues = temp_storage.import_from_csv(csv_path, import_format="nordpass")
    assert imported == 1
    assert skipped == 1
    assert len(issues) == 1
    assert "Unsupported item type" in issues[0]["reason"]
    assert issues[0]["service"] == "Secure Note Example"

    creds = temp_storage.list_credentials()
    assert len(creds) == 1
    assert creds[0]["service"] == "GitLab"
    assert creds[0]["username"] == "git-user"
    assert creds[0]["password"] == "git-pass"


def test_csv_export_bitwarden_format_headers_and_row_mapping(temp_storage, tmp_path):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")
    temp_storage.save_credential("GitHub", "dev", "gh_pass")

    csv_path = tmp_path / "export_bitwarden.csv"
    exported, skipped = temp_storage.export_to_csv(csv_path, export_format="bitwarden")
    assert exported == 1
    assert skipped == []

    with open(csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))

    assert rows[0] == [
        "folder",
        "favorite",
        "type",
        "name",
        "notes",
        "fields",
        "reprompt",
        "login_uri",
        "login_username",
        "login_password",
        "login_totp",
    ]
    assert rows[1][2] == "login"
    assert rows[1][3] == "GitHub"
    assert rows[1][8] == "dev"
    assert rows[1][9] == "gh_pass"


def test_csv_export_apple_format_headers_and_row_mapping(temp_storage, tmp_path):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")
    temp_storage.save_credential("iCloud", "apple-user", "apple-pass")

    csv_path = tmp_path / "export_apple.csv"
    exported, skipped = temp_storage.export_to_csv(csv_path, export_format="apple")
    assert exported == 1
    assert skipped == []

    with open(csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))

    assert rows[0] == ["Title", "URL", "Username", "Password", "Notes", "OTPAuth"]
    assert rows[1] == ["iCloud", "", "apple-user", "apple-pass", "", ""]


def test_csv_export_nordpass_format_headers_and_row_mapping(temp_storage, tmp_path):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")
    temp_storage.save_credential("NordAccount", "nord-user", "nord-pass")

    csv_path = tmp_path / "export_nordpass.csv"
    exported, skipped = temp_storage.export_to_csv(csv_path, export_format="nordpass")
    assert exported == 1
    assert skipped == []

    with open(csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))

    assert rows[0] == [
        "name",
        "url",
        "username",
        "password",
        "note",
        "cardholdername",
        "cardnumber",
        "cvc",
        "expirydate",
        "zipcode",
        "folder",
        "full_name",
        "phone_number",
        "email",
        "address1",
        "address2",
        "city",
        "country",
        "state",
        "type",
        "custom_fields",
    ]
    assert rows[1][0] == "NordAccount"
    assert rows[1][2] == "nord-user"
    assert rows[1][3] == "nord-pass"
    assert rows[1][19] == "password"


def test_csv_import_invalid_format_raises(temp_storage, tmp_path):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")
    csv_path = tmp_path / "sample.csv"
    csv_path.write_text("name,username,password\nGitHub,dev,pass\n", encoding="utf-8")

    with pytest.raises(StorageError, match="Unsupported import format"):
        temp_storage.import_from_csv(csv_path, import_format="unknown-format")


def test_csv_export_invalid_format_raises(temp_storage, tmp_path):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")
    csv_path = tmp_path / "sample.csv"

    with pytest.raises(StorageError, match="Unsupported export format"):
        temp_storage.export_to_csv(csv_path, export_format="unknown-format")


def test_save_credential_with_note_and_hidden_flag(temp_storage):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")

    cred_id = temp_storage.save_credential(
        "GitHub", "dev", "password", "This is a secret note", note_is_hidden=True
    )

    creds = temp_storage.list_credentials()
    assert len(creds) == 1
    assert creds[0]["note"] == "This is a secret note"
    assert creds[0]["note_is_hidden"] is True


def test_save_credential_with_note_visible(temp_storage):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")

    cred_id = temp_storage.save_credential(
        "GitHub", "dev", "password", "Visible note", note_is_hidden=False
    )

    creds = temp_storage.list_credentials()
    assert creds[0]["note"] == "Visible note"
    assert creds[0]["note_is_hidden"] is False


def test_update_credential_note_and_hidden_flag(temp_storage):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")

    cred_id = temp_storage.save_credential("GitHub", "dev", "password")
    creds = temp_storage.list_credentials()
    assert creds[0]["note"] == ""
    assert creds[0]["note_is_hidden"] is False

    temp_storage.update_credential(cred_id, "GitHub", "dev", "password", "Updated note", True)

    creds = temp_storage.list_credentials()
    assert creds[0]["note"] == "Updated note"
    assert creds[0]["note_is_hidden"] is True


def test_update_credential_toggle_hidden_flag(temp_storage):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")

    cred_id = temp_storage.save_credential("GitHub", "dev", "password", "Note", True)

    temp_storage.update_credential(cred_id, "GitHub", "dev", "password", "Note", False)

    creds = temp_storage.list_credentials()
    assert creds[0]["note_is_hidden"] is False


def test_delete_credential_nonexistent_id_does_not_raise(temp_storage):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")
    temp_storage.save_credential("GitHub", "dev", "password")

    temp_storage.delete_credential(9999)


def test_vault_unlock_invalid_password_raises(temp_storage):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")
    temp_storage.close()

    storage2 = StorageManager(db_path=temp_storage.db_path)

    with pytest.raises(InvalidPasswordError, match="Invalid master password"):
        storage2.unlock_vault("wrong_password")


def test_vault_unlock_after_close_reconnects(temp_storage):
    """Verify that unlock works after closing and reopening the vault (auto-lock scenario)."""
    temp_storage.initialize_vault("A-Very-Secret-Key1!")

    # Save a credential while unlocked
    temp_storage.save_credential("test_service", "test_user", "test_pass")
    creds = temp_storage.list_credentials()
    assert len(creds) == 1

    # Close the vault (simulates auto-lock)
    temp_storage.close()

    # Unlock should reconnect and work properly
    temp_storage.unlock_vault("A-Very-Secret-Key1!")
    creds = temp_storage.list_credentials()
    assert len(creds) == 1
    assert creds[0]["service"] == "test_service"
    assert creds[0]["password"] == "test_pass"


def test_list_credentials_empty_vault(temp_storage):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")

    creds = temp_storage.list_credentials()
    assert creds == []


def test_export_csv_with_note_field(temp_storage, tmp_path):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")
    temp_storage.save_credential("GitHub", "dev", "pass", "My note")

    csv_path = tmp_path / "export.csv"
    exported, skipped = temp_storage.export_to_csv(csv_path, export_format="generic")

    assert exported == 1
    content = csv_path.read_text(encoding="utf-8")
    assert "My note" in content


def test_import_csv_with_note_field(temp_storage, tmp_path):
    temp_storage.initialize_vault("A-Very-Secret-Key1!")

    csv_path = tmp_path / "import.csv"
    csv_path.write_text("name,username,password,note\nGitHub,dev,pass,Imported note\n", encoding="utf-8")

    imported, skipped, issues = temp_storage.import_from_csv(csv_path, import_format="generic")

    assert imported == 1
    creds = temp_storage.list_credentials()
    assert creds[0]["note"] == "Imported note"
