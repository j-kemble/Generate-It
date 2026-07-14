"""End-to-end integration tests for the full credential lifecycle."""

from __future__ import annotations

from pathlib import Path

from generate_it.storage import StorageManager


def test_full_credential_lifecycle(tmp_path: Path) -> None:
    """Generate → save → export CSV → import to fresh vault → verify roundtrip."""
    db_path = tmp_path / "vault.db"
    csv_path = tmp_path / "export.csv"

    # 1. Create vault and save credentials
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault("A-Strong-Passw0rd!")
    storage.save_credential("GitHub", "dev", "gh-secret", note="2FA enabled")
    storage.save_credential("Gmail", "alice", "mail-secret")
    storage.close()

    # 2. Reopen and export
    storage = StorageManager(db_path=db_path)
    storage.unlock_vault("A-Strong-Passw0rd!")
    exported, skipped = storage.export_to_csv(csv_path, export_format="generic")
    assert exported == 2
    assert skipped == []
    storage.close()

    # 3. Import into a fresh vault
    fresh_db = tmp_path / "fresh.db"
    fresh = StorageManager(db_path=fresh_db)
    fresh.initialize_vault("Different-Pw!1")
    imported, skipped_num, dupes = fresh.import_from_csv(csv_path, import_format="generic")
    assert imported == 2
    assert skipped_num == 0
    assert dupes == []
    fresh.close()

    # 4. Reopen fresh vault and verify
    fresh = StorageManager(db_path=fresh_db)
    fresh.unlock_vault("Different-Pw!1")
    creds = fresh.list_credentials()
    assert len(creds) == 2
    services = {c["service"] for c in creds}
    assert services == {"GitHub", "Gmail"}
    fresh.close()

    # 5. Add a third credential and re-export
    fresh = StorageManager(db_path=fresh_db)
    fresh.unlock_vault("Different-Pw!1")
    fresh.save_credential("Netflix", "bob", "nf-secret")
    fresh.close()

    fresh = StorageManager(db_path=fresh_db)
    fresh.unlock_vault("Different-Pw!1")
    csv2 = tmp_path / "export2.csv"
    exported2, _ = fresh.export_to_csv(csv2, export_format="generic")
    assert exported2 == 3
    fresh.close()

    # 6. Import CSV2 into first vault with merge — only Netflix is new
    storage = StorageManager(db_path=db_path)
    storage.unlock_vault("A-Strong-Passw0rd!")
    imported2, _, _ = storage.import_from_csv(csv2, merge_duplicates=True, import_format="generic")
    # imported counts all rows processed (3 = 2 merged updates + 1 new insert)
    assert imported2 == 3
    storage.close()

    # Verify no duplicates were created — still exactly 3 unique credentials
    storage = StorageManager(db_path=db_path)
    storage.unlock_vault("A-Strong-Passw0rd!")
    all_creds = storage.list_credentials()
    assert len(all_creds) == 3
    services = {c["service"] for c in all_creds}
    assert services == {"GitHub", "Gmail", "Netflix"}
    storage.close()
