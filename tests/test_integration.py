"""End-to-end integration tests for the full credential lifecycle."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from generate_it import tui_csv
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


def test_tui_csv_preview_then_import_succeeds(tmp_path: Path, monkeypatch) -> None:
    """Exercise the exact tui_csv preview-to-import sequence with mocked modals.

    Regression: the dry-run preview used to leave the connection inside an
    explicit transaction, so the real import that immediately follows in the
    same app session failed with 'cannot start a transaction within a
    transaction'.
    """
    db_path = tmp_path / "vault.db"
    csv_path = tmp_path / "import.csv"
    csv_path.write_text(
        "name,url,username,password,note\n"
        "GitHub,,dev,gh-secret,\n"
        "GitLab,,ops,gl-secret,note text\n",
        encoding="utf-8",
    )

    storage = StorageManager(db_path=db_path)
    try:
        storage.initialize_vault_v2("A-Strong-Passw0rd!")
        state = SimpleNamespace(message="", vault_credentials=[])

        # Mock all modal entry points used by import_vault_csv.
        monkeypatch.setattr(tui_csv.tui_modal, "_run_modal", lambda *a, **k: None)
        monkeypatch.setattr(tui_csv.tui_modal, "_run_scrollable_modal", lambda *a, **k: None)

        imported, skipped, duplicates = tui_csv.import_vault_csv(
            stdscr=None,
            storage=storage,
            path=str(csv_path),
            import_format="generic",
            theme=None,
            state=state,
        )

        assert imported == 2
        assert skipped == 0
        assert duplicates == []
        assert storage._get_conn().in_transaction is False
        assert "Imported 2 credential(s)" in state.message
        assert len(state.vault_credentials) == 2
    finally:
        storage.close()


def test_tui_csv_preview_then_import_with_duplicates(tmp_path: Path, monkeypatch) -> None:
    """Preview detects a duplicate; the user declines to merge; the real
    import skips the duplicate and imports the new row."""
    db_path = tmp_path / "vault.db"
    csv_path = tmp_path / "import.csv"
    csv_path.write_text(
        "name,url,username,password,note\n"
        "GitHub,,dev,new-pass,\n"
        "GitLab,,ops,gl-secret,\n",
        encoding="utf-8",
    )

    storage = StorageManager(db_path=db_path)
    try:
        storage.initialize_vault_v2("A-Strong-Passw0rd!")
        storage.save_credential("GitHub", "dev", "old-pass")
        state = SimpleNamespace(message="", vault_credentials=[])

        # The merge prompt returns None (user declines to type 'yes').
        monkeypatch.setattr(tui_csv.tui_modal, "_run_modal", lambda *a, **k: None)
        monkeypatch.setattr(tui_csv.tui_modal, "_run_scrollable_modal", lambda *a, **k: None)

        imported, skipped, duplicates = tui_csv.import_vault_csv(
            stdscr=None,
            storage=storage,
            path=str(csv_path),
            import_format="generic",
            theme=None,
            state=state,
        )

        assert imported == 1
        assert skipped == 1
        assert any(d["service"] == "GitHub" for d in duplicates)

        creds = storage.list_credentials()
        assert len(creds) == 2
        github = next(c for c in creds if c["service"] == "GitHub")
        assert github["password"] == "old-pass"  # not merged
    finally:
        storage.close()
