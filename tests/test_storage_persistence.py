"""Regression tests for storage persistence (Phase 1 storage.py change).

These tests prove that ``import_from_csv`` HOISTS its single ``conn.commit()``
to AFTER the row loop (gated by ``if not dry_run:``), so the imported rows are
actually flushed to disk. They also cover the ``_require_unlocked`` helper so
that operations on a locked vault raise ``StorageError``.

Each test is regression-sensitive: removing or misplacing the hoisted commit
would leave an uncommitted transaction that vanishes when the connection is
closed, and these tests reopen a FRESH connection to prove durability.
"""

import pytest

from generate_it.storage import StorageManager, StorageError


def _write_generic_csv(csv_path, rows):
    """Write a generic-format CSV (name,url,username,password,note)."""
    lines = ["name,url,username,password,note"]
    for service, username, password, note in rows:
        lines.append(f"{service},,{username},{password},{note}")
    csv_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_import_persists_rows_after_reopen(tmp_path):
    """The hoisted commit must flush rows to disk across a fresh connection."""
    db_path = tmp_path / "vault.db"
    master = "A-Strong-Passw0rd!"

    storage = StorageManager(db_path=db_path)
    storage.initialize_vault(master)

    csv_path = tmp_path / "import.csv"
    _write_generic_csv(
        csv_path,
        [
            ("GitHub", "dev", "gh_pass", ""),
            ("GitLab", "dev2", "gl_pass", ""),
            ("AWS", "admin", "aws_pass", "root"),
        ],
    )

    imported, skipped, duplicates = storage.import_from_csv(csv_path)
    assert imported >= 3
    assert skipped == 0
    assert duplicates == []

    # CRITICAL: close the original connection and open a brand-new
    # StorageManager on the SAME db file. If the hoisted commit were removed
    # (leaving an uncommitted transaction), these rows would be gone here.
    storage.close()

    fresh = StorageManager(db_path=db_path)
    fresh.unlock_vault(master)
    creds = fresh.list_credentials()
    fresh.close()

    assert len(creds) == imported
    services = {c["service"] for c in creds}
    assert {"GitHub", "GitLab", "AWS"}.issubset(services)


def test_import_dry_run_does_not_persist(tmp_path):
    """The ``if not dry_run:`` guard around the hoisted commit must prevent writes."""
    db_path = tmp_path / "vault.db"
    master = "A-Strong-Passw0rd!"

    storage = StorageManager(db_path=db_path)
    storage.initialize_vault(master)

    csv_path = tmp_path / "dryrun.csv"
    _write_generic_csv(
        csv_path,
        [
            ("GitHub", "dev", "gh_pass", ""),
            ("GitLab", "dev2", "gl_pass", ""),
            ("AWS", "admin", "aws_pass", ""),
        ],
    )

    imported, skipped, duplicates = storage.import_from_csv(csv_path, dry_run=True)
    # Dry-run still reports what it WOULD import, but writes nothing.
    assert imported == 3
    assert skipped == 0

    storage.close()

    # Nothing should have been written to disk.
    fresh = StorageManager(db_path=db_path)
    fresh.unlock_vault(master)
    creds = fresh.list_credentials()
    fresh.close()

    assert len(creds) == 0


def test_import_handles_duplicates_and_skips(tmp_path):
    """Duplicate rows (merge_duplicates=False) are skipped, not double-inserted."""
    db_path = tmp_path / "vault.db"
    master = "A-Strong-Passw0rd!"

    storage = StorageManager(db_path=db_path)
    storage.initialize_vault(master)
    # Seed an existing credential that the CSV will duplicate.
    storage.save_credential("GitHub", "dev", "old_pass")

    csv_path = tmp_path / "dupes.csv"
    _write_generic_csv(
        csv_path,
        [
            ("GitHub", "dev", "new_pass", ""),   # duplicate of existing -> skip
            ("GitLab", "dev2", "gl_pass", ""),   # new -> import
            ("AWS", "admin", "aws_pass", ""),    # new -> import
        ],
    )

    imported, skipped, duplicates = storage.import_from_csv(
        csv_path, merge_duplicates=False
    )
    # Only the two genuinely-new rows are counted as imported.
    assert imported == 2
    assert skipped >= 1
    assert len(duplicates) >= 1
    assert any(d["service"] == "GitHub" for d in duplicates)

    storage.close()

    fresh = StorageManager(db_path=db_path)
    fresh.unlock_vault(master)
    creds = fresh.list_credentials()
    fresh.close()

    # 1 seeded + 2 new = 3, and the duplicate was NOT inserted a second time.
    assert len(creds) == 3
    github = [c for c in creds if c["service"] == "GitHub"]
    assert len(github) == 1
    # The original password is untouched (no merge).
    assert github[0]["password"] == "old_pass"


def test_locked_ops_raise_storage_error(tmp_path):
    """Operations on a locked (never-unlocked) vault must raise StorageError."""
    db_path = tmp_path / "vault.db"
    storage = StorageManager(db_path=db_path)
    # NOTE: intentionally NOT initialize_vault / unlock_vault -> _fernet is None.

    with pytest.raises(StorageError):
        storage.save_credential("GitHub", "dev", "pass")

    with pytest.raises(StorageError):
        storage.list_credentials()

    with pytest.raises(StorageError):
        storage.delete_credential(1)

    with pytest.raises(StorageError):
        storage.update_credential(1, "GitHub", "dev", "pass")

    storage.close()
