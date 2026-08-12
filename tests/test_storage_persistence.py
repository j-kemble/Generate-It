"""Regression tests for storage persistence (Phase 1 storage.py change).

These tests prove that ``import_from_csv`` HOISTS its single ``conn.commit()``
to AFTER the row loop (gated by ``if not dry_run:``), so the imported rows are
actually flushed to disk. They also cover the ``_require_unlocked`` helper so
that operations on a locked vault raise ``StorageError``.

Each test is regression-sensitive: removing or misplacing the hoisted commit
would leave an uncommitted transaction that vanishes when the connection is
closed, and these tests reopen a FRESH connection to prove durability.

They also pin the dry-run transaction contract: a preview must NEVER open an
explicit transaction (``Connection.in_transaction`` stays False), and a real
import immediately after a dry run on the same connection must succeed.
"""

import pytest

from generate_it.storage import StorageManager, StorageError

V2_MASTER_PASSWORD = "A-Strong-Passw0rd!"


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


# ---------------------------------------------------------------------------
# Dry-run transaction handling
# ---------------------------------------------------------------------------


def _make_v1_vault(tmp_path):
    storage = StorageManager(db_path=tmp_path / "vault.db")
    storage.initialize_vault(V2_MASTER_PASSWORD)
    return storage


def _make_v2_vault(tmp_path):
    storage = StorageManager(db_path=tmp_path / "vault.db")
    storage.initialize_vault_v2(V2_MASTER_PASSWORD)
    return storage


@pytest.mark.parametrize("make_vault", [_make_v1_vault, _make_v2_vault], ids=["v1", "v2"])
def test_dry_run_then_real_import_same_manager(tmp_path, make_vault):
    """Preview (dry_run=True) followed by a real import through the SAME
    StorageManager must succeed — the dry run must not leave the connection
    inside a transaction (the original bug raised 'cannot start a transaction
    within a transaction' on the second call)."""
    storage = make_vault(tmp_path)
    try:
        csv_path = tmp_path / "import.csv"
        _write_generic_csv(
            csv_path,
            [("GitHub", "dev", "gh_pass", ""), ("GitLab", "dev2", "gl_pass", "")],
        )

        preview = storage.import_from_csv(csv_path, dry_run=True)
        assert preview[0] == 2
        assert storage._get_conn().in_transaction is False

        imported, skipped, duplicates = storage.import_from_csv(csv_path)
        assert imported == 2
        assert skipped == 0
        assert duplicates == []
        assert storage._get_conn().in_transaction is False

        assert len(storage.list_credential_metadata()) == 2
    finally:
        storage.close()


@pytest.mark.parametrize("make_vault", [_make_v1_vault, _make_v2_vault], ids=["v1", "v2"])
def test_dry_run_then_save_update_delete_same_manager(tmp_path, make_vault):
    """After a dry run, regular write operations must keep working."""
    storage = make_vault(tmp_path)
    try:
        csv_path = tmp_path / "dryrun.csv"
        _write_generic_csv(csv_path, [("GitHub", "dev", "gh_pass", "")])

        storage.import_from_csv(csv_path, dry_run=True)
        assert storage._get_conn().in_transaction is False

        cred_id = storage.save_credential("Manual", "user", "pass")
        storage.update_credential(cred_id, "Manual", "user", "pass2")
        storage.delete_credential(cred_id)
        assert storage.list_credential_metadata() == []
    finally:
        storage.close()


@pytest.mark.parametrize("make_vault", [_make_v1_vault, _make_v2_vault], ids=["v1", "v2"])
def test_failed_dry_run_leaves_no_transaction(tmp_path, make_vault):
    """A dry run that fails validation must not leave an open transaction."""
    storage = make_vault(tmp_path)
    try:
        bad_csv = tmp_path / "bad.csv"
        bad_csv.write_text("name,username\nGitHub,dev\n", encoding="utf-8")  # no password col

        with pytest.raises(StorageError, match="missing required columns"):
            storage.import_from_csv(bad_csv, dry_run=True)
        assert storage._get_conn().in_transaction is False

        # An invalid format name fails before any file/transaction work.
        with pytest.raises(StorageError, match="Unsupported import format"):
            storage.import_from_csv(bad_csv, dry_run=True, import_format="not-a-format")
        assert storage._get_conn().in_transaction is False

        # A missing file also fails without touching transaction state.
        with pytest.raises(StorageError, match="Cannot read CSV file"):
            storage.import_from_csv(tmp_path / "does-not-exist.csv", dry_run=True)
        assert storage._get_conn().in_transaction is False
    finally:
        storage.close()


@pytest.mark.parametrize("make_vault", [_make_v1_vault, _make_v2_vault], ids=["v1", "v2"])
def test_real_import_rolls_back_after_first_mutation(tmp_path, make_vault):
    """A failure after at least one INSERT must roll back ALL mutations."""
    storage = make_vault(tmp_path)
    try:
        csv_path = tmp_path / "partial.csv"
        long_field = "x" * 600  # exceeds _MAX_CSV_FIELD_BYTES on row 3
        csv_path.write_text(
            "name,url,username,password,note\n"
            "GitHub,,dev,validpass,\n"
            f"BadSvc,,baduser,{long_field},\n",
            encoding="utf-8",
        )

        with pytest.raises(StorageError, match="exceeds"):
            storage.import_from_csv(csv_path)

        assert storage._get_conn().in_transaction is False
        # No partial rows remain from the failed import.
        assert storage.list_credential_metadata() == []

        # The same manager is still usable after the rollback.
        storage.save_credential("After", "user", "pass")
        assert len(storage.list_credential_metadata()) == 1
    finally:
        storage.close()
