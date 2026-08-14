from __future__ import annotations

import pytest

from generate_it.exceptions import StorageError
from generate_it.storage import StorageManager
from generate_it.storage import migration


def test_core_ensure_identity_schema_delegates_to_migration_module(
    tmp_path, monkeypatch
) -> None:
    """core._ensure_identity_schema must delegate to the canonical module."""
    db_path = tmp_path / "vault.db"
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault("A-Strong-Passw0rd!")
    storage.close()

    reopened = StorageManager(db_path=db_path)
    calls = []
    orig = migration.ensure_identity_schema
    monkeypatch.setattr(migration, "ensure_identity_schema", lambda s: calls.append(s) or orig(s))

    reopened._ensure_identity_schema()

    assert calls == [reopened]
    reopened.close()


def test_migration_retry_identity_index_recomputes_stale_keys(tmp_path) -> None:
    """The canonical migration module must backfill stale keys before the index."""
    db_path = tmp_path / "vault.db"
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault("A-Strong-Passw0rd!")
    credential_id = storage.save_credential("Citibank", "dev", "password")
    connection = storage._get_conn()
    connection.execute(
        "UPDATE credentials SET service_key='stale', username_key='stale' WHERE id=?",
        (credential_id,),
    )
    connection.execute("DROP INDEX idx_credentials_identity")
    connection.commit()

    migration.retry_identity_unique_index(storage)

    assert storage.find_credential_by_identity("citibank", "dev") is not None
    storage.close()


def test_migration_run_identity_migration_cleans_temporary_backup_on_replace_failure(
    tmp_path, monkeypatch
) -> None:
    """run_identity_migration must clean its temporary backup if os.replace fails."""
    db_path = tmp_path / "vault.db"
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault("A-Strong-Passw0rd!")
    storage.close()

    reopened = StorageManager(db_path=db_path)
    # Force the final backup path to be a directory so os.replace raises.
    backup_path = db_path.with_suffix(db_path.suffix + ".identity.bak")
    backup_path.mkdir()

    original_replace = __import__("os").replace

    def fail_backup_replace(source: str, destination: str) -> None:
        if destination == str(backup_path):
            raise IsADirectoryError(destination)
        original_replace(source, destination)

    monkeypatch.setattr("generate_it.storage.migration.os.replace", fail_backup_replace)

    with pytest.raises(IsADirectoryError):
        migration.run_identity_migration(reopened)

    orphaned = [
        p for p in tmp_path.iterdir() if p.name.endswith(".identity.bak") and p != backup_path
    ]
    assert orphaned == []
    reopened.close()