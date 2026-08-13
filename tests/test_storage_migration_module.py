from __future__ import annotations

from types import SimpleNamespace

from generate_it.storage import CredentialIdentityConflictError
from generate_it.storage import migration


def test_set_identity_conflict_uses_canonical_storage_exception() -> None:
    storage = SimpleNamespace(identity_conflict=None)
    conflicts = [{"service": "GitHub", "username": "Dev", "ids": [3, 7]}]

    migration.set_identity_conflict(storage, conflicts)

    assert isinstance(storage.identity_conflict, CredentialIdentityConflictError)
    assert storage.identity_conflict.conflicts == conflicts
    assert "GitHub / Dev (ids: 3, 7)" in str(storage.identity_conflict)


def test_migration_module_exposes_identity_index_helpers() -> None:
    assert callable(migration.create_identity_indexes)
    assert callable(migration.detect_identity_conflicts)
    assert callable(migration.ensure_identity_schema)
    assert callable(migration.retry_identity_unique_index)
    assert callable(migration.run_identity_migration)
