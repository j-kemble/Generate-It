"""Identity schema migration logic for Generate It storage."""

from __future__ import annotations

import os
import shutil
from typing import Any, Dict, List, Optional, Tuple

import sqlite3

from .core import _IDENTITY_SCHEMA_VERSION, _IDX_IDENTITY_UNIQUE, _IDX_IDENTITY_ORDER
from ..identity import canonical_service_username
from ..logging import get_logger

_log = get_logger(__name__)


def create_identity_indexes(cursor: sqlite3.Cursor, *, include_unique: bool = True) -> None:
    """Create the canonical-identity indexes (idempotent)."""
    if include_unique:
        cursor.execute(
            f"CREATE UNIQUE INDEX IF NOT EXISTS {_IDX_IDENTITY_UNIQUE}"
            " ON credentials (service_key, username_key)"
        )
    cursor.execute(
        f"CREATE INDEX IF NOT EXISTS {_IDX_IDENTITY_ORDER}"
        " ON credentials (service_key, username_key, id)"
    )


def identity_columns_present(cursor: sqlite3.Cursor) -> bool:
    cursor.execute("PRAGMA table_info(credentials)")
    columns = {row["name"] for row in cursor.fetchall()}
    return {"service_key", "username_key"}.issubset(columns)


def identity_unique_index_present(cursor: sqlite3.Cursor) -> bool:
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name=?",
        (_IDX_IDENTITY_UNIQUE,),
    )
    return cursor.fetchone() is not None


def detect_identity_conflicts(
    cursor: sqlite3.Cursor
) -> List[Dict[str, Any]]:
    """Group rows by canonical identity and return colliding groups.

    Each returned dict has ``service``/``username`` (from the first row
    of the group) and ``ids`` (all row ids sharing that canonical
    identity), sorted by id for deterministic reporting.
    """
    from ..exceptions import StorageError
    cursor.execute("SELECT id, service, username FROM credentials ORDER BY id")
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for row in cursor.fetchall():
        service = row["service"]
        username = row["username"]
        if not isinstance(service, str) or not isinstance(username, str):
            raise StorageError(
                "Vault contains a credential with non-text service/username "
                f"(id={row['id']}); cannot migrate identity schema."
            )
        service_key, username_key = canonical_service_username(service, username)
        if not service_key or not username_key:
            raise StorageError(
                "Vault contains a credential with an empty canonical identity "
                f"(id={row['id']}, service={service!r}, username={username!r}). "
                "Rename or delete it, then retry."
            )
        key = (service_key, username_key)
        entry = groups.setdefault(
            key,
            {"service": service, "username": username, "ids": []},
        )
        ids_list: List[int] = entry["ids"]
        ids_list.append(row["id"])
    return [entry for entry in groups.values() if len(entry["ids"]) > 1]


def ensure_identity_schema(storage) -> None:
    """Ensure canonical identity columns and indexes exist.

    Called automatically at the end of every successful unlock.  New
    vaults are created with the identity schema, so this is a no-op for
    them.  For pre-identity vaults it runs a migration-safe upgrade:
    private on-disk backup, single exclusive transaction, canonical
    backfill, then index creation.

    Canonical duplicates in existing data are handled non-destructively:
    the backfill commits but the unique index is deferred, and
    ``storage.identity_conflict`` describes the colliding rows so the UI can
    guide the user to rename/delete them.  The migration retries on the
    next unlock.

    Raises:
        StorageError: for malformed data or migration I/O failures.  The
            database is rolled back and the backup preserved.
    """
    from ..exceptions import StorageError
    storage.identity_conflict = None
    conn = storage._get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='credentials'"
    )
    if cursor.fetchone() is None:
        return
    if not identity_columns_present(cursor):
        run_identity_migration(storage)
        return
    if not identity_unique_index_present(cursor):
        retry_identity_unique_index(storage)


def retry_identity_unique_index(storage) -> None:
    """Create the deferred unique identity index once conflicts are gone."""
    conn = storage._get_conn()
    cursor = conn.cursor()
    conflicts = detect_identity_conflicts(cursor)
    if conflicts:
        set_identity_conflict(storage, conflicts)
        return
    try:
        conn.execute("BEGIN EXCLUSIVE")
        create_identity_indexes(cursor)
        cursor.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES ('identity_schema_version', ?)",
            (str(_IDENTITY_SCHEMA_VERSION),),
        )
        conn.commit()
        _log.info("identity unique index created after conflict resolution")
    except BaseException:
        try:
            conn.rollback()
        except Exception as rollback_exc:
            _log.debug("rollback failed during identity index retry: %s", rollback_exc)
        raise


def set_identity_conflict(storage, conflicts: List[Dict[str, Any]]) -> None:
    from ..exceptions import CredentialIdentityConflictError
    summary_items: List[str] = []
    for c in conflicts:
        c_ids: List[int] = c.get("ids", [])
        ids_str = ", ".join(str(i) for i in c_ids)
        summary_items.append(f"{c['service']} / {c['username']} (ids: {ids_str})")
    summary = "; ".join(summary_items)
    storage.identity_conflict = CredentialIdentityConflictError(
        "Some stored credentials are duplicates under the canonical "
        "identity rules (same service/username ignoring case, surrounding "
        "whitespace, and equivalent Unicode). Nothing was changed or "
        "deleted. Rename or delete the duplicates in the vault explorer, "
        "then unlock again to finish the upgrade. Conflicts: " + summary,
        conflicts=conflicts,
    )
    _log.warning("identity schema migration deferred: %s", summary)


def run_identity_migration(storage) -> None:
    """Backfill canonical identity columns for a pre-identity vault.

    Creates a private backup first, then runs in a single exclusive
    transaction: add nullable columns, backfill canonical keys, create
    indexes, and commit the schema marker last.  On canonical conflicts
    the backfill still commits (data is only enriched, never dropped or
    merged) but the unique index is deferred — see
    ``ensure_identity_schema``.
    """
    # Back up before rewriting any existing data.
    backup_tmp = storage._secure_temp_file(storage.db_path.parent, ".identity.bak")
    try:
        shutil.copy2(storage.db_path, backup_tmp)
    except BaseException:
        if backup_tmp.exists():
            try:
                backup_tmp.unlink()
            except OSError:
                pass
        raise
    backup_path = storage.db_path.with_suffix(storage.db_path.suffix + ".identity.bak")
    os.replace(str(backup_tmp), str(backup_path))
    _log.info("identity migration backup created at %s", backup_path)

    conn = storage._get_conn()
    cursor = conn.cursor()
    try:
        conn.execute("BEGIN EXCLUSIVE")

        # 1. Add nullable canonical columns.
        if not identity_columns_present(cursor):
            cursor.execute("ALTER TABLE credentials ADD COLUMN service_key TEXT")
            cursor.execute("ALTER TABLE credentials ADD COLUMN username_key TEXT")

        # 2. Backfill canonical keys (read with one cursor, write with a
        #    separate cursor to avoid disturbing the active result set).
        conflicts = detect_identity_conflicts(cursor)
        read_cursor = conn.cursor()
        write_cursor = conn.cursor()
        read_cursor.execute("SELECT id, service, username FROM credentials ORDER BY id")
        for row in read_cursor:
            service_key, username_key = canonical_service_username(
                row["service"], row["username"]
            )
            write_cursor.execute(
                "UPDATE credentials SET service_key = ?, username_key = ? WHERE id = ?",
                (service_key, username_key, row["id"]),
            )

        # 3. Ordering index is always safe; the unique index is created
        #    only when no canonical conflicts exist.
        create_identity_indexes(cursor, include_unique=not conflicts)

        # 4. Commit the schema marker last (only on full completion).
        if not conflicts:
            cursor.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES ('identity_schema_version', ?)",
                (str(_IDENTITY_SCHEMA_VERSION),),
            )
        conn.commit()

        if conflicts:
            set_identity_conflict(storage, conflicts)
        _log.info("identity schema migration complete (backup at %s)", backup_path)
    except BaseException:
        try:
            conn.rollback()
        except Exception as rollback_exc:
            _log.debug("rollback failed during identity migration: %s", rollback_exc)
        _log.error(
            "identity schema migration failed; vault unchanged (backup at %s)",
            backup_path,
        )
        raise
