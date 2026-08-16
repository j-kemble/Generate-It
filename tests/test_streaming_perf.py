"""Tests for Phase 3: Streaming storage operations and memory efficiency."""

from __future__ import annotations

import tracemalloc
from pathlib import Path

import pytest

from generate_it.storage import StorageManager, StorageError


def test_export_thousands_of_rows_streams(tmp_path: Path) -> None:
    """Exporting thousands of rows works and produces complete CSV output."""
    db_path = tmp_path / "vault.db"
    csv_path = tmp_path / "export.csv"
    master = "A-Strong-Passw0rd!"

    storage = StorageManager(db_path=db_path)
    storage.initialize_vault_v2(master)

    # Seed 1000 rows
    conn = storage._get_conn()
    conn.execute("BEGIN")
    for i in range(1000):
        storage.save_credential(f"Service-{i:04d}", f"user-{i:04d}", f"pass-{i}")

    tracemalloc.start()
    exported, skipped = storage.export_to_csv(csv_path)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert exported == 1000
    assert skipped == []
    assert csv_path.exists()

    lines = csv_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1001  # header + 1000 rows
    assert "Service-0000" in lines[1]
    assert "Service-0999" in lines[-1]

    storage.close()


def test_v1_to_v2_migration_streams(tmp_path: Path) -> None:
    """v1->v2 migration streams rows without failing or corrupting data."""
    db_path = tmp_path / "v1.db"
    master = "A-Strong-Passw0rd!"

    storage = StorageManager(db_path=db_path)
    storage.initialize_vault(master)

    for i in range(200):
        storage.save_credential(f"Svc-{i:03d}", f"usr-{i:03d}", f"pass-{i}")

    storage.migrate_v1_to_v2(master)
    assert storage._vault_version == 2

    creds = storage.list_credentials()
    assert len(creds) == 200
    assert creds[0]["service"] == "Svc-000"
    assert creds[-1]["service"] == "Svc-199"

    storage.close()


def test_aad_v1_to_v3_migration_streams(tmp_path: Path) -> None:
    """AAD v1->v3 migration streams rows without failing or corrupting data."""
    db_path = tmp_path / "v2.db"
    master = "A-Strong-Passw0rd!"

    storage = StorageManager(db_path=db_path)
    storage.initialize_vault_v2(master)
    storage._aad_version = 1
    conn = storage._get_conn()
    conn.execute("UPDATE config SET value='1' WHERE key='aad_version'")
    conn.commit()

    for i in range(200):
        storage.save_credential(f"Svc-{i:03d}", f"usr-{i:03d}", f"pass-{i}")

    storage.migrate_aad_to_v3()
    assert storage._aad_version == 4

    creds = storage.list_credentials()
    assert len(creds) == 200
    storage.close()
