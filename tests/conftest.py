"""Shared fixtures for the Generate-It test suite."""

from __future__ import annotations

import pytest

from generate_it.storage import StorageManager


@pytest.fixture
def temp_storage(tmp_path):
    """Temporary StorageManager with a fresh database path."""
    db_path = tmp_path / "test_vault.db"
    storage = StorageManager(db_path=db_path)
    yield storage
    storage.close()


@pytest.fixture
def temp_storage_initialized(tmp_path):
    """Temporary StorageManager initialized with a default master password."""
    db_path = tmp_path / "initialized_vault.db"
    storage = StorageManager(db_path=db_path)
    storage.initialize_vault("a-strong-master-password-for-tests")
    yield storage
    storage.close()
