from __future__ import annotations

import os

import pytest

from generate_it.storage import StorageError, StorageManager


def test_required_storage_permission_failure_is_raised(tmp_path, monkeypatch) -> None:
    path = tmp_path / "vault.db"

    def fail_chmod(*args, **kwargs):
        raise OSError("chmod failed")

    monkeypatch.setattr(os, "chmod", fail_chmod)

    with pytest.raises(StorageError, match="permissions"):
        StorageManager._ensure_private_permissions(path, 0o600)
