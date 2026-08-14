from __future__ import annotations

import logging
from pathlib import Path

import pytest

from generate_it import logging as app_logging


def test_logging_rejects_symlinked_parent(tmp_path: Path) -> None:
    app_logging._reset_logging()
    target = tmp_path / "target"
    target.mkdir()
    parent = tmp_path / "logs"
    parent.symlink_to(target, target_is_directory=True)

    with pytest.raises(app_logging.LoggingError, match="symlink"):
        app_logging.init_logging(log_path=parent / "app.log")


def test_logging_restores_root_level_when_handler_install_fails(tmp_path: Path, monkeypatch) -> None:
    app_logging._reset_logging()
    root = logging.getLogger()
    old_level = root.level
    original_add_handler = root.addHandler
    monkeypatch.setattr(root, "addHandler", lambda handler: (_ for _ in ()).throw(OSError("add failed")))

    try:
        with pytest.raises(OSError, match="add failed"):
            app_logging.init_logging(log_path=tmp_path / "app.log", level=logging.INFO)
    finally:
        monkeypatch.setattr(root, "addHandler", original_add_handler)
        app_logging._reset_logging()

    assert root.level == old_level


def test_private_handler_honors_write_mode(tmp_path: Path) -> None:
    path = tmp_path / "app.log"
    path.write_text("old\n", encoding="utf-8")
    handler = app_logging._PrivateRotatingFileHandler(path, mode="w", delay=False)
    try:
        handler.emit(logging.LogRecord("test", logging.INFO, "", 0, "new", (), None))
    finally:
        handler.close()
    assert path.read_text(encoding="utf-8") == "new\n"


def test_storage_connection_is_cleared_when_permission_check_fails(tmp_path: Path, monkeypatch) -> None:
    from generate_it.storage import StorageError, StorageManager

    storage = StorageManager(db_path=tmp_path / "vault.db")
    original_permissions = storage._ensure_private_permissions
    monkeypatch.setattr(
        storage,
        "_ensure_private_permissions",
        lambda *args, **kwargs: (_ for _ in ()).throw(StorageError("permissions failed")),
    )
    with pytest.raises(StorageError, match="permissions failed"):
        storage._get_conn()
    assert storage._db_connection is None
    monkeypatch.setattr(storage, "_ensure_private_permissions", original_permissions)
    storage.close()


def test_permission_regression_is_posix_only(monkeypatch) -> None:
    if app_logging.os.name != "posix":
        pytest.skip("owner-only chmod is POSIX-specific")
