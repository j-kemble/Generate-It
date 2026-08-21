from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

from generate_it import logging as app_logging


def _reset() -> None:
    app_logging._reset_logging()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink/directory checks not applicable on Windows")
def test_init_logging_rejects_existing_symlink(tmp_path: Path) -> None:
    _reset()
    victim = tmp_path / "victim.log"
    victim.write_text("original")
    link = tmp_path / "app.log"
    link.symlink_to(victim)

    with pytest.raises(app_logging.LoggingError, match="symlink"):
        app_logging.init_logging(log_path=link)

    assert victim.read_text() == "original"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory check not applicable on Windows")
def test_init_logging_rejects_existing_directory(tmp_path: Path) -> None:
    _reset()
    log_path = tmp_path / "app.log"
    log_path.mkdir()

    with pytest.raises(app_logging.LoggingError, match="regular file"):
        app_logging.init_logging(log_path=log_path)


def test_logging_can_retry_after_setup_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _reset()
    log_path = tmp_path / "app.log"
    original_handler = app_logging._PrivateRotatingFileHandler

    def fail_once(*args, **kwargs):
        monkeypatch.setattr(app_logging, "_PrivateRotatingFileHandler", original_handler)
        raise OSError("handler setup failed")

    monkeypatch.setattr(app_logging, "_PrivateRotatingFileHandler", fail_once)
    with pytest.raises(OSError, match="handler setup failed"):
        app_logging.init_logging(log_path=log_path)

    app_logging.init_logging(log_path=log_path, level=logging.INFO)
    try:
        app_logging.get_logger("retry").info("initialized after retry")
    finally:
        _reset()

    assert "initialized after retry" in log_path.read_text()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX chmod not enforced on Windows")
def test_permission_failure_is_not_silenced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _reset()
    log_path = tmp_path / "app.log"

    def fail_chmod(*args, **kwargs):
        raise OSError("chmod failed")

    monkeypatch.setattr(app_logging.os, "chmod", fail_chmod)
    with pytest.raises(app_logging.LoggingError, match="permissions"):
        app_logging.init_logging(log_path=log_path)
