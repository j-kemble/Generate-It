from __future__ import annotations

import logging
from pathlib import Path

import pytest

from generate_it import logging as app_logging


def test_non_posix_log_file_setup_uses_normal_file_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_path = tmp_path / "app.log"
    monkeypatch.setattr(app_logging.os, "name", "nt")
    monkeypatch.delattr(app_logging.os, "O_NOFOLLOW", raising=False)

    assert app_logging._prepare_log_file(log_path) is True
    assert log_path.is_file()
    assert app_logging._prepare_log_file(log_path) is False


def test_non_posix_log_file_setup_uses_atomic_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_path = tmp_path / "app.log"
    monkeypatch.setattr(app_logging.os, "name", "nt")
    monkeypatch.delattr(app_logging.os, "O_NOFOLLOW", raising=False)

    def fail_exists(self: Path) -> bool:
        raise AssertionError("non-POSIX setup must not pre-check path existence")

    monkeypatch.setattr(Path, "exists", fail_exists)

    assert app_logging._prepare_log_file(log_path) is True


def test_symlink_log_path_is_rejected(tmp_path: Path) -> None:
    if app_logging.os.name != "posix":
        pytest.skip("Symlink rejection is a POSIX-only logging guarantee")
    app_logging._reset_logging()
    target = tmp_path / "target.log"
    target.write_text("protected", encoding="utf-8")
    link = tmp_path / "app.log"
    link.symlink_to(target)

    with pytest.raises(app_logging.LoggingError, match="symlink"):
        app_logging.init_logging(link)

    assert target.read_text(encoding="utf-8") == "protected"
    assert app_logging._initialised is False


def test_setup_failure_does_not_latch_initialised(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app_logging._reset_logging()
    log_path = tmp_path / "app.log"
    monkeypatch.setattr(app_logging, "_set_private", lambda path, mode: (_ for _ in ()).throw(OSError("denied")))

    with pytest.raises(OSError, match="denied"):
        app_logging.init_logging(log_path)

    assert app_logging._initialised is False

    monkeypatch.undo()
    app_logging.init_logging(log_path)
    assert app_logging._initialised is True
    app_logging._reset_logging()
    assert not any(isinstance(handler, logging.FileHandler) for handler in logging.getLogger().handlers)
