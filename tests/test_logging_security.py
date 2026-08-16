from __future__ import annotations

import logging
from pathlib import Path

import pytest

from generate_it import logging as app_logging


def test_symlink_log_path_is_rejected(tmp_path: Path) -> None:
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
