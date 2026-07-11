"""Unit tests for the logging module."""

from __future__ import annotations

import logging
from pathlib import Path

from generate_it.logging import init_logging, get_logger, _reset_logging


def test_init_creates_log_file(tmp_path: Path) -> None:
    _reset_logging()
    log_path = tmp_path / "test.log"
    init_logging(log_path=log_path, level=logging.DEBUG)
    logger = get_logger("test")

    logger.debug("debug msg")
    logger.info("info msg")
    logger.warning("warn msg")
    logger.error("error msg")

    # Flush and close
    root = logging.getLogger()
    for h in root.handlers[:]:
        h.flush()
        h.close()
        root.removeHandler(h)

    content = log_path.read_text()
    assert "DEBUG" in content
    assert "debug msg" in content
    assert "INFO" in content
    assert "WARNING" in content
    assert "ERROR" in content
    assert "[test]" in content


def test_default_level_filters_debug(tmp_path: Path) -> None:
    _reset_logging()
    log_path = tmp_path / "test.log"
    init_logging(log_path=log_path)  # default WARNING

    logger = get_logger("test")
    logger.debug("should not appear")
    logger.warning("should appear")

    root = logging.getLogger()
    for h in root.handlers[:]:
        h.flush()
        h.close()
        root.removeHandler(h)

    content = log_path.read_text()
    assert "should not appear" not in content
    assert "should appear" in content


def test_get_logger_returns_same_instance() -> None:
    a = get_logger("mod_a")
    b = get_logger("mod_a")
    assert a is b


def test_logger_name_appears_in_output(tmp_path: Path) -> None:
    _reset_logging()
    log_path = tmp_path / "test.log"
    init_logging(log_path=log_path, level=logging.DEBUG)

    get_logger("storage").info("storage event")
    get_logger("tui").info("tui event")

    root = logging.getLogger()
    for h in root.handlers[:]:
        h.flush()
        h.close()
        root.removeHandler(h)

    content = log_path.read_text()
    assert "[storage]" in content
    assert "[tui]" in content
