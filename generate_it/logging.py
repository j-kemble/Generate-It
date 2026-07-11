"""Rotating file logger for Generate-It.

Logs go to ``<data_dir>/generate-it.log`` by default (1 MB × 3 backups).
Never log passwords, keys, or credential contents.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from platformdirs import user_data_dir

APP_NAME = "generate-it"
APP_AUTHOR = "j-kemble"

_DEFAULT_LOG_PATH = Path(user_data_dir(APP_NAME, APP_AUTHOR)) / "generate-it.log"

_FORMATTER = logging.Formatter(
    "%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

_initialised = False


def init_logging(
    log_path: Path | None = None,
    level: int = logging.WARNING,
) -> None:
    """Initialise rotating file logging.

    Call once at startup.  Subsequent calls are no-ops.
    """
    global _initialised
    if _initialised:
        return
    _initialised = True

    root = logging.getLogger()
    path = log_path or _DEFAULT_LOG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    # Create an empty file first so RotatingFileHandler can append.
    path.touch(exist_ok=True)

    handler = RotatingFileHandler(
        path, maxBytes=1_048_576, backupCount=3, encoding="utf-8", delay=True
    )
    handler.setFormatter(_FORMATTER)
    handler.setLevel(level)

    root.setLevel(level)
    root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Return a child logger for *name* (e.g. ``"storage"``, ``"tui"``)."""
    return logging.getLogger(name)


def _reset_logging() -> None:
    """Remove all handlers and clear the initialised flag.  Test helper only."""
    global _initialised
    _initialised = False
    root = logging.getLogger()
    for h in root.handlers[:]:
        h.close()
        root.removeHandler(h)
