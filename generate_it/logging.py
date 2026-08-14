"""Rotating file logger for Generate-It.

Logs go to ``<data_dir>/generate-it.log`` by default (1 MB × 3 backups).
Never log passwords, keys, or credential contents.

All log directories and files are created owner-only on POSIX systems
regardless of the prevailing umask. Windows uses its native filesystem ACLs.
"""

from __future__ import annotations

import logging
import os
import stat
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


class LoggingError(RuntimeError):
    """Raised when secure log-file setup cannot be completed."""


class _PrivateRotatingFileHandler(RotatingFileHandler):
    """RotatingFileHandler that keeps rotated files owner-only on POSIX."""

    def _open(self):
        if os.name != "posix":
            return super()._open()
        flags = os.O_WRONLY | os.O_CREAT
        if "a" in self.mode:
            flags |= os.O_APPEND
        elif "w" in self.mode:
            flags |= os.O_TRUNC
        no_follow = getattr(os, "O_NOFOLLOW", None)
        if no_follow is None:
            raise LoggingError("Secure no-follow file opening is unavailable.")
        fd = os.open(self.baseFilename, flags | no_follow, 0o600)
        try:
            file_stat = os.fstat(fd)
            if not stat.S_ISREG(file_stat.st_mode):
                raise LoggingError("Log path is not a regular file.")
            return os.fdopen(fd, self.mode, encoding=self.encoding, errors=self.errors)
        except BaseException:
            os.close(fd)
            raise

    def doRollover(self) -> None:
        super().doRollover()
        # After rotation the just-rotated file sits at <base>.1 — tighten it
        # and any pre-existing backup files in case they were created before
        # this protection was added.
        if os.name != "posix":
            return
        if hasattr(os, "chmod"):
            for idx in range(1, self.backupCount + 1):
                rotated = Path(self.baseFilename).with_suffix(
                    Path(self.baseFilename).suffix + f".{idx}"
                )
                if rotated.exists():
                    if rotated.is_symlink():
                        raise LoggingError("Rotated log path is a symlink.")
                    try:
                        fd = os.open(str(rotated), os.O_RDONLY | os.O_NOFOLLOW)
                        try:
                            os.fchmod(fd, 0o600)
                        finally:
                            os.close(fd)
                    except OSError as exc:
                        raise LoggingError("Could not secure rotated log file.") from exc


def _set_private(path: Path, mode: int) -> None:
    """Set *path* to *mode* on POSIX systems."""
    if os.name != "posix":
        return
    if hasattr(os, "chmod"):
        if path.is_symlink():
            raise LoggingError(f"Refusing symlinked path: {path}.")
        try:
            os.chmod(str(path), mode)
        except OSError as exc:
            raise LoggingError(f"Could not set permissions on {path}.") from exc


def _prepare_log_file(path: Path) -> None:
    """Create or validate a regular owner-only log file without following links."""
    try:
        file_stat = path.lstat()
    except FileNotFoundError:
        file_stat = None
    except OSError as exc:
        raise LoggingError(f"Could not inspect log path {path}.") from exc

    if file_stat is not None:
        if stat.S_ISLNK(file_stat.st_mode):
            raise LoggingError("Log path is a symlink.")
        if not stat.S_ISREG(file_stat.st_mode):
            raise LoggingError("Log path is not a regular file.")

    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise LoggingError("Secure no-follow file opening is unavailable.")
    try:
        fd = os.open(str(path), flags | no_follow, 0o600)
    except OSError as exc:
        raise LoggingError(f"Could not create or open log path {path}.") from exc
    try:
        opened_stat = os.fstat(fd)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise LoggingError("Log path is not a regular file.")
    finally:
        os.close(fd)
    fd = os.open(str(path), os.O_RDONLY | no_follow)
    try:
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


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

    root = logging.getLogger()
    path = log_path or _DEFAULT_LOG_PATH
    handler: _PrivateRotatingFileHandler | None = None
    try:
        current = path.parent
        missing: list[Path] = []
        while not current.exists() and current != current.parent:
            missing.append(current)
            current = current.parent
        if current.is_symlink():
            raise LoggingError("Log parent contains a symlink.")
        for directory in reversed(missing):
            directory.mkdir()
            _set_private(directory, 0o700)
        if path.parent.is_symlink():
            raise LoggingError("Log parent is a symlink.")
        _set_private(path.parent, 0o700)
        _prepare_log_file(path)
        handler = _PrivateRotatingFileHandler(
            path, maxBytes=1_048_576, backupCount=3, encoding="utf-8", delay=True
        )
        handler.setFormatter(_FORMATTER)
        handler.setLevel(level)
        old_level = root.level
        try:
            root.setLevel(level)
            root.addHandler(handler)
        except BaseException:
            root.setLevel(old_level)
            raise
    except BaseException:
        if handler is not None:
            handler.close()
        raise
    _initialised = True


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
