"""Unit tests for the logging module."""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

import pytest

from generate_it.logging import (
    init_logging,
    get_logger,
    _reset_logging,
    _PrivateRotatingFileHandler,
)
from generate_it.storage import StorageManager


# ── helpers ──────────────────────────────────────────────────────────

def _flush_and_close(root: logging.Logger) -> None:
    """Flush and remove all handlers on *root*, then reset logging."""
    for h in root.handlers[:]:
        h.flush()
        h.close()
        root.removeHandler(h)
    _reset_logging()


def _file_mode(path: Path) -> int:
    """Return POSIX permission bits of *path* (e.g. 0o600)."""
    if os.name != "posix":
        pytest.skip("Unix permission bits are not supported on Windows")
    return stat.S_IMODE(path.stat().st_mode)


# ── existing tests (unchanged behaviour) ─────────────────────────────

def test_init_creates_log_file(tmp_path: Path) -> None:
    _reset_logging()
    log_path = tmp_path / "test.log"
    init_logging(log_path=log_path, level=logging.DEBUG)
    logger = get_logger("test")

    logger.debug("debug msg")
    logger.info("info msg")
    logger.warning("warn msg")
    logger.error("error msg")

    root = logging.getLogger()
    _flush_and_close(root)

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
    _flush_and_close(root)

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
    _flush_and_close(root)

    content = log_path.read_text()
    assert "[storage]" in content
    assert "[tui]" in content


# ── new tests: private permissions (Task 6) ──────────────────────────

def test_log_dir_is_0700_under_restrictive_umask(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Log directory must be 0700 even when umask is 022."""
    _reset_logging()

    log_dir = tmp_path / "logs"
    log_path = log_dir / "app.log"

    old_umask = os.umask(0o022)
    try:
        init_logging(log_path=log_path)
    finally:
        os.umask(old_umask)

    root = logging.getLogger()
    _flush_and_close(root)

    assert log_dir.exists()
    assert _file_mode(log_dir) == 0o700, (
        f"Expected 0o700, got {oct(_file_mode(log_dir))} "
        f"(old umask was {oct(old_umask)})"
    )


def test_active_log_file_is_0600(tmp_path: Path) -> None:
    """The active log file must be owner-only (0600)."""
    _reset_logging()
    log_path = tmp_path / "app.log"
    init_logging(log_path=log_path)

    root = logging.getLogger()
    _flush_and_close(root)

    assert log_path.exists()
    assert _file_mode(log_path) == 0o600, (
        f"Expected 0o600, got {oct(_file_mode(log_path))}"
    )


def test_log_dir_created_by_init_logging_is_0700(tmp_path: Path) -> None:
    """When init_logging creates the directory, it must be 0700."""
    _reset_logging()

    log_dir = tmp_path / "nested" / "logs"
    log_path = log_dir / "app.log"

    init_logging(log_path=log_path)

    root = logging.getLogger()
    _flush_and_close(root)

    assert log_dir.exists()
    assert _file_mode(log_dir) == 0o700, (
        f"Expected 0o700, got {oct(_file_mode(log_dir))}"
    )


def test_rotated_log_file_is_0600(tmp_path: Path) -> None:
    """After rotation, the rotated backup file must be 0600."""
    log_path = tmp_path / "rotate.log"
    rotate_path = tmp_path / "rotate.log.1"

    # Use a tiny maxBytes so a single message triggers rotation.
    handler = _PrivateRotatingFileHandler(
        str(log_path), maxBytes=100, backupCount=2, encoding="utf-8"
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-8s [%(name)s] %(message)s")
    )

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)

    # Write enough to trigger at least one rotation.
    for i in range(50):
        logging.info("padding message to fill log and trigger rotation %d", i)

    _flush_and_close(root)

    assert rotate_path.exists(), "Rotation did not produce a backup file"
    assert _file_mode(rotate_path) == 0o600, (
        f"Expected rotated file 0o600, got {oct(_file_mode(rotate_path))}"
    )


# ── new tests: metadata-free logging (Task 6) ────────────────────────

def test_no_identifying_info_in_credential_save_logs(
    tmp_path: Path,
) -> None:
    """At INFO level, credential-save must NOT log service or username."""
    _reset_logging()

    log_path = tmp_path / "vault.log"
    init_logging(log_path=log_path, level=logging.INFO)

    # Create a real vault and save a credential.
    db_path = tmp_path / "vault.db"
    master = "A-Secure-Master-Passw0rd!"
    service = "GitHub"
    username = "alice@example.com"

    storage = StorageManager(db_path=db_path)
    storage.initialize_vault(master)
    storage.save_credential(service, username, "s3cret-password2026!")
    storage.close()

    root = logging.getLogger()
    _flush_and_close(root)

    content = log_path.read_text()
    # The service and username MUST NOT appear in the log.
    assert service not in content, (
        f"Service name '{service}' leaked into log: {content!r}"
    )
    assert username not in content, (
        f"Username '{username}' leaked into log: {content!r}"
    )
    # But the structured "credential saved (id=%d)" message must appear.
    assert "credential saved (id=" in content, (
        "Expected non-identifying save message in log"
    )


def test_no_identifying_info_in_credential_v2_save_logs(
    tmp_path: Path,
) -> None:
    """At INFO level, v2 credential-save must NOT log service or username."""
    _reset_logging()

    log_path = tmp_path / "vault.log"
    init_logging(log_path=log_path, level=logging.INFO)

    db_path = tmp_path / "vault.db"
    master = "A-Secure-Master-Passw0rd!"
    service = "GitLab"
    username = "bob@example.com"

    storage = StorageManager(db_path=db_path)
    storage.initialize_vault_v2(master)
    storage.save_credential(service, username, "s3cret-password2026!")
    storage.close()

    root = logging.getLogger()
    _flush_and_close(root)

    content = log_path.read_text()
    assert service not in content, (
        f"Service name '{service}' leaked into v2 log: {content!r}"
    )
    assert username not in content, (
        f"Username '{username}' leaked into v2 log: {content!r}"
    )
    assert "credential saved (id=" in content, (
        "Expected non-identifying save message in v2 log"
    )
