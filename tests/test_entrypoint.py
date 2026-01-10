from __future__ import annotations

import sys

import pytest

import generate_it.__main__ as entry


def test_main_cli_flag_runs_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    called = {"count": 0}

    def fake_run() -> int:
        called["count"] += 1
        return 42

    monkeypatch.setattr(entry.cli, "run", fake_run)

    assert entry.main(["--cli"]) == 42
    assert called["count"] == 1


def test_main_non_tty_falls_back_to_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    called = {"count": 0}

    def fake_run() -> int:
        called["count"] += 1
        return 0

    monkeypatch.setattr(entry.cli, "run", fake_run)

    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)

    assert entry.main([]) == 0
    assert called["count"] == 1
