from __future__ import annotations

import pytest

import generate_it.__main__ as entry


def test_main_runs_tui(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that main() calls tui.run()."""
    called = {"count": 0}

    def fake_run() -> int:
        called["count"] += 1
        return 0

    monkeypatch.setattr(entry.tui, "run", fake_run)

    assert entry.main() == 0
    assert called["count"] == 1
