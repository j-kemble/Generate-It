"""Security regression tests for the TUI layer."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from generate_it import tui
from generate_it import tui_modal


def test_username_save_flow_masks_password_prompt(monkeypatch) -> None:
    """The username-mode save flow MUST call _run_modal with is_password=True."""
    state = tui.AppState()
    state.mode = "username"
    state.output = "testuser123"
    state.vault_unlocked = True
    state.storage = MagicMock(name="StorageManager")

    theme = SimpleNamespace(title=0, dim=0, ok=1, warn=2, border=0)
    stdscr = MagicMock(name="stdscr")

    call_args: list[dict] = []

    def _fake_run_modal(
        stdscr_,
        theme_,
        title,
        prompt,
        *,
        is_password=False,
        generator_func=None,
        **__: object,
    ):
        call_args.append({"prompt": prompt, "is_password": is_password})
        # Return a value for the service prompt, then a password for the password prompt
        if "Service" in prompt:
            return "example.com"
        if "Password" in prompt:
            return "testpassword"
        return ""

    monkeypatch.setattr(tui_modal, "_run_modal", _fake_run_modal)

    tui._run_save_generated_flow(stdscr, theme, state)

    # Find the password-prompt call
    password_calls = [
        c for c in call_args if "Password" in c["prompt"]
    ]
    assert len(password_calls) == 1, (
        f"Expected 1 password-prompt call, got {len(password_calls)}: {call_args}"
    )
    assert password_calls[0]["is_password"] is True, (
        "Password prompt MUST be masked (is_password=True)"
    )
