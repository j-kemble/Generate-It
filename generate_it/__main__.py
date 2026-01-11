"""Generate It entrypoint.

Runs the curses TUI for generating passwords, passphrases, and usernames.
"""

from __future__ import annotations

from . import tui


def main(argv: list[str] | None = None) -> int:
    """Run the TUI."""
    return tui.run()


if __name__ == "__main__":
    raise SystemExit(main())
