"""Generate It entrypoint.

Allows:
- `python -m generate_it`
- console script `generate-it` (when packaged)
"""

from __future__ import annotations

import argparse
import sys

from . import cli


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="generate-it")
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Run the prompt-based CLI instead of the curses terminal UI.",
    )
    args = parser.parse_args(argv)

    if args.cli:
        return cli.run()

    # If we're not in a real interactive terminal, curses won't work well.
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return cli.run()

    try:
        from . import tui
    except ModuleNotFoundError as exc:
        if exc.name in {"curses", "_curses"}:
            print(
                "Curses TUI unavailable; falling back to CLI.\n"
                "On Windows, install the TUI support with: pip install generate-it[tui]",
                file=sys.stderr,
            )
            return cli.run()
        raise

    return tui.run()


if __name__ == "__main__":
    raise SystemExit(main())
