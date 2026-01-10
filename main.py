#!/usr/bin/env python3
"""Generate It - terminal password generator.

Runs the curses-based terminal UI by default.
Use `--cli` for a simple prompt-based interface.
"""

from __future__ import annotations

import argparse
import sys

from generate_it import cli, tui


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

    return tui.run()


if __name__ == "__main__":
    raise SystemExit(main())
