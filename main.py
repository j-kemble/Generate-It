#!/usr/bin/env python3
"""Generate It convenience entrypoint.

This file exists so you can run the app from a source checkout:

- `python3 main.py`

For the installable entrypoint, use:

- `python -m generate_it`
- `generate-it`
"""

from __future__ import annotations

from generate_it.__main__ import main


if __name__ == "__main__":
    raise SystemExit(main())
