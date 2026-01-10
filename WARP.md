# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project summary
Generate It is a terminal password/passphrase generator with two frontends:
- **Curses TUI** (default when running in an interactive terminal)
- **Prompt-based CLI** (fallback when curses isn’t available, or when `--cli` is provided)

Core generation logic lives in `generate_it/generator.py` and is used by both UIs.

## Common commands
### Setup (editable install)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Windows note: the full-screen TUI uses curses. If you’re on Windows and want the TUI, install with:

```bash
pip install -e ".[tui]"
```

### Run
After installing:
```bash
generate-it
generate-it --cli
```

From a source checkout (no install):
```bash
python3 main.py
python3 main.py --cli
```

Module entrypoint (equivalent to the console script):
```bash
python -m generate_it
python -m generate_it --cli
```

### Tests
CI runs a smoke test script and a small pytest suite:

```bash
python scripts/smoke_test.py
python -m pytest
```

Run a single test:

```bash
python -m pytest tests/test_generator.py::test_generate_character_password_invariants
```

### Build (sdist/wheel)
Packaging is defined in `pyproject.toml` (setuptools backend). To build locally:

```bash
python -m pip install build
python -m build
```

### Lint / typecheck
No dedicated lint/typecheck tooling is configured in this repo yet.

## Architecture / code map
### Entrypoints
- `main.py`: convenience runner for source checkouts; delegates to `generate_it.__main__.main()`.
- `generate_it/__main__.py`: installable entrypoint (`python -m generate_it` and the `generate-it` console script).
  - `--cli` forces the prompt-based UI (`generate_it/cli.py`).
  - If stdin/stdout aren’t TTYs, it auto-falls back to the CLI (curses doesn’t work well non-interactively).
  - If importing curses fails (notably on Windows), it prints a hint about the `[tui]` extra and falls back to the CLI.

### Core generation (UI-agnostic)
`generate_it/generator.py` contains the logic shared by both frontends:
- `generate_character_password(...)`: validates length (8–24), requires 2–3 selected categories, and guarantees at least one character from each selected category.
- `generate_passphrase(...)`: selects words **without replacement** and optionally inserts digits/special characters into random words.
- `load_wordlist(...)`: wordlist lookup priority:
  1) explicit `path` argument
  2) `$GENERATE_IT_WORDLIST`
  3) `./wordlist.txt` in the current working directory
  4) packaged default `generate_it/wordlist.txt`
  Falls back to a small built-in list if the file is missing or too small.

### Prompt-based CLI
- `generate_it/cli.py`: interactive prompts for mode/options.
  - Keeps a `seen_passphrases` set to avoid repeating the same passphrase during a single run.

### Curses TUI
- `generate_it/tui.py`: dashboard-style curses app.
  - `AppState` holds the current mode, options, output, and focus.
  - Rendering is split into panel renderers (MODE / SETTINGS / ACTIONS / OUTPUT / INFO).
  - Calls `generator.*` and enforces the “select at least 2 categories” rule at the UI layer as well.

## Wordlist customization
The env var used to point at a custom word list is `GENERATE_IT_WORDLIST`. See the “Custom word list” section in `README.md` and the implementation in `generate_it/generator.py` for exact precedence and fallback behavior.
