# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project summary
Generate It is a terminal credential generator featuring a curses-based TUI for generating:
- **Random passwords** (configurable length and character categories)
- **Random passphrases** (configurable word count with optional number/special char insertion)
- **Random usernames** (three styles: adjective+noun, random characters, or multiple words)

Core generation logic lives in `generate_it/generator.py`, and the curses TUI in `generate_it/tui.py` is the only user-facing interface.

## Common commands
### Setup (editable install)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Note: `windows-curses` is automatically installed as a dependency on Windows to support the TUI.

### Run
After installing:
```bash
generate-it
```

From a source checkout (no install):
```bash
python3 main.py
```

Module entrypoint (equivalent to the console script):
```bash
python -m generate_it
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
  - Directly launches the TUI (`generate_it/tui.py`).
  - On Windows, `windows-curses` is automatically installed as a dependency.

### Core generation (UI-agnostic)
`generate_it/generator.py` contains the core generation logic used by the TUI:
- `generate_character_password(...)`: validates length (8–24), requires 2–3 selected categories, and guarantees at least one character from each selected category.
- `generate_passphrase(...)`: selects words **without replacement** and optionally inserts digits/special characters into random words.
- `generate_username_adjective_noun(...)`: combines random adjective + noun with optional number suffix.
- `generate_username_random(...)`: generates random alphanumeric usernames (3–25 chars) with optional separators.
- `generate_username_words(...)`: combines 1–3 random words with optional numbers and separators.
- `load_wordlist(...)`: wordlist lookup priority:
  1) explicit `path` argument
  2) `$GENERATE_IT_WORDLIST`
  3) `./wordlist.txt` in the current working directory
  4) packaged default `generate_it/wordlist.txt`
  Falls back to a small built-in list if the file is missing or too small.

### Curses TUI
- `generate_it/tui.py`: dashboard-style curses application.
  - `AppState` holds current mode (chars/words/username), options, output, and focus.
  - Three generation modes:
    1. **Characters**: password generation with category selection
    2. **Words**: passphrase generation with optional number/special char insertion
    3. **Username**: three username styles (adjective+noun, random chars, multiple words)
  - Rendering split into panel renderers (MODE / SETTINGS / ACTIONS / OUTPUT / INFO).
  - Dynamic focus system adapts available options based on selected mode and style.
  - Calls `generator.*` functions for credential generation.

## Wordlist customization
The env var used to point at a custom word list is `GENERATE_IT_WORDLIST`. See the “Custom word list” section in `README.md` and the implementation in `generate_it/generator.py` for exact precedence and fallback behavior.
