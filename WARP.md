# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project summary
Generate It is a terminal credential generator and local manager featuring a curses-based TUI for:
- **Generating Random Passwords**: configurable length and categories.
- **Generating Random Passphrases**: configurable word count with optional insertion.
- **Generating Random Usernames**: three styles (adjective+noun, random chars, or multiple words).
- **Secure Local Storage**: AES-encrypted vault for storing and managing generated credentials.

Core logic lives in `generate_it/generator.py` and `generate_it/storage.py`. The curses TUI in `generate_it/tui.py` is the primary interface.

## Common commands
### Setup (editable install)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```
New dependencies: `platformdirs`, `cryptography`, `pyperclip`.

### Run
```bash
generate-it
```
On first run, you will be prompted to create a **Master Password**. Subsequent runs require this password to unlock the encrypted vault.

### Tests
```bash
python -m pytest
```
Tests cover generation invariants (`tests/test_generator.py`) and secure storage/encryption logic (`tests/test_storage.py`).

## Architecture / code map
### Entrypoints
- `generate_it/__main__.py`: Initializer. Handles the startup sequence:
  1. Checks if vault exists (via `StorageManager`).
  2. Triggers **Setup** (first run) or **Login** (unlock) modals.
  3. Launches the main TUI loop once unlocked.

### Storage & Security
`generate_it/storage.py` handles the local SQLite database and encryption:
- **Location**: Uses `platformdirs` to store `vault.db` in standard user data paths (e.g., `~/.local/share/generate-it/`).
- **Encryption**: Uses `cryptography.fernet`. The key is derived from the Master Password + a unique salt using **PBKDF2HMAC** (100k iterations).
- **Data**: Credentials (service, username, password) are stored as encrypted blobs.

### Curses TUI
`generate_it/tui.py` contains the dashboard and modal systems:
- **Global Hotkeys**:
  - `g`: Generate new credential.
  - `v`: Open **Vault Explorer** modal.
  - `q`: Quit.
- **Save Flow**:
  - In Generator modes, clicking **[ Save ]** prompts for Service and Username/Password.
  - **Tab**: In any save-dialog input field, press Tab to generate a random value (username or password) on the fly.
- **Vault Explorer (`v`)**:
  - File-browser style navigation (`↑/↓`).
  - `Enter`: View full details.
  - `c`: Copy Password to clipboard (`pyperclip`).
  - `u`: Copy Username to clipboard.
  - `d`: Delete entry (requires "yes" confirmation).

## Wordlist customization
The env var used to point at a custom word list is `GENERATE_IT_WORDLIST`.