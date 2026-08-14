# AGENTS.md

This file provides guidance to AI coding agents (Warp, Claude Code, Codex, Cursor, and similar tools) when working with code in this repository.

## Project summary
Generate It is a terminal credential generator and local manager featuring a curses-based TUI for:
- **Generating Random Passwords**: configurable length and categories.
- **Generating Random Passphrases**: configurable word count with optional insertion.
- **Generating Random Usernames**: three styles (adjective+noun, random chars, or multiple words).
- **Secure Local Storage**: AES-encrypted vault for storing and managing generated credentials.
- **Credential Management**: add/edit/delete/search/copy credentials from an encrypted local vault.
- **Note Support**: Add and view notes for each credential to store additional information.
- **CSV I/O**: import/export across multiple provider formats.
- **Security UX**: configurable clipboard auto-clear and vault auto-lock policies.

Core logic lives in `generate_it/generator.py` and the `generate_it/storage/` package (implementation in `generate_it/storage/core.py`). The curses TUI in `generate_it/tui.py` is the primary interface.

## Common commands
### Setup (editable install)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```
Dependencies include: `platformdirs`, `cryptography`, `pyperclip`.

### Run
```bash
generate-it
```
On first run, you will be prompted to create a **Master Password**. Subsequent runs require this password to unlock the encrypted vault.

### Tests
```bash
python -m pytest
```
Tests cover generation invariants (`tests/test_generator.py`), storage/encryption and CSV behavior (`tests/test_storage.py`), plus TUI helper logic (`tests/test_tui_helpers.py`).

## Architecture / code map
### Entrypoints
- `generate_it/__main__.py`: package entrypoint.
- `generate_it/tui.py:run()`: main curses app loop and startup login/setup flow.

### Storage & Security
`generate_it/storage.py` handles the local SQLite database and encryption:
- **Location**: Uses `platformdirs` to store `vault.db` in standard user data paths.
- **Encryption**: Uses `cryptography.fernet` for legacy v1 vaults. New vaults default to vault v2 with Argon2id key derivation (64 MiB memory, 3 iterations, 4 lanes) and AES-256-GCM AEAD. The key is derived from the Master Password + a unique salt using **PBKDF2HMAC** for legacy vaults (480k iterations for v1; legacy vaults remain at 100k) or **Argon2id** for v2.
- **Data**: Credentials (service, username, password, note) are stored as encrypted blobs.
- **App settings**: non-sensitive preferences are persisted in the `config` table via keys prefixed `app_setting:`.

### TUI behavior (current)
`generate_it/tui.py` contains dashboard rendering, modal input, and event handling.

#### Global hotkeys
- `g`: Generate
- `s`: Save currently generated credential
- `a`: Add credential manually
- `/`: Quick vault search (opens vault modal in search mode)
- `v`: Vault explorer
- `i`: CSV import
- `e`: CSV export
- `t`: Security settings
- `?`: Hotkey legend
- `Esc` twice: quit app

#### Save / add flow
- Save and manual add both use duplicate-safe behavior:
  - duplicates are detected by **(service, username)** (case-insensitive, trimmed)
  - user is prompted to type `overwrite` or cancel.
- Both save and add operations now include optional note field for additional information.

#### Vault explorer
- Live fuzzy search while typing.
- `Enter` details, `e` edit, `c/u` copy, `d` delete.
- Copy actions can trigger clipboard auto-clear policy.
- Details view now shows notes if they exist.

#### Security settings
Configured in-app via `t`:
- Clipboard auto-clear options:
  - `No auto-clear`, `15 seconds`, `30 seconds`, `45 seconds`, `1 minute`, `2 minutes`, `3 minutes`
- Auto-lock options:
  - `No auto-lock`, `Lock when screen off`, `5 minutes`, `10 minutes`, `15 minutes`
- Policies are persisted and reloaded from storage settings.

## Contributor notes
- Keep hotkey/help/footer text in sync with behavior whenever controls change.
- If modal behavior or key handling changes, add/adjust helper tests in `tests/test_tui_helpers.py`.
- For storage schema/logic changes, update `tests/test_storage.py` and run full `pytest`.

## Wordlist customization
The env var used to point at a custom word list is `GENERATE_IT_WORDLIST`.