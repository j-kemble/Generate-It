# Generate It

A terminal credential generator and local manager with a curses-based UI.

It can generate:
- **Random passwords** (choose a length and character categories)
- **Random passphrases** (random words separated by hyphens)
- **Random usernames** (adjective+noun, random characters, or word combinations)

**New:** Now features a **secure local vault** to save and manage your credentials directly from the TUI.

## Install

### From PyPI (recommended)

Requires Python 3.10-3.13 and pip.

```bash
pip install generate-it
```

Then run:

```bash
generate-it
```

### From source (for development)

```bash
git clone https://github.com/j-kemble/Generate-It.git
cd Generate-It
python3 -m venv .venv

# Linux/macOS
source .venv/bin/activate

# Windows (PowerShell)
# .\venv\Scripts\Activate.ps1

pip install -e .
```

Then run:

```bash
generate-it
```

## Features

### Secure Vault
Generate It includes an encrypted local vault to store your generated credentials.
- **Encryption**: Uses AES-256 (via `cryptography`) to secure your data locally.
- **Master Password**: You create a master password on first run. This key is never stored; it unlocks your vault each session.
- **Offline**: Your data stays on your machine (`~/.local/share/generate-it/` on Linux).
- **Clipboard**: Quickly copy passwords or usernames with hotkeys.

### Controls

- **General Navigation**:
  - `Tab` / `Shift-Tab` or `Arrow keys`: move focus
  - `Space`: toggle checkboxes / options
  - `Left`/`Right`: adjust numeric values
  - `Enter`: confirm action
  - `q` (or `ESC`): quit

- **Hotkeys**:
  - `g`: Generate new credential
  - `s`: Save the currently generated credential
  - `/`: Quick vault search (opens vault search mode)
  - `v`: Open **Vault Explorer**
  - `i`: Import credentials from CSV
  - `e`: Export credentials to CSV

### Vault Explorer (`v`)
- `↑/↓`: Navigate your saved credentials
- `Enter`: View credential details
- `e`: Edit credential
- `c`: Copy Password to clipboard
- `u`: Copy Username to clipboard
- `d`: Delete credential (requires confirmation)
- `/`: Start live fuzzy search (results update as you type)
- `Esc`: Close vault

### Saving Credentials
When you generate a credential you will:
1. Press **`s`** (or select **[ Save ]**).
2. Enter a **Service Name** (e.g., "GitHub").
3. Enter a **Username** or **Password** (whichever wasn't generated).
   - **Pro Tip**: Press **`Tab`** in these fields to instantly generate a random username or password on the fly!

### CSV Import/Export
- **Export**: Press `e`, choose an export format, then enter a file path. If the file already exists, you must confirm overwrite.
  - If any credentials fail to decrypt during export, you'll see a list of skipped entries.
- **Import**: Press `i`, choose an import format (or `auto`), then enter a CSV file path.
  - The importer detects duplicates (case-insensitive match on **service name + username**) and asks whether to **merge (overwrite)** or **ignore** them.
  - Rows with missing required fields or unsupported record types are skipped with an issue report.
- **Supported formats**:
  - `generic` (browser-style): `name,url,username,password,note`
  - `bitwarden`: supports login CSV fields (`name`, `login_username`, `login_password`, `type`, etc.). Non-login item types are skipped.
  - `apple`: supports Apple-style title/url/username/password exports (with optional notes/OTP columns).
  - `nordpass`: supports NordPass CSV template columns.
- **Data model note**: The vault currently stores only `service`, `username`, and `password`.
  - During export, unsupported provider fields (folder, notes, TOTP, cards, custom fields, etc.) are emitted as empty/default values.
  - During import, unsupported/non-credential rows are ignored with a reason.

## How it works

### Random passwords (characters)

- Length options: **8–64** characters
- Choose **2 or 3** categories from:
  - letters
  - numbers
  - special characters

### Random passphrases (words)

- Word options: **3–10** words
- Words are joined with hyphens (e.g. `forest-ember-spark`)
- Words are chosen **without replacement** (no repeated words within a single passphrase)
- Optional extras:
  - add numbers (randomly inserted into words)
  - add special characters (randomly inserted into words)

### Random usernames

**Three generation styles:**

1. **Adjective + Noun** (e.g. `swift_tiger`, `cosmic_eagle_42`)
   - Memorable and easy to pronounce
   - Optionally add 2-3 digit suffix
   - Separator options: underscore or hyphen

2. **Random Characters** (e.g. `a7k9m2p1`, `ab_3d_ef`)
   - Maximum security and randomness
   - Length: **3–25** characters
   - Separator options: none, underscore, or hyphen

3. **Multiple Words** (e.g. `swift_tiger_eagle`, `forest_ocean_123`)
   - Memorable yet more unique
   - Word count: **1–3** words
   - Optionally add digit suffix
   - Separator options: underscore or hyphen

## Custom word list

The included word list contains **1000** lowercase words.

Override the word list in one of these ways (highest priority first):

1) Set `GENERATE_IT_WORDLIST` to a file path
2) Put a `wordlist.txt` in your current working directory

Otherwise, Generate It uses the bundled default word list.

## License

Generate It is licensed under the **GNU Affero General Public License v3.0 or later** (**AGPL-3.0-or-later**). See `LICENSE`.