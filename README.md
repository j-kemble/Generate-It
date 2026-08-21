![Generate It Banner](https://raw.githubusercontent.com/j-kemble/Generate-It/development/assets/generateit-banner.png)

# Generate It

A terminal credential generator and local manager with a curses-based UI.

[![Security & Quality](https://github.com/j-kemble/Generate-It/actions/workflows/security.yml/badge.svg)](https://github.com/j-kemble/Generate-It/actions/workflows/security.yml)
[![Python Versions](https://img.shields.io/badge/python-3.10%20%7C%203.12%20%7C%203.13-blue)](https://pypi.org/project/generate-it/)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

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
.\.venv\Scripts\Activate.ps1

pip install -e .
```

Then run:

```bash
generate-it
```

## Features

### Secure Vault
Generate It includes an encrypted local vault to store your generated credentials.
- **Encryption**: Uses AES-256-GCM AEAD with Argon2id key derivation by default (vault v2). Legacy v1 vaults use Fernet (AES-128-CBC + HMAC-SHA256) with PBKDF2. Both formats are supported; v1 vaults auto-migrate on unlock.
- **Master Password**: You create a master password on first run. This key is never stored; it unlocks your vault each session.
- **Offline**: Your data stays on your machine:
  - Linux: `~/.local/share/generate-it/`
  - Windows: `C:\Users\<user>\AppData\Local\<user>\generate-it\`
- **Clipboard**: Quickly copy passwords or usernames with hotkeys.

### Controls

- **General Navigation**:
  - `Tab` / `Shift-Tab` or `Arrow keys`: move focus
  - `Space`: toggle checkboxes / options
  - `Left`/`Right`: adjust numeric values
  - `Enter`: confirm action
  - `Esc` (press twice): quit

- **Hotkeys**:
  - `g`: Generate new credential
  - `s`: Save the currently generated credential
  - `t`: Open Security Settings
  - `/`: Quick vault search (opens vault search mode)
  - `v`: Open **Vault Explorer**
  - `i`: Import credentials from CSV
  - `e`: Export credentials to CSV

### Security Settings (`t`)
- **Clipboard auto-clear** (defaults to `30 seconds`):
  - `No auto-clear`
  - `15 seconds`
  - `30 seconds`
  - `45 seconds`
  - `1 minute`
  - `2 minutes`
  - `3 minutes`
- **Auto-lock** (defaults to `5 minutes`):
  - `No auto-lock`
  - `Lock when screen off`
  - `5 minutes`
  - `10 minutes`
  - `15 minutes`

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
4. If a credential with the same **service + username** already exists (case-insensitive), you'll be prompted to **overwrite** or **cancel**.

### CSV Import/Export
- **Export**: Press `e`, choose an export format, then enter a file path. If the file already exists, you must confirm overwrite.
  - If any credentials fail to decrypt during export, you'll see a list of skipped entries.
- **Import**: Press `i`, choose an import format (or `auto`), then enter a CSV file path.
  - The importer detects duplicates (case-insensitive match on **service name + username**) and asks whether to **merge (overwrite)** or **ignore** them.
  - Rows with missing required fields or unsupported record types are skipped with an issue report.
- **Supported formats**:
  - `generic` (browser-style): `name,url,username,password,note`
  - `spreadsheet-safe`: Same structure as `generic`. All formats now escape formula-triggering characters; this format is retained for explicit spreadsheet-safe intent.
  - `bitwarden`: supports login CSV fields (`name`, `login_username`, `login_password`, `type`, etc.). Non-login item types are skipped.
  - `apple`: supports Apple-style title/url/username/password exports (with optional notes/OTP columns).
  - `nordpass`: supports NordPass CSV template columns.
- **Data model note**: The vault stores `service`, `username`, `password`, `url`, and `note` (with optional hidden flag).
  - During export, unsupported provider fields (folder, TOTP, cards, custom fields, etc.) are emitted as empty/default values.
  - During import, unsupported/non-credential rows are ignored with a reason. Imported `url` values (e.g., `login_uri`) are preserved.

> **⚠️ Security:** CSV exports are plaintext — they are not encrypted and anyone with filesystem access can read them.
> All export formats automatically escape formula-triggering characters (`=`, `+`, `-`, `@`) to prevent
> spreadsheet formula injection. However, exercise caution when opening credential exports in any application.

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

## Security

Generate It includes a comprehensive security suite to ensure credential generation is cryptographically sound:

- **Bandit**: Static security analysis to catch common Python security issues
- **pip-audit**: Automated dependency vulnerability scanning
- **mypy**: Static type checking for code quality
- **TruffleHog**: Secrets detection in commits
- **Dependabot**: Automated dependency updates
- **Entropy tests**: Automated validation that passwords meet minimum entropy thresholds
- **Reproducible builds**: Build artifacts are reproducible for verification

All security checks run automatically on every commit via GitHub Actions.

## Known Limitations

For a security-sensitive offline credential vault, the following scope limits
are documented so users can make an informed decision about acceptable risk.

- **Brute-force lockout is now persistent.** Since `0.2.4` the escalating
  unlock lockout (`30s`, `5m`, `30m`) is persisted in the vault `config` table
  (`lockout_failed_attempts`/`lockout_until_epoch`) and survives restarts. A
  successful unlock clears it. Pre-`0.2.4` vaults had process-local only lockout.
- **Migration backups are retained indefinitely.** Each one-time upgrade
  (v1→v2, identity schema, zero-width identity, AAD re-encryption) writes a
  backup next to the vault (e.g. `vault.db.identity_zw.bak`). These backups
  are encrypted with the same vault key and are never auto-deleted; prune via
  `generate-it --prune-backups 1` or `m` → `p` (pruning now orders by `st_ctime`
  not forgeable `st_mtime`). Remove obsolete backups once vault is healthy.
- **Metadata sanitization is partial.** Stored credential notes are clamped
  and truncated to a safe bound before rendering, but the raw `service` and
  `username` fields are drawn to the screen as provided. A malicious or
  unexpected value could display terminal control sequences. Only enter
  service/usernames you trust into your own vault. CSV export now escapes
  `=+-@|%` (and tab/CR-prefixed formulas via stripped check) for spreadsheet
  safety; vault search is `LIKE` on `service/username/url` (final `LIMIT 500`
  < `LIKE_LIMIT 2000`) — true FTS5 would be needed for 2B-scale.

## Custom word list

The included word list contains **7,690** lowercase words sourced from the EFF Large Wordlist (filtered to lowercase a-z, 4–10 characters), providing ~51.6 bits of entropy for a 4-word passphrase.

Override the word list with the `GENERATE_IT_WORDLIST` environment variable:

1) Set `GENERATE_IT_WORDLIST` to a file path

Otherwise, Generate It uses the bundled default word list.

## Vault maintenance

Migration and rotation operations create backups next to the vault (e.g., `vault.db.v1.bak`, `vault.db.dek.bak`, `vault.db.pwd.bak`, `vault.db.aad_v*.bak`).

- Check vault health: `generate-it --check-vault` or press `m` in the TUI (vault health view).
- Check integrity: `generate-it --check-integrity` or `m` → `c` in the TUI.
- Prune old backups: `generate-it --prune-backups 1` or `m` → `p` in the TUI (keeps newest 1).

Backups are never auto-deleted; remove obsolete backups manually once you are confident the vault is healthy.

## Development

### Setup

```bash
git clone https://github.com/j-kemble/Generate-It.git
cd Generate-It
python3 -m venv .venv
# Linux/macOS
source .venv/bin/activate

# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

### Pre-commit hooks

Install pre-commit hooks for automated security and quality checks:

```bash
pre-commit install
```

This will run Bandit (security), mypy (types), Black (formatting), and TruffleHog (secrets detection) before each commit.

### Running tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=generate_it --cov-report=html

# Run security tests specifically
pytest tests/test_security.py -v
```

### Security tools

```bash
# Run Bandit security scanner
bandit -r generate_it

# Run pip-audit for vulnerable dependencies
pip-audit

# Run mypy type checker
mypy generate_it
```

### Reproducible builds

To install dependencies from hash-locked constraint files (ensuring identical versions and verified integrity across CI and release environments):

```bash
# Install CI dependencies (runtime + dev/test, hash-pinned)
pip install -c constraints/ci.txt -e ".[dev]"

# Install release dependencies (CI + build/twine, hash-pinned)
pip install -c constraints/release.txt -e ".[dev]" build twine
```

**Updating constraints after changing dependencies:**

1. Edit `constraints/ci.in` or `constraints/release.in` to add/remove direct dependencies
2. Re-generate the hash-locked files:
   ```bash
   pip install pip-tools
   pip-compile --generate-hashes --output-file=constraints/ci.txt constraints/ci.in
   pip-compile --generate-hashes --output-file=constraints/release.txt constraints/release.in
   ```
3. Commit the updated `.txt` files

The CI workflow in `.github/workflows/security.yml` uses `constraints/ci.txt` for reproducible hash-locked builds. The publish workflow in `.github/workflows/publish.yml` uses `constraints/release.txt` for hash-locked release tooling.

## License

Generate It is licensed under the **GNU Affero General Public License v3.0 or later** (**AGPL-3.0-or-later**). See `LICENSE`.
