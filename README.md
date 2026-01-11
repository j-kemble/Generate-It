# Generate It

A terminal credential generator with a curses-based UI.

It can generate:
- **Random passwords** (choose a length and character categories)
- **Random passphrases** (random words separated by hyphens)
- **Random usernames** (adjective+noun, random characters, or word combinations)

## Install

### From PyPI (recommended)

Requires Python 3.10 or later and pip.

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
# .\\venv\\Scripts\\Activate.ps1

pip install -e .
```

Then run:

```bash
generate-it
```

## Controls

### Running from source

```bash
python3 main.py
```

### Keyboard controls

- Tab / Shift-Tab or Arrow keys: move focus
- Space: toggle checkboxes / options
- Left/Right: adjust numeric values (length / word count)
- Enter or `g`: generate
- `b`: jump focus to Mode
- `q` (or ESC): quit

## How it works

### Random passwords (characters)

- Length options: **8–24** characters
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
