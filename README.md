# Generate It

A terminal password generator with a curses-based UI.

It can generate either:
- **Random characters** (choose a length and character categories)
- **Random words** separated by hyphens (a passphrase)

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

**Windows note:** On Windows, if you want the full-screen TUI, pip will automatically install the curses compatibility layer. If you prefer, you can run the CLI mode instead:

```bash
generate-it --cli
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

## Run (without installing)

```bash
python3 main.py
```

If you prefer a simple prompt-based mode (no curses):

```bash
python3 main.py --cli
```

## TUI controls

- Tab / Shift-Tab or Arrow keys: move focus
- Space: toggle checkboxes / options
- Left/Right: adjust numeric values (length / word count)
- Enter or `g`: generate
- `b`: jump focus to Mode
- `q` (or ESC): quit

## How it works

### Random characters

- Length options: **8–24** characters
- Choose **2 or 3** categories from:
  - letters
  - numbers
  - special characters

### Random words (passphrase)

- Word options: **3–10** words
- Words are joined with hyphens (e.g. `forest-ember-spark`)
- Words are chosen **without replacement** (no repeated words within a single passphrase)
- Optional extras:
  - add numbers (randomly inserted into words)
  - add special characters (randomly inserted into words)

## Custom word list

The included word list contains **1000** lowercase words.

Override the word list in one of these ways (highest priority first):

1) Set `GENERATE_IT_WORDLIST` to a file path
2) Put a `wordlist.txt` in your current working directory

Otherwise, Generate It uses the bundled default word list.

## License

Generate It is licensed under the **GNU Affero General Public License v3.0 or later** (**AGPL-3.0-or-later**). See `LICENSE`.
