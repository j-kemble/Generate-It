# Generate It

A terminal password generator with a curses-based UI.

It can generate either:
- **Random characters** (choose a length and character categories)
- **Random words** separated by hyphens (a passphrase)

## Run

```bash
python3 main.py
```

If you prefer a simple prompt-based mode (no curses):

```bash
python3 main.py --cli
```

Optional (recommended): use a virtual environment.

```bash
python3 -m venv .venv
source .venv/bin/activate
python main.py
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

The included `wordlist.txt` contains **1000** lowercase words.

Edit `wordlist.txt` to customize which words can appear in passphrases.
