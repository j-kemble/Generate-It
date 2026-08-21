"""Generate It entrypoint.

Runs the curses TUI for generating passwords, passphrases, and usernames.
Also provides headless CLI helpers (--check-vault, --change-password).
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from . import tui
from .storage import StorageManager


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="generate-it", description="Generate It — credential generator + vault")
    parser.add_argument("--vault-path", type=Path, default=None, help="Custom vault.db path")
    parser.add_argument("--check-vault", action="store_true", help="Print vault status (no TUI) and exit")
    parser.add_argument("--json", action="store_true", help="With --check-vault, output JSON")
    parser.add_argument("--change-password", action="store_true", help="Change master password (headless)")
    parser.add_argument("--prune-backups", type=int, metavar="N", default=None, help="Prune backups, keep N newest (headless)")
    parser.add_argument("--check-integrity", action="store_true", help="Decrypt all credentials and report issues (requires unlock)")
    # Generation (headless, vault-independent)
    parser.add_argument("--generate-password", action="store_true", help="Generate a random password and print it")
    parser.add_argument("--generate-passphrase", action="store_true", help="Generate a passphrase and print it")
    parser.add_argument("--generate-username", action="store_true", help="Generate a username and print it")
    parser.add_argument("--length", type=int, default=None, help="Password length (8-64) or username random length (3-64)")
    parser.add_argument("--words", type=int, default=None, help="Word count for passphrase (3-10) or username words (1-3)")
    parser.add_argument("--no-letters", action="store_true", help="Exclude letters from password")
    parser.add_argument("--no-numbers", action="store_true", help="Exclude numbers from password")
    parser.add_argument("--special", action="store_true", help="Include special characters (password) or add special token (passphrase)")
    parser.add_argument("--add-numbers", action="store_true", help="Add numbers to passphrase/username")
    parser.add_argument("--username-style", choices=["adjective", "random", "words"], default=None, help="Username style")
    parser.add_argument("--separator", choices=["_", "-"], default=None, help="Separator for username words/adjective style")
    parser.add_argument("--copy", action="store_true", help="Copy generated credential to clipboard")
    return parser


def _storage_for_args(args: argparse.Namespace) -> StorageManager:
    return StorageManager(db_path=args.vault_path) if args.vault_path else StorageManager()


def _run_check_vault(args: argparse.Namespace) -> int:
    storage = _storage_for_args(args)
    status = storage.get_vault_status()
    if args.json:
        print(json.dumps(status, indent=2))
    else:
        for key, value in status.items():
            print(f"{key}: {value}")
    return 0


def _run_prune_backups(args: argparse.Namespace) -> int:
    storage = _storage_for_args(args)
    deleted = storage.prune_backups(keep_latest=args.prune_backups if args.prune_backups is not None else 1)
    print(f"Deleted {len(deleted)} backup(s).")
    for path in deleted:
        print(f"  - {path}")
    return 0


def _run_check_integrity(args: argparse.Namespace) -> int:
    storage = _storage_for_args(args)
    if not storage.vault_exists():
        print("No vault found.", file=sys.stderr)
        return 1
    password = getpass.getpass("Master password: ")
    try:
        storage.unlock_vault(password)
    except Exception as exc:
        print(f"Unlock failed: {exc}", file=sys.stderr)
        return 1
    finally:
        # Minimize lifetime of plaintext master password.
        try:
            password = "\x00" * len(password)
        except Exception:
            pass
        try:
            del password
        except Exception:
            pass
    issues = storage.check_vault_integrity()
    if not issues:
        print("Integrity OK: all credentials decrypt correctly.")
        return 0
    print(f"Found {len(issues)} issue(s):")
    for item in issues:
        print(f"  id={item['id']} service={item['service']} error={item['error']}")
    return 1


def _run_change_password_cli(args: argparse.Namespace) -> int:
    storage = _storage_for_args(args)
    if not storage.vault_exists():
        print("No vault found.", file=sys.stderr)
        return 1
    current = getpass.getpass("Current master password: ")
    new_one = getpass.getpass("New master password: ")
    confirm = getpass.getpass("Confirm new master password: ")
    if new_one != confirm:
        print("New passwords do not match.", file=sys.stderr)
        # Clear promptly even on mismatch — overwrite each variable explicitly
        # (loop variable rebinding would not affect the originals).
        try:
            current = "\x00" * len(current)
        except Exception:
            pass
        try:
            new_one = "\x00" * len(new_one)
        except Exception:
            pass
        try:
            confirm = "\x00" * len(confirm)
        except Exception:
            pass
        try:
            del current, new_one, confirm
        except Exception:
            pass
        return 1
    try:
        storage.unlock_vault(current)
    except Exception as exc:
        print(f"Unlock failed: {exc}", file=sys.stderr)
        return 1
    try:
        storage.change_master_password(current, new_one)
    except Exception as exc:
        print(f"Password change failed: {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            current = "\x00" * len(current)
        except Exception:
            pass
        try:
            new_one = "\x00" * len(new_one)
        except Exception:
            pass
        try:
            confirm = "\x00" * len(confirm)
        except Exception:
            pass
        try:
            del current, new_one, confirm
        except Exception:
            pass
    print("Master password changed.")
    return 0


def _maybe_copy_cli(text: str) -> None:
    try:
        import pyperclip  # local import so tests without clipboard still work
        pyperclip.copy(text)
        print("(copied to clipboard)", file=sys.stderr)
    except Exception:
        pass


def _run_generate_password_cli(args: argparse.Namespace) -> int:
    from .generator import generate_character_password, MIN_PASSWORD_CHARS, MAX_PASSWORD_CHARS
    length = args.length if args.length is not None else 12
    if not MIN_PASSWORD_CHARS <= length <= MAX_PASSWORD_CHARS:
        print(f"length must be between {MIN_PASSWORD_CHARS} and {MAX_PASSWORD_CHARS}", file=sys.stderr)
        return 2
    use_letters = not args.no_letters
    use_numbers = not args.no_numbers
    use_special = bool(args.special)
    try:
        pwd = generate_character_password(length, use_letters=use_letters, use_numbers=use_numbers, use_special=use_special)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(pwd)
    if args.copy:
        _maybe_copy_cli(pwd)
    return 0


def _run_generate_passphrase_cli(args: argparse.Namespace) -> int:
    from .generator import generate_passphrase, MIN_PASSPHRASE_WORDS, MAX_PASSPHRASE_WORDS
    count = args.words if args.words is not None else 4
    if not MIN_PASSPHRASE_WORDS <= count <= MAX_PASSPHRASE_WORDS:
        print(f"words must be between {MIN_PASSPHRASE_WORDS} and {MAX_PASSPHRASE_WORDS}", file=sys.stderr)
        return 2
    try:
        phrase = generate_passphrase(count, add_numbers=bool(args.add_numbers), add_special=bool(args.special))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(phrase)
    if args.copy:
        _maybe_copy_cli(phrase)
    return 0


def _run_generate_username_cli(args: argparse.Namespace) -> int:
    from .generator import generate_username_adjective_noun, generate_username_random, generate_username_words
    style = args.username_style or "adjective"
    separator = args.separator or "_"
    add_numbers = bool(args.add_numbers)
    try:
        if style == "adjective":
            username = generate_username_adjective_noun(add_numbers=add_numbers, separator=separator)
        elif style == "random":
            length = args.length if args.length is not None else 12
            sep_style = "underscore" if separator == "_" else "hyphen" if separator == "-" else "none"
            # For random style, honour --length, default 12
            username = generate_username_random(length, separator_style=sep_style if args.separator else "none")
        else:  # words
            count = args.words if args.words is not None else 2
            username = generate_username_words(count, add_numbers=add_numbers, separator=separator)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(username)
    if args.copy:
        _maybe_copy_cli(username)
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the TUI or a headless subcommand."""
    parser = _build_parser()
    if argv is None:
        # Avoid parsing pytest's sys.argv when called programmatically (tests).
        # Only parse real CLI invocation (argv contains generate-it or __main__).
        prog = sys.argv[0] if sys.argv else ""
        if "generate-it" in prog or "generate_it" in prog:
            argv = sys.argv[1:]
        else:
            argv = []
    args = parser.parse_args(argv)
    if args.check_vault:
        return _run_check_vault(args)
    if args.prune_backups is not None:
        return _run_prune_backups(args)
    if args.check_integrity:
        return _run_check_integrity(args)
    if args.change_password:
        return _run_change_password_cli(args)
    if args.generate_password:
        return _run_generate_password_cli(args)
    if args.generate_passphrase:
        return _run_generate_passphrase_cli(args)
    if args.generate_username:
        return _run_generate_username_cli(args)
    return tui.run()


if __name__ == "__main__":
    raise SystemExit(main())
