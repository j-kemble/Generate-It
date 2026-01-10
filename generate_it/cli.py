"""Prompt-based CLI for Generate It (fallback when curses isn't available)."""

from __future__ import annotations

from . import generator

APP_NAME = "Generate It"
QUIT_WORDS = {"q", "quit", "exit"}


def _parse_choice_tokens(raw: str) -> list[str]:
    tokens = raw.replace(",", " ").split()
    unique: list[str] = []
    for t in tokens:
        if t not in unique:
            unique.append(t)
    return unique


def _prompt_yes_no(prompt: str) -> bool:
    raw = input(prompt).strip().lower()
    return raw in {"y", "yes"}


def _prompt_int_in_range(prompt: str, min_value: int, max_value: int) -> int | None:
    while True:
        raw = input(prompt).strip().lower()
        if raw in QUIT_WORDS:
            return None

        try:
            value = int(raw)
        except ValueError:
            print("Please enter a whole number or 'q' to quit.")
            continue

        if value < min_value or value > max_value:
            print(f"Please enter a value between {min_value} and {max_value}.")
            continue

        return value


def _prompt_mode() -> str | None:
    print("\nWhat kind of password would you like?")
    print("1) Random characters")
    print("2) Random words separated by hyphens")
    print("q) Quit")

    while True:
        raw = input("Choose 1/2 (or 'q'): ").strip().lower()
        if raw in QUIT_WORDS:
            return None

        if raw in {"1", "c", "char", "chars", "character", "characters"}:
            return "chars"
        if raw in {"2", "w", "word", "words", "passphrase"}:
            return "words"

        print("Please enter 1, 2, or 'q'.")


def _prompt_character_categories() -> tuple[bool, bool, bool] | None:
    print("\nChoose 2 or 3 categories for your password:")
    print("1) Letters (a-z, A-Z)")
    print("2) Numbers (0-9)")
    print("3) Special characters")

    while True:
        raw = input("Enter choices (e.g., 1,3 or 1,2,3) or 'q': ").strip().lower()
        if raw in QUIT_WORDS:
            return None

        tokens = _parse_choice_tokens(raw)
        if len(tokens) not in {2, 3}:
            print("Please choose 2 or 3 options.")
            continue

        if any(t not in {"1", "2", "3"} for t in tokens):
            print("Choices must be from 1, 2, 3.")
            continue

        use_letters = "1" in tokens
        use_numbers = "2" in tokens
        use_special = "3" in tokens
        return use_letters, use_numbers, use_special


def _prompt_passphrase_extras() -> tuple[bool, bool] | None:
    print("\nOptional extras:")
    print("1) Add numbers")
    print("2) Add special characters")

    while True:
        raw = input("Enter choices (e.g., 1,2), press Enter for none, or 'q': ").strip().lower()
        if raw in QUIT_WORDS:
            return None

        if raw == "":
            return False, False

        tokens = _parse_choice_tokens(raw)
        if any(t not in {"1", "2"} for t in tokens):
            print("Choices must be from 1 or 2 (or press Enter for none).")
            continue

        add_numbers = "1" in tokens
        add_special = "2" in tokens
        return add_numbers, add_special


def run() -> int:
    print(APP_NAME)

    words = generator.load_wordlist()
    seen_passphrases: set[str] = set()

    while True:
        mode = _prompt_mode()
        if mode is None:
            print("Bye.")
            return 0

        if mode == "chars":
            length = _prompt_int_in_range(
                f"\nHow many characters would you like? ({generator.MIN_PASSWORD_CHARS}-{generator.MAX_PASSWORD_CHARS}, or 'q'): ",
                generator.MIN_PASSWORD_CHARS,
                generator.MAX_PASSWORD_CHARS,
            )
            if length is None:
                print("Bye.")
                return 0

            cats = _prompt_character_categories()
            if cats is None:
                print("Bye.")
                return 0

            use_letters, use_numbers, use_special = cats
            password = generator.generate_character_password(
                length,
                use_letters=use_letters,
                use_numbers=use_numbers,
                use_special=use_special,
            )
            print(f"\nGenerated password ({length} chars):\n{password}\n")

        else:
            word_count = _prompt_int_in_range(
                f"\nHow many words would you like? ({generator.MIN_PASSPHRASE_WORDS}-{generator.MAX_PASSPHRASE_WORDS}, or 'q'): ",
                generator.MIN_PASSPHRASE_WORDS,
                generator.MAX_PASSPHRASE_WORDS,
            )
            if word_count is None:
                print("Bye.")
                return 0

            extras = _prompt_passphrase_extras()
            if extras is None:
                print("Bye.")
                return 0

            add_numbers, add_special = extras
            # Avoid repeating the same passphrase during a single run of the program.
            for _ in range(200):
                passphrase = generator.generate_passphrase(
                    word_count,
                    add_numbers=add_numbers,
                    add_special=add_special,
                    words=words,
                )
                if passphrase not in seen_passphrases:
                    seen_passphrases.add(passphrase)
                    break
            else:
                raise RuntimeError(
                    "Unable to generate a unique passphrase (too many already generated)."
                )

            print(f"\nGenerated passphrase ({word_count} words):\n{passphrase}\n")

        if not _prompt_yes_no("Generate another? [y/N]: "):
            print("Bye.")
            return 0
