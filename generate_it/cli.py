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
    print("\nWhat would you like to generate?")
    print("1) Random password (characters)")
    print("2) Random passphrase (words)")
    print("3) Random username")
    print("q) Quit")

    while True:
        raw = input("Choose 1/2/3 (or 'q'): ").strip().lower()
        if raw in QUIT_WORDS:
            return None

        if raw in {"1", "c", "char", "chars", "character", "characters"}:
            return "chars"
        if raw in {"2", "w", "word", "words", "passphrase"}:
            return "words"
        if raw in {"3", "u", "username"}:
            return "username"

        print("Please enter 1, 2, 3, or 'q'.")


def _prompt_character_categories() -> tuple[bool, bool, bool] | None:
    print("\nChoose which categories to include in your password:")
    print("1) Letters (a-z, A-Z)")
    print("2) Numbers (0-9)")
    print("3) Special characters")

    while True:
        raw = input("Enter choices (e.g., 1 or 1,2,3), press Enter to skip, or 'q': ").strip().lower()
        if raw in QUIT_WORDS:
            return None

        if raw == "":
            # Default: use all categories
            return True, True, True

        tokens = _parse_choice_tokens(raw)
        if len(tokens) > 3:
            print("Please choose up to 3 options (or press Enter for all).")
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


def _prompt_username_style() -> str | None:
    print("\nWhich username style?")
    print("1) Adjective + noun (e.g., swift_tiger)")
    print("2) Random characters (e.g., a7k9m2p1)")
    print("3) Multiple words (e.g., swift_tiger_eagle)")
    print("q) Quit")

    while True:
        raw = input("Choose 1/2/3 (or 'q'): ").strip().lower()
        if raw in QUIT_WORDS:
            return None

        if raw in {"1", "adj", "adjective"}:
            return "adjective"
        if raw in {"2", "rand", "random"}:
            return "random"
        if raw in {"3", "words", "multi"}:
            return "words"

        print("Please enter 1, 2, 3, or 'q'.")


def _prompt_username_options() -> tuple[str, int, bool] | None:
    """Prompt for username generation options.
    
    Returns: (separator, word_count, add_numbers) or None if quit.
    """
    while True:
        sep = input("\nUse separator? (u=underscore, h=hyphen, n=none) [u]: ").strip().lower()
        if sep in QUIT_WORDS:
            return None
        if sep in {"", "u", "underscore"}:
            separator = "_"
            break
        if sep in {"h", "hyphen"}:
            separator = "-"
            break
        if sep in {"n", "none"}:
            separator = None
            break
        print("Please enter u, h, or n.")

    word_count = _prompt_int_in_range(
        f"How many words? ({generator.MIN_USERNAME_WORDS}-{generator.MAX_USERNAME_WORDS}, or 'q'): ",
        generator.MIN_USERNAME_WORDS,
        generator.MAX_USERNAME_WORDS,
    )
    if word_count is None:
        return None

    add_nums = _prompt_yes_no("Add numbers? [y/N]: ")
    return separator, word_count, add_nums


def _prompt_random_username_options() -> tuple[int, str] | None:
    """Prompt for random username options.
    
    Returns: (length, separator_style) or None if quit.
    """
    length = _prompt_int_in_range(
        f"\nUsername length? ({generator.MIN_USERNAME_LENGTH}-{generator.MAX_USERNAME_LENGTH}, or 'q'): ",
        generator.MIN_USERNAME_LENGTH,
        generator.MAX_USERNAME_LENGTH,
    )
    if length is None:
        return None

    while True:
        sep = input("Use separators? (u=underscore, h=hyphen, n=none) [n]: ").strip().lower()
        if sep in QUIT_WORDS:
            return None
        if sep in {"", "n", "none"}:
            separator_style = "none"
            break
        if sep in {"u", "underscore"}:
            separator_style = "underscore"
            break
        if sep in {"h", "hyphen"}:
            separator_style = "hyphen"
            break
        print("Please enter u, h, or n.")

    return length, separator_style


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
            if password:
                print(f"\nGenerated password ({length} chars):\n{password}\n")
            else:
                print(f"\nGenerated empty password (no categories selected).\n")

        elif mode == "words":
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

        else:  # mode == "username"
            style = _prompt_username_style()
            if style is None:
                print("Bye.")
                return 0

            if style == "adjective":
                add_nums = _prompt_yes_no("\nAdd numbers? [y/N]: ")
                sep = input("Separator? (u=underscore, h=hyphen) [u]: ").strip().lower()
                separator = "_" if sep in {"", "u", "underscore"} else "-"
                username = generator.generate_username_adjective_noun(
                    add_numbers=add_nums,
                    separator=separator,
                )
                print(f"\nGenerated username:\n{username}\n")

            elif style == "random":
                opts = _prompt_random_username_options()
                if opts is None:
                    print("Bye.")
                    return 0
                length, sep_style = opts
                username = generator.generate_username_random(
                    length,
                    separator_style=sep_style,
                )
                print(f"\nGenerated username ({length} chars):\n{username}\n")

            else:  # style == "words"
                opts = _prompt_username_options()
                if opts is None:
                    print("Bye.")
                    return 0
                separator, word_count, add_nums = opts
                username = generator.generate_username_words(
                    word_count,
                    add_numbers=add_nums,
                    separator=separator,
                    words=words,
                )
                print(f"\nGenerated username:\n{username}\n")

        if not _prompt_yes_no("Generate another? [y/N]: "):
            print("Bye.")
            return 0
