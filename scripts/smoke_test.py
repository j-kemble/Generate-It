from __future__ import annotations

from generate_it import generator


def main() -> None:
    words = generator.load_wordlist()
    assert len(words) >= 10

    pw = generator.generate_character_password(
        12, use_letters=True, use_numbers=True, use_special=False
    )
    assert isinstance(pw, str) and len(pw) == 12

    pp = generator.generate_passphrase(4, add_numbers=True, add_special=True, words=words)
    assert isinstance(pp, str) and "-" in pp

    print("ok")


if __name__ == "__main__":
    main()
