from __future__ import annotations

from pathlib import Path

import pytest

from generate_it import generator


def _assert_contains_any(s: str, alphabet: str) -> None:
    assert any(ch in alphabet for ch in s), f"expected at least one char from {alphabet!r} in {s!r}"


@pytest.mark.parametrize(
    "use_letters,use_numbers,use_special",
    [
        (True, True, False),
        (True, False, True),
        (False, True, True),
        (True, True, True),
    ],
)
def test_generate_character_password_invariants(
    use_letters: bool, use_numbers: bool, use_special: bool
) -> None:
    length = 20
    pw = generator.generate_character_password(
        length,
        use_letters=use_letters,
        use_numbers=use_numbers,
        use_special=use_special,
    )

    assert isinstance(pw, str)
    assert len(pw) == length

    if use_letters:
        _assert_contains_any(pw, generator.LETTERS)
    if use_numbers:
        _assert_contains_any(pw, generator.NUMBERS)
    if use_special:
        _assert_contains_any(pw, generator.SPECIAL_CHARACTERS)

    allowed = ""
    if use_letters:
        allowed += generator.LETTERS
    if use_numbers:
        allowed += generator.NUMBERS
    if use_special:
        allowed += generator.SPECIAL_CHARACTERS

    assert all(ch in allowed for ch in pw)


@pytest.mark.parametrize(
    "length",
    [generator.MIN_PASSWORD_CHARS - 1, generator.MAX_PASSWORD_CHARS + 1],
)
def test_generate_character_password_length_out_of_range_raises(length: int) -> None:
    with pytest.raises(ValueError):
        generator.generate_character_password(
            length,
            use_letters=True,
            use_numbers=True,
            use_special=False,
        )


def test_generate_character_password_allows_single_category() -> None:
    # Single category should now be allowed
    pw = generator.generate_character_password(
        12,
        use_letters=True,
        use_numbers=False,
        use_special=False,
    )
    assert isinstance(pw, str) and len(pw) == 12
    assert all(ch in generator.LETTERS for ch in pw)


def test_generate_character_password_allows_no_categories() -> None:
    # Zero categories should return empty string
    pw = generator.generate_character_password(
        12,
        use_letters=False,
        use_numbers=False,
        use_special=False,
    )
    assert pw == ""


def test_load_wordlist_missing_path_falls_back_to_default(tmp_path: Path) -> None:
    missing = tmp_path / "missing_wordlist.txt"
    assert not missing.exists()

    words = generator.load_wordlist(missing)
    assert words == generator.DEFAULT_WORDLIST


def test_load_wordlist_small_file_falls_back_to_default(tmp_path: Path) -> None:
    wl = tmp_path / "wordlist.txt"
    wl.write_text("alpha\nbeta\ngamma\n", encoding="utf-8")

    words = generator.load_wordlist(wl)
    assert words == generator.DEFAULT_WORDLIST


def test_load_wordlist_ignores_comments_blanks_and_dedupes(tmp_path: Path) -> None:
    wl = tmp_path / "wordlist.txt"
    wl.write_text(
        "\n".join(
            [
                "# comment",
                "alpha",
                "beta",
                "beta",  # duplicate
                "gamma",
                "delta",
                "epsilon",
                "zeta",
                "eta",
                "theta",
                "iota",
                "kappa",
                "lambda",
                "",  # blank
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    words = generator.load_wordlist(wl)
    assert words == [
        "alpha",
        "beta",
        "gamma",
        "delta",
        "epsilon",
        "zeta",
        "eta",
        "theta",
        "iota",
        "kappa",
        "lambda",
    ]


def test_load_wordlist_precedence_env_over_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_wl = tmp_path / "env_wordlist.txt"
    env_wl.write_text("\n".join([f"env{i}" for i in range(12)]) + "\n", encoding="utf-8")

    cwd_dir = tmp_path / "cwd"
    cwd_dir.mkdir()
    (cwd_dir / "wordlist.txt").write_text(
        "\n".join([f"cwd{i}" for i in range(12)]) + "\n", encoding="utf-8"
    )

    monkeypatch.chdir(cwd_dir)
    monkeypatch.setenv("GENERATE_IT_WORDLIST", str(env_wl))

    words = generator.load_wordlist()
    assert words[0] == "env0"
    assert all(w.startswith("env") for w in words)


def test_load_wordlist_precedence_explicit_path_over_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_wl = tmp_path / "env_wordlist.txt"
    env_wl.write_text("\n".join([f"env{i}" for i in range(12)]) + "\n", encoding="utf-8")

    explicit = tmp_path / "explicit_wordlist.txt"
    explicit.write_text("\n".join([f"explicit{i}" for i in range(12)]) + "\n", encoding="utf-8")

    monkeypatch.setenv("GENERATE_IT_WORDLIST", str(env_wl))

    words = generator.load_wordlist(explicit)
    assert words[0] == "explicit0"
    assert all(w.startswith("explicit") for w in words)


def test_generate_passphrase_basic_no_repeated_words() -> None:
    words = [f"word{i}" for i in range(20)]
    pp = generator.generate_passphrase(
        6,
        add_numbers=False,
        add_special=False,
        words=words,
    )

    parts = pp.split("-")
    assert len(parts) == 6
    assert len(set(parts)) == 6
    assert all(p in words for p in parts)


def test_generate_passphrase_adds_numbers_and_special() -> None:
    words = [f"alpha{i}" for i in range(20)]
    pp = generator.generate_passphrase(
        4,
        add_numbers=True,
        add_special=True,
        words=words,
    )

    parts = pp.split("-")
    assert len(parts) == 4

    assert any(ch.isdigit() for ch in pp)
    assert any(ch in generator.PASSPHRASE_SPECIALS for ch in pp)


@pytest.mark.parametrize(
    "word_count",
    [generator.MIN_PASSPHRASE_WORDS - 1, generator.MAX_PASSPHRASE_WORDS + 1],
)
def test_generate_passphrase_word_count_out_of_range_raises(word_count: int) -> None:
    with pytest.raises(ValueError):
        generator.generate_passphrase(
            word_count,
            add_numbers=False,
            add_special=False,
            words=[f"w{i}" for i in range(50)],
        )


def test_generate_passphrase_wordlist_too_small_raises() -> None:
    with pytest.raises(ValueError):
        generator.generate_passphrase(
            5,
            add_numbers=False,
            add_special=False,
            words=["one", "two", "three", "four"],
        )


def test_insert_token_last_word_is_not_appended(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def fake_randbelow(n: int) -> int:
        calls.append(n)
        return n - 1  # always choose the last valid index/position

    monkeypatch.setattr(generator.secrets, "randbelow", fake_randbelow)

    words = ["alpha", "beta"]
    generator._insert_token_into_words(words, "X")

    # We should have targeted the last word...
    assert words[0] == "alpha"
    assert "X" in words[1]

    # ...but not appended at the very end.
    assert words[1] != "betaX"

    # Implementation detail: when inserting into the last word, the final position
    # is excluded (so randbelow() shouldn't be called with len(word)+1).
    assert calls == [2, len("beta")]


def test_generate_username_words_basic() -> None:
    words = [f"word{i}" for i in range(10)]
    username = generator.generate_username_words(
        2,
        add_numbers=False,
        separator="_",
        words=words,
    )

    assert isinstance(username, str)
    assert "_" in username
    parts = username.split("_")
    assert len(parts) == 2
    assert all(p in words for p in parts)


def test_generate_username_words_with_numbers() -> None:
    words = [f"w{i}" for i in range(10)]
    username = generator.generate_username_words(
        1,
        add_numbers=True,
        separator="_",
        words=words,
    )

    assert isinstance(username, str)
    # Should have word + 3 digits
    assert any(ch.isdigit() for ch in username)


@pytest.mark.parametrize(
    "word_count",
    [generator.MIN_USERNAME_WORDS - 1, generator.MAX_USERNAME_WORDS + 1],
)
def test_generate_username_words_count_out_of_range_raises(word_count: int) -> None:
    with pytest.raises(ValueError):
        generator.generate_username_words(
            word_count,
            words=[f"w{i}" for i in range(10)],
        )


def test_generate_username_words_invalid_separator_raises() -> None:
    with pytest.raises(ValueError):
        generator.generate_username_words(
            2,
            separator="@",
            words=["a", "b", "c"],
        )


def test_generate_username_random_no_separator() -> None:
    username = generator.generate_username_random(10, separator_style="none")

    assert isinstance(username, str)
    assert len(username) == 10
    assert all(ch in generator.USERNAME_ALPHANUMERIC for ch in username)
    assert "_" not in username
    assert "-" not in username


def test_generate_username_random_with_underscore() -> None:
    username = generator.generate_username_random(12, separator_style="underscore")

    assert isinstance(username, str)
    assert len(username) == 12
    assert "_" in username
    assert all(ch in generator.USERNAME_ALPHANUMERIC or ch == "_" for ch in username)


def test_generate_username_random_with_hyphen() -> None:
    username = generator.generate_username_random(12, separator_style="hyphen")

    assert isinstance(username, str)
    assert len(username) == 12
    assert "-" in username
    assert all(ch in generator.USERNAME_ALPHANUMERIC or ch == "-" for ch in username)


@pytest.mark.parametrize(
    "length",
    [generator.MIN_USERNAME_LENGTH - 1, generator.MAX_USERNAME_LENGTH + 1],
)
def test_generate_username_random_length_out_of_range_raises(length: int) -> None:
    with pytest.raises(ValueError):
        generator.generate_username_random(length)


def test_generate_username_random_invalid_separator_style_raises() -> None:
    with pytest.raises(ValueError):
        generator.generate_username_random(10, separator_style="invalid")


def test_generate_username_adjective_noun_basic() -> None:
    username = generator.generate_username_adjective_noun(
        add_numbers=False,
        separator="_",
    )

    assert isinstance(username, str)
    assert "_" in username
    parts = username.split("_")
    assert len(parts) == 2
    assert parts[0] in generator.DEFAULT_ADJECTIVES
    assert parts[1] in generator.load_wordlist()


def test_generate_username_adjective_noun_with_numbers() -> None:
    username = generator.generate_username_adjective_noun(
        add_numbers=True,
        separator="_",
    )

    assert isinstance(username, str)
    assert any(ch.isdigit() for ch in username)


def test_generate_username_adjective_noun_with_hyphen() -> None:
    username = generator.generate_username_adjective_noun(
        add_numbers=False,
        separator="-",
    )

    assert isinstance(username, str)
    assert "-" in username
    assert "_" not in username


def test_generate_username_adjective_noun_invalid_separator_raises() -> None:
    with pytest.raises(ValueError):
        generator.generate_username_adjective_noun(separator="@")


def test_generate_username_adjective_noun_custom_lists() -> None:
    custom_adjs = ["fast", "slow", "happy"]
    custom_nouns = ["cat", "dog", "bird"]

    username = generator.generate_username_adjective_noun(
        separator="_",
        adjectives=custom_adjs,
        nouns=custom_nouns,
    )

    parts = username.split("_")
    assert len(parts) == 2
    assert parts[0] in custom_adjs
    assert parts[1] in custom_nouns
