from __future__ import annotations

from generate_it import generator


def test_separator_username_has_exact_length_without_trailing_separator() -> None:
    for length in range(generator.MIN_USERNAME_LENGTH, generator.MAX_USERNAME_LENGTH + 1):
        for style, separator in (("underscore", "_"), ("hyphen", "-")):
            username = generator.generate_username_random(length, separator_style=style)

            assert len(username) == length
            assert not username.endswith(separator)
            assert all(char in generator.USERNAME_ALPHANUMERIC or char == separator for char in username)


def test_separator_username_allocates_content_around_separators(monkeypatch) -> None:
    monkeypatch.setattr(generator.secrets, "choice", lambda chars: chars[0])

    assert generator.generate_username_random(4, separator_style="underscore") == "aa_a"
    assert generator.generate_username_random(5, separator_style="underscore") == "a_a_a"
    assert generator.generate_username_random(6, separator_style="underscore") == "aa_a_a"
