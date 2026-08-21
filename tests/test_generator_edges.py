"""Deterministic edge-case tests for the credential generator."""

from __future__ import annotations

import pytest

from generate_it import generator


# ── Character password edge cases ─────────────────────────────────────

def test_generate_character_password_empty_pools_returns_empty() -> None:
    """No character classes selected returns empty string (documented behavior)."""
    result = generator.generate_character_password(
        12, use_letters=False, use_numbers=False, use_special=False
    )
    assert result == ""


def test_generate_character_password_only_letters() -> None:
    pwd = generator.generate_character_password(
        20, use_letters=True, use_numbers=False, use_special=False
    )
    assert len(pwd) == 20
    assert all(c in generator.LETTERS for c in pwd)


def test_generate_character_password_only_numbers() -> None:
    pwd = generator.generate_character_password(
        20, use_letters=False, use_numbers=True, use_special=False
    )
    assert len(pwd) == 20
    assert all(c.isdigit() for c in pwd)


def test_generate_character_password_only_special() -> None:
    pwd = generator.generate_character_password(
        20, use_letters=False, use_numbers=False, use_special=True
    )
    assert len(pwd) == 20
    assert all(c in generator.SPECIAL_CHARACTERS for c in pwd)


def test_generate_character_password_min_length_with_all_categories() -> None:
    """At minimum length (8) with all 3 categories, still produces valid output."""
    pwd = generator.generate_character_password(
        generator.MIN_PASSWORD_CHARS,
        use_letters=True,
        use_numbers=True,
        use_special=True,
    )
    assert len(pwd) == generator.MIN_PASSWORD_CHARS


def test_generate_character_password_below_min_length_raises() -> None:
    with pytest.raises(ValueError, match="length must be between"):
        generator.generate_character_password(
            1, use_letters=True, use_numbers=False, use_special=False
        )


def test_generate_character_password_above_max_length_raises() -> None:
    with pytest.raises(ValueError, match="length must be between"):
        generator.generate_character_password(
            999, use_letters=True, use_numbers=False, use_special=False
        )


# ── Passphrase edge cases ─────────────────────────────────────────────

def test_generate_passphrase_below_min_words_raises() -> None:
    with pytest.raises(ValueError):
        generator.generate_passphrase(1, add_numbers=False, add_special=False)


def test_generate_passphrase_at_min_words() -> None:
    pp = generator.generate_passphrase(
        generator.MIN_PASSPHRASE_WORDS,
        add_numbers=False,
        add_special=False,
    )
    assert len(pp.split("-")) == generator.MIN_PASSPHRASE_WORDS
    assert all(w for w in pp.split("-"))  # no empty words


def test_generate_passphrase_no_duplicate_words() -> None:
    """Each passphrase has unique words."""
    for _ in range(20):
        pp = generator.generate_passphrase(5, add_numbers=False, add_special=False)
        words = pp.split("-")
        assert len(words) == len(set(words)), f"Duplicate found in: {pp}"
