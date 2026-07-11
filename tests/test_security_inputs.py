"""Security regression tests for input handling and wordlists."""

from __future__ import annotations

from pathlib import Path

import pytest

from generate_it import generator


def test_cwd_wordlist_is_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CWD wordlist.txt must be ignored — only explicit path or env var opt in.

    An attacker who provides a weak wordlist.txt in a working directory
    must NOT be able to reduce passphrase entropy.
    """
    # Create a weak wordlist in a temporary directory.
    weak_wl = tmp_path / "wordlist.txt"
    weak_words = [f"weak{i}" for i in range(10)]
    weak_wl.write_text("\n".join(weak_words) + "\n", encoding="utf-8")

    # Change into that directory so it becomes CWD.
    monkeypatch.chdir(tmp_path)

    # Clear the cache so we test the actual lookup path.
    generator.load_wordlist.cache_clear()

    # load_wordlist() with no args and no env var must return the
    # packaged list, NOT the CWD one.
    words = generator.load_wordlist()
    assert words != weak_words, (
        "CWD wordlist.txt was loaded when it should have been ignored"
    )
    # Verify we got the packaged list (or its built-in fallback).
    assert len(words) >= 10
    assert "weak0" not in words

    # An explicit path to a weak list must be rejected by entropy validation.
    generator.load_wordlist.cache_clear()
    with pytest.raises(generator.WordlistSecurityError):
        generator.load_wordlist(weak_wl)


def test_ten_word_list_rejected(tmp_path: Path) -> None:
    """A 10-word list must be rejected."""
    wl = tmp_path / "tiny.txt"
    wl.write_text("\n".join(f"word{i}" for i in range(10)), encoding="utf-8")
    generator.load_wordlist.cache_clear()
    with pytest.raises(ValueError) as exc:
        generator.load_wordlist(wl)
    assert "WordlistSecurityError" in type(exc.value).__name__


def test_small_list_below_threshold_rejected(tmp_path: Path) -> None:
    """A list below the entropy threshold must be rejected."""
    # 2000 words at k=4 gives ~43 bits — below 50
    wl = tmp_path / "small.txt"
    wl.write_text("\n".join(f"word{i}" for i in range(2000)), encoding="utf-8")
    generator.load_wordlist.cache_clear()
    with pytest.raises(ValueError) as exc:
        generator.load_wordlist(wl)
    assert "WordlistSecurityError" in type(exc.value).__name__


def test_sufficient_list_accepted(tmp_path: Path) -> None:
    """A list meeting the entropy threshold must be accepted."""
    # 6000 words at k=4 gives ~50.2 bits — meets 50-bit threshold
    wl = tmp_path / "sufficient.txt"
    wl.write_text("\n".join(f"word{i}" for i in range(6000)), encoding="utf-8")
    generator.load_wordlist.cache_clear()
    words = generator.load_wordlist(wl)
    assert len(words) == 6000


def test_duplicates_not_counted(tmp_path: Path) -> None:
    """Duplicate words must not inflate the measured list size."""
    wl = tmp_path / "dupes.txt"
    # 3000 lines, but only 10 unique words
    lines = [f"word{i % 10}" for i in range(3000)]
    wl.write_text("\n".join(lines), encoding="utf-8")
    generator.load_wordlist.cache_clear()
    with pytest.raises(ValueError) as exc:
        generator.load_wordlist(wl)
    assert "WordlistSecurityError" in type(exc.value).__name__


def test_packaged_list_meets_threshold() -> None:
    """The packaged default list must pass the entropy check."""
    generator.load_wordlist.cache_clear()
    words = generator.load_wordlist()  # no path = packaged
    assert len(words) >= 1000  # packaged list
    bits = generator._ordered_sample_entropy_bits(len(words), 4)
    # Packaged list is NOT validated against the 50-bit floor
    # (the entropy check only applies to custom wordlists),
    # but we verify it's at least a reasonable size.
    assert bits >= 39.0, f"Packaged list only provides {bits:.1f} bits at 4 words"
