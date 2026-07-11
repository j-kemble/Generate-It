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

    # An explicit path= argument must still work.
    generator.load_wordlist.cache_clear()
    explicit_words = generator.load_wordlist(weak_wl)
    assert explicit_words == weak_words
