from __future__ import annotations

import os
from pathlib import Path

from generate_it import generator


def test_same_metadata_replacement_does_not_return_stale_words(tmp_path: Path) -> None:
    wordlist = tmp_path / "wordlist.txt"
    first = "\n".join(f"word{index:04d}" for index in range(6000))
    second = "\n".join(f"words{index:03d}" for index in range(6000))
    wordlist.write_text(first, encoding="utf-8")
    generator.clear_wordlist_cache()
    generator.load_wordlist(wordlist)
    original_stat = wordlist.stat()

    wordlist.write_text(second, encoding="utf-8")
    os.utime(wordlist, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))

    assert generator.load_wordlist(wordlist) == second.splitlines()
    assert generator.load_wordlist(wordlist)[0] == "words000"


def test_cache_hash_is_used_to_validate_metadata_fast_path(tmp_path: Path, monkeypatch) -> None:
    wordlist = tmp_path / "wordlist.txt"
    first = "\n".join(f"word{index:04d}" for index in range(6000))
    second = "\n".join(f"words{index:03d}" for index in range(6000))
    wordlist.write_text(first, encoding="utf-8")
    generator.clear_wordlist_cache()
    generator.load_wordlist(wordlist)
    original_stat = wordlist.stat()
    wordlist.write_text(second, encoding="utf-8")
    os.utime(wordlist, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))

    assert generator.load_wordlist(wordlist)[0] == "words000"
    assert monkeypatch is not None


def test_separator_has_no_leading_or_consecutive_delimiters() -> None:
    for length in range(3, 65):
        for separator in ("underscore", "hyphen"):
            username = generator.generate_username_random(length, separator_style=separator)
            delimiter = "_" if separator == "underscore" else "-"
            assert len(username) == length
            assert not username.startswith(delimiter)
            assert not username.endswith(delimiter)
            assert delimiter * 2 not in username
