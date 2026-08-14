from __future__ import annotations

from pathlib import Path
from unittest import mock
import hashlib

from generate_it import generator


def test_unchanged_wordlist_uses_metadata_fast_path_without_hashing(tmp_path: Path) -> None:
    wordlist = tmp_path / "wordlist.txt"
    wordlist.write_text("\n".join(f"word{index}" for index in range(6000)), encoding="utf-8")
    generator.clear_wordlist_cache()

    with mock.patch.object(hashlib, "blake2b", wraps=hashlib.blake2b) as hasher:
        generator.load_wordlist(wordlist)
        first_hash_count = hasher.call_count
        generator.load_wordlist(wordlist)

    assert first_hash_count == 1
    assert hasher.call_count == first_hash_count + 1


def test_metadata_change_triggers_hash_and_reload(tmp_path: Path, monkeypatch) -> None:
    wordlist = tmp_path / "wordlist.txt"
    first = "\n".join(f"word{index}" for index in range(6000))
    second = "\n".join(f"newword{index}" for index in range(6000))
    wordlist.write_text(first, encoding="utf-8")
    generator.clear_wordlist_cache()
    generator.load_wordlist(wordlist)

    wordlist.write_text(second, encoding="utf-8")
    stat_after_write = wordlist.stat()
    original_get_signature = generator._get_file_signature
    monkeypatch.setattr(
        generator,
        "_get_file_signature",
        lambda path: (path.resolve(), stat_after_write.st_mtime_ns, stat_after_write.st_size)
        if path == wordlist
        else original_get_signature(path),
    )

    assert generator.load_wordlist(wordlist) == second.splitlines()
