"""Regression-sensitive tests for the Phase 1 generator.py performance wins.

These tests must FAIL if any of the following optimizations are reverted or broken:
  1. ``load_wordlist`` is wrapped in ``@functools.lru_cache(maxsize=1)``.
  2. ``USERNAME_SEPARATORS`` is a ``frozenset`` of ``"_"`` and ``"-"``.
  3. ``_dedupe_preserve_order`` preserves insertion order while removing dupes.

They also exercise edge cases (empty/single inputs, leading-vs-trailing dups,
path-keyed caching, separator validation).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from unittest import mock

from generate_it import generator


@pytest.fixture(autouse=True)
def _clear_wordlist_cache():
    """Clear the lru_cache before and after every test to avoid cross-test leakage."""
    generator.load_wordlist.cache_clear()
    yield
    generator.load_wordlist.cache_clear()


def test_dedupe_preserves_order_and_removes_dups():
    """Order preserved, duplicates removed; FAILS if dedupe returns a set or keeps dups."""
    assert generator._dedupe_preserve_order(["a", "b", "a", "c", "b"]) == ["a", "b", "c"]
    # Edge cases: single element and empty list.
    assert generator._dedupe_preserve_order(["x"]) == ["x"]
    assert generator._dedupe_preserve_order([]) == []


def test_dedupe_edge_cases():
    """Empty-string elements handled, and leading-vs-trailing duplicates collapse correctly."""
    assert generator._dedupe_preserve_order(["", "", "x", ""]) == ["", "x"]
    # Leading duplicate ('z') then trailing duplicate ('a') must both collapse.
    assert generator._dedupe_preserve_order(["z", "a", "z", "a"]) == ["z", "a"]


def test_signature_cache_actually_caches():
    """The file read must happen exactly ONCE across two identical calls when the file is unchanged."""
    read_count = {"n": 0}
    original_read_text = generator.Path.read_text

    def counting_read_text(self, *args, **kwargs):
        read_count["n"] += 1
        return original_read_text(self, *args, **kwargs)

    with mock.patch.object(generator.Path, "read_text", counting_read_text):
        generator.clear_wordlist_cache()
        _ = generator.load_wordlist()  # miss -> reads the file
        _ = generator.load_wordlist()  # hit  -> must NOT read again

    assert read_count["n"] == 1, (
        f"expected the wordlist file to be read exactly once, but read_count={read_count['n']}"
    )


def test_wordlist_reloads_when_modified(tmp_path: Path):
    """Modifying the file causes a cache reload (freshness-aware)."""
    custom = tmp_path / "wl.txt"
    words1 = [f"word{n}" for n in range(6000)]
    custom.write_text("\n".join(words1) + "\n", encoding="utf-8")

    generator.clear_wordlist_cache()
    loaded1 = generator.load_wordlist(custom)
    assert loaded1 == words1

    # Update file content and modify mtime
    words2 = [f"newword{n}" for n in range(6000)]
    custom.write_text("\n".join(words2) + "\n", encoding="utf-8")

    loaded2 = generator.load_wordlist(custom)
    assert loaded2 == words2


def test_caller_mutation_does_not_corrupt_cache(tmp_path: Path):
    """Mutating the returned list does not alter subsequent load_wordlist results."""
    generator.clear_wordlist_cache()
    words1 = generator.load_wordlist()
    words1.pop(0)  # mutate returned list

    words2 = generator.load_wordlist()
    assert len(words2) == len(words1) + 1  # cache remains intact


def test_signature_cache_distinguishes_paths(tmp_path: Path):
    """The cache keys by path and signature, not globally."""
    custom = tmp_path / "wl.txt"
    custom.write_text(
        "\n".join([f"word{n}" for n in range(6000)]) + "\n", encoding="utf-8"
    )

    generator.clear_wordlist_cache()

    custom_words = generator.load_wordlist(custom)
    assert custom_words == [f"word{n}" for n in range(6000)]

    default_words = generator.load_wordlist(None)
    assert default_words != custom_words


def test_username_separators_is_frozenset_and_membership():
    """USERNAME_SEPARATORS must be a frozenset containing only ``_`` and ``-``."""
    assert isinstance(generator.USERNAME_SEPARATORS, frozenset)
    assert "_" in generator.USERNAME_SEPARATORS
    assert "-" in generator.USERNAME_SEPARATORS
    assert "x" not in generator.USERNAME_SEPARATORS
    assert generator.USERNAME_SEPARATORS == frozenset(["_", "-"])


def test_username_separators_used_in_generation():
    """The separator set is actually consumed by username generation.

    - A valid separator from the set appears as the joiner in the output.
    - An invalid separator is rejected (proving the membership check is live).
    """
    # Using "-" (a member) must join the words with "-".
    hyphen_user = generator.generate_username_words(2, separator="-")
    assert "-" in hyphen_user
    assert "_" not in hyphen_user

    # Using "_" (a member) must join the words with "_".
    under_user = generator.generate_username_words(2, separator="_")
    assert "_" in under_user
    assert "-" not in under_user

    # A separator NOT in the frozenset must be rejected.
    with pytest.raises(ValueError):
        generator.generate_username_words(2, separator=".")


def test_secure_sample_without_replacement_uses_shrinking_csprng_ranges(monkeypatch):
    calls: list[int] = []

    def choose_first(size: int) -> int:
        calls.append(size)
        return 0

    monkeypatch.setattr(generator.secrets, "randbelow", choose_first)

    sampled = generator._secure_sample_without_replacement(
        ["alpha", "beta", "gamma", "delta", "epsilon"], 3
    )

    assert sampled == ["alpha", "beta", "gamma"]
    assert calls == [5, 4, 3]


def test_word_generators_share_secure_sampling_helper(monkeypatch):
    calls: list[int] = []

    def sample_first(words: list[str], count: int) -> list[str]:
        calls.append(count)
        return words[:count]

    monkeypatch.setattr(generator, "_secure_sample_without_replacement", sample_first)
    words = ["alpha", "beta", "gamma", "delta", "epsilon"]

    assert generator.generate_passphrase(
        3, add_numbers=False, add_special=False, words=words
    ) == "alpha-beta-gamma"
    assert generator.generate_username_words(
        2, add_numbers=False, separator="_", words=words
    ) == "alpha_beta"
    assert calls == [3, 2]
