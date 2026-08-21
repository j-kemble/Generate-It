"""Unit tests for the bounded-set wrapper."""

from __future__ import annotations

import pytest

from generate_it._bounded_set import BoundedSet


def test_add_and_contains() -> None:
    s: BoundedSet[str] = BoundedSet[str](max_size=3)
    s.add("a")
    s.add("b")
    assert "a" in s
    assert "b" in s
    assert "c" not in s
    assert len(s) == 2


def test_eviction_on_overflow() -> None:
    s: BoundedSet[str] = BoundedSet[str](max_size=3)
    s.add("a")
    s.add("b")
    s.add("c")
    s.add("d")  # triggers eviction of "a" (oldest)
    assert "a" not in s
    assert "b" in s
    assert "c" in s
    assert "d" in s
    assert len(s) == 3


def test_re_add_is_noop() -> None:
    s: BoundedSet[str] = BoundedSet[str](max_size=3)
    s.add("a")
    s.add("b")
    s.add("a")  # re-adding "a" — already present, no-op (position unchanged)
    s.add("c")
    s.add("d")  # triggers eviction of "a" (still oldest)
    assert "a" not in s  # evicted
    assert "b" in s  # survived
    assert "c" in s
    assert "d" in s
    assert len(s) == 3


def test_no_eviction_below_limit() -> None:
    s: BoundedSet[str] = BoundedSet[str](max_size=10)
    for i in range(10):
        s.add(str(i))
    assert len(s) == 10
    assert "0" in s  # oldest still present
    assert "9" in s  # newest present


def test_default_max_size() -> None:
    s: BoundedSet[str] = BoundedSet[str]()
    assert s.max_size == 10_000
