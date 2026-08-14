from __future__ import annotations

import pytest

from generate_it import identity
from generate_it.storage import WeakMasterPasswordError
from generate_it.storage.core import _estimate_password_entropy, _validate_master_password


def test_identity_normalization_is_idempotent_at_format_boundaries() -> None:
    value = "  GitHub  "
    canonical = identity.canonical_identity(value)
    assert canonical == "github"
    assert identity.canonical_identity(canonical) == canonical


def test_invisible_format_characters_are_rejected_at_validation_boundary() -> None:
    with pytest.raises(ValueError, match="prohibited invisible"):
        identity.validate_identity("\u200bGitHub", "user")
    with pytest.raises(ValueError, match="prohibited invisible"):
        identity.validate_identity("GitHub", "us\u200ber")


def test_meaningful_joiners_are_not_collapsed() -> None:
    assert identity.canonical_identity("👩‍💻") != identity.canonical_identity("👩💻")
    assert identity.canonical_identity("می‌خواهم") != identity.canonical_identity("میخواهم")


def test_near_repeated_password_suffix_is_rejected() -> None:
    password = "Ab1!" * 19 + "X"
    assert _estimate_password_entropy(password) < 64
    with pytest.raises(WeakMasterPasswordError):
        _validate_master_password(password)


def test_repeated_high_entropy_unit_is_not_classified_as_zero_entropy() -> None:
    unit = "aB7!" + "x" * 508
    password = unit * 2
    assert _estimate_password_entropy(password) > 0
    _validate_master_password(password)


def test_normal_strong_password_remains_valid() -> None:
    _validate_master_password("correct-horse-battery-staple-2026!")
