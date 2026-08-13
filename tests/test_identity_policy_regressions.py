from __future__ import annotations

import pytest

from generate_it import identity
from generate_it.storage import StorageManager, WeakMasterPasswordError
from generate_it.storage.core import _estimate_password_entropy, _validate_master_password


def test_canonical_identity_removes_embedded_zero_width_format_characters() -> None:
    assert identity.canonical_identity("al\u200bpha") == "alpha"
    assert identity.canonical_identity("us\u200d\u2060er") == "user"
    assert identity.canonical_service_username(" Git\u200bHub ", "De\u200bv") == (
        "github",
        "dev",
    )


def test_validate_identity_returns_cleaned_keys() -> None:
    assert identity.validate_identity("Git\u200bHub", "De\u200bv") == ("github", "dev")


def test_predictable_repeated_password_does_not_gain_entropy_from_length() -> None:
    assert _estimate_password_entropy("A" * 64) < 64
    with pytest.raises(WeakMasterPasswordError):
        _validate_master_password("A" * 64)


def test_predictable_repeated_chunk_does_not_gain_entropy_from_length() -> None:
    with pytest.raises(WeakMasterPasswordError):
        _validate_master_password("Ab1!" * 20)


def test_strong_password_still_initializes_v1_and_v2_vaults(tmp_path) -> None:
    for name, initializer in (("v1", "initialize_vault"), ("v2", "initialize_vault_v2")):
        storage = StorageManager(db_path=tmp_path / f"{name}.db")
        try:
            getattr(storage, initializer)("correct-horse-battery-staple-2026!")
        finally:
            storage.close()
