from __future__ import annotations

import pytest

from generate_it import _crypto_v2
from generate_it.identity import canonical_identity
from generate_it.storage.core import _estimate_password_entropy, _validate_master_password


def test_historical_aad_v3_format_character_ciphertext_remains_decryptable() -> None:
    vault_uuid = b"V" * 16
    credential_uuid = b"C" * 16
    dek = b"D" * 32
    historical_service = "github"
    current_service = "git\u200bhub"

    historical_aad = _crypto_v2.make_associated_data_v3(
        vault_uuid, credential_uuid, "password", historical_service, "user"
    )
    ciphertext = _crypto_v2.encrypt_field(dek, historical_aad, "secret")
    current_aad = _crypto_v2.make_associated_data_v3(
        vault_uuid, credential_uuid, "password", current_service, "user"
    )
    assert _crypto_v2.decrypt_field(dek, current_aad, ciphertext) == "secret"


def test_high_entropy_short_repeated_unit_is_not_rejected() -> None:
    unit = "aB7!xY9@qW3#eR5$"
    password = unit * 3

    assert _estimate_password_entropy(password) >= 64
    _validate_master_password(password)


@pytest.mark.parametrize("suffix", ["X", "!"])
def test_low_entropy_repeat_with_suffix_is_rejected(suffix: str) -> None:
    password = "Ab1!" * 19 + suffix
    with pytest.raises(Exception):
        _validate_master_password(password)


def test_current_identity_canonicalization_is_unchanged() -> None:
    assert canonical_identity("  GitHub  ") == "github"
    assert canonical_identity("Git\u200bHub") == "git\u200bhub"
