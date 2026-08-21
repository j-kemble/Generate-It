from __future__ import annotations

from generate_it._crypto_v2 import decrypt_field, encrypt_field, make_associated_data_v3
from generate_it.identity import canonical_identity


def test_aad_v3_preserves_existing_format_character_identity_bytes() -> None:
    vault_uuid = b"V" * 16
    credential_uuid = b"C" * 16
    dek = b"D" * 32
    service = "Git\u200bHub"
    username = "user"

    assert canonical_identity(service) == service.casefold()
    associated_data = make_associated_data_v3(
        vault_uuid, credential_uuid, "password", service, username
    )
    ciphertext = encrypt_field(dek, associated_data, "secret")

    assert decrypt_field(dek, associated_data, ciphertext) == "secret"
