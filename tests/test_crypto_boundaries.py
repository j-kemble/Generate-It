from __future__ import annotations

import os
from typing import Any

import pytest

from generate_it._crypto_v2 import (
    AEAD_AES_256_GCM,
    AEAD_CHACHA20_POLY1305,
    CREDENTIAL_UUID_LEN,
    MAX_NOTE_BYTES,
    MAX_PASSWORD_BYTES,
    NONCE_LEN,
    decrypt_field,
    encrypt_field,
    make_associated_data,
)


@pytest.fixture(params=[AEAD_AES_256_GCM, AEAD_CHACHA20_POLY1305])
def aead_algorithm(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture
def crypto_context() -> tuple[bytes, bytes]:
    return os.urandom(32), os.urandom(CREDENTIAL_UUID_LEN)


def test_encrypt_field_rejects_password_above_byte_limit(
    crypto_context: tuple[bytes, bytes],
) -> None:
    dek, credential_uuid = crypto_context
    associated_data = make_associated_data(os.urandom(16), credential_uuid, "password")

    with pytest.raises(ValueError, match="password plaintext exceeds 1024 bytes"):
        encrypt_field(dek, associated_data, "x" * (MAX_PASSWORD_BYTES + 1))


def test_encrypt_field_rejects_multibyte_password_at_byte_boundary(
    crypto_context: tuple[bytes, bytes],
) -> None:
    dek, credential_uuid = crypto_context
    associated_data = make_associated_data(os.urandom(16), credential_uuid, "password")
    password = "é" * (MAX_PASSWORD_BYTES // 2 + 1)

    with pytest.raises(ValueError, match="password plaintext exceeds 1024 bytes"):
        encrypt_field(dek, associated_data, password)


def test_encrypt_field_accepts_note_limit_when_explicitly_selected(
    crypto_context: tuple[bytes, bytes],
    aead_algorithm: str,
) -> None:
    dek, credential_uuid = crypto_context
    associated_data = make_associated_data(os.urandom(16), credential_uuid, "note")
    note = "n" * MAX_NOTE_BYTES

    ciphertext = encrypt_field(
        dek,
        associated_data,
        note,
        aead_algorithm=aead_algorithm,
        max_plaintext_bytes=MAX_NOTE_BYTES,
        field_name="note",
    )

    assert decrypt_field(dek, associated_data, ciphertext, aead_algorithm=aead_algorithm) == note


def test_decrypt_field_rejects_malformed_ciphertext_before_aead(
    crypto_context: tuple[bytes, bytes],
    aead_algorithm: str,
) -> None:
    dek, credential_uuid = crypto_context
    associated_data = make_associated_data(os.urandom(16), credential_uuid, "password")

    malformed: tuple[Any, ...] = (b"", b"x" * (NONCE_LEN + 15), "not-bytes")
    for value in malformed:
        with pytest.raises(ValueError, match="ciphertext"):
            decrypt_field(dek, associated_data, value, aead_algorithm=aead_algorithm)
