"""Vault v2 cryptographic primitives (Argon2id, AES-KW, AES-256-GCM).

This module provides the v2-specific cryptographic operations used by
``StorageManager`` for vaults created or migrated to format version 2.
It is intentionally kept separate from ``storage.py`` so crypto remains
auditable and testable in isolation.
"""

from __future__ import annotations

import os
import struct
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_wrap,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VAULT_VERSION: int = 2

VAULT_UUID_LEN: int = 16
CREDENTIAL_UUID_LEN: int = 16
DEK_LEN: int = 32  # 256 bits
NONCE_LEN: int = 12  # 96 bits

# AES-KW adds 8 bytes of integrity overhead.
WRAPPED_DEK_LEN: int = 40  # 32 + 8

VERIFICATION_PLAINTEXT: bytes = b"VAULT_V2_VERIFICATION_TOKEN"

# Argon2id defaults (OWASP 2023 recommendations).
DEFAULT_ARGON2_MEMORY: int = 65536  # 64 MiB in KiB
DEFAULT_ARGON2_TIME: int = 3
DEFAULT_ARGON2_PARALLELISM: int = 4
SALT_LEN: int = 32

# AEAD algorithms recognised by the vault config.
AEAD_AES_256_GCM: str = "aes-256-gcm"
AEAD_CHACHA20_POLY1305: str = "chacha20-poly1305"

# Verification associated-data field name.
_VERIFICATION_FIELD_NAME: str = "verification"

# Sentinel credential UUID for verification token associated data.
_VERIFICATION_CREDENTIAL_UUID: bytes = b"\x00" * CREDENTIAL_UUID_LEN

# Maximum plaintext sizes.
MAX_PASSWORD_BYTES: int = 1024
MAX_NOTE_BYTES: int = 64 * 1024


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def derive_kek(
    master_password: str,
    salt: bytes,
    memory: int = DEFAULT_ARGON2_MEMORY,
    time: int = DEFAULT_ARGON2_TIME,
    parallelism: int = DEFAULT_ARGON2_PARALLELISM,
) -> bytes:
    """Derive a 256-bit Key Encryption Key from *master_password* via Argon2id.

    The KDF parameters are stored in the vault config table so that every
    unlock can reproduce the same KEK.

    Returns:
        32-byte key suitable for use as an AES-256 key-wrapping key.
    """
    kdf = Argon2id(
        salt=salt,
        length=32,
        memory_cost=memory,
        iterations=time,
        lanes=parallelism,
    )
    return kdf.derive(master_password.encode())


# ---------------------------------------------------------------------------
# DEK generation and wrapping
# ---------------------------------------------------------------------------


def generate_dek() -> bytes:
    """Generate a random 256-bit Data Encryption Key."""
    return os.urandom(DEK_LEN)


def wrap_dek(kek: bytes, dek: bytes) -> bytes:
    """Wrap *dek* with *kek* using AES-256 Key Wrap (RFC 3394).

    Returns:
        40-byte wrapped DEK (32 bytes DEK + 8 bytes integrity).
    """
    return aes_key_wrap(kek, dek)


def unwrap_dek(kek: bytes, wrapped_dek: bytes) -> bytes:
    """Unwrap *wrapped_dek* with *kek* via AES-256 Key Wrap.

    Raises:
        InvalidUnwrap: if *kek* is wrong or *wrapped_dek* has been
            tampered with.
    """
    return aes_key_unwrap(kek, wrapped_dek)


# ---------------------------------------------------------------------------
# Associated data construction
# ---------------------------------------------------------------------------


def make_associated_data(
    vault_uuid: bytes,
    credential_uuid: bytes,
    field_name: str,
) -> bytes:
    """Build AEAD associated data binding ciphertext to vault + credential + field.

    The associated data is the concatenation of:

    * *vault_uuid* — 16 bytes (prevents cross-vault ciphertext substitution).
    * *credential_uuid* — 16 bytes (prevents cross-credential substitution).
    * *field_name* — UTF-8 encoded (prevents field-name substitution).
    * version — uint16 big-endian ``VAULT_VERSION`` (prevents format
      confusion).

    All encryption and decryption in v2 MUST use this function to produce
    consistent associated data.
    """
    return b"".join(
        [
            vault_uuid,
            credential_uuid,
            field_name.encode(),
            struct.pack(">H", VAULT_VERSION),
        ]
    )


def _make_verification_associated_data(vault_uuid: bytes) -> bytes:
    """Build associated data for the verification token.

    Uses the zero credential UUID sentinel and ``"verification"`` as the
    field name, per the spec.
    """
    return make_associated_data(
        vault_uuid, _VERIFICATION_CREDENTIAL_UUID, _VERIFICATION_FIELD_NAME
    )


# ---------------------------------------------------------------------------
# AEAD encryption / decryption
# ---------------------------------------------------------------------------


def _get_aead(dek: bytes, aead_algorithm: str) -> AESGCM | ChaCha20Poly1305:
    """Return the AEAD cipher for *aead_algorithm* keyed with *dek*."""
    if aead_algorithm == AEAD_CHACHA20_POLY1305:
        return ChaCha20Poly1305(dek)
    # Default to AES-256-GCM (the primary algorithm).
    return AESGCM(dek)


def encrypt_field(
    dek: bytes,
    associated_data: bytes,
    plaintext: str,
    *,
    aead_algorithm: str = AEAD_AES_256_GCM,
) -> bytes:
    """Encrypt *plaintext* under *dek* with AES-256-GCM (or ChaCha20-Poly1305).

    The AEAD **associated data** must be constructed by
    :func:`make_associated_data` so that ciphertext is bound to the vault
    UUID, credential UUID, field name, and format version.

    Returns:
        A single BLOB suitable for direct storage in the ``encrypted_password``
        or ``encrypted_note`` column.  The wire format is::

            nonce (12 bytes) || ciphertext (N bytes) || tag (16 bytes)
    """
    aead = _get_aead(dek, aead_algorithm)
    nonce = os.urandom(NONCE_LEN)
    plaintext_bytes = plaintext.encode()
    ct = aead.encrypt(nonce, plaintext_bytes, associated_data)
    return nonce + ct


def decrypt_field(
    dek: bytes,
    associated_data: bytes,
    ciphertext: bytes,
    *,
    aead_algorithm: str = AEAD_AES_256_GCM,
) -> str:
    """Decrypt a field previously encrypted with :func:`encrypt_field`.

    The **associated_data** MUST match exactly what was used during
    encryption.  Any mismatch (wrong vault UUID, wrong credential UUID,
    wrong field name, wrong version) will cause authentication failure.

    Returns:
        The original plaintext string.

    Raises:
        ``cryptography.exceptions.InvalidTag`` (or equivalent from
        ``cryptography``) if authentication fails.
    """
    aead = _get_aead(dek, aead_algorithm)
    nonce = ciphertext[:NONCE_LEN]
    ct = ciphertext[NONCE_LEN:]
    return aead.decrypt(nonce, ct, associated_data).decode()


# ---------------------------------------------------------------------------
# Verification token
# ---------------------------------------------------------------------------


def create_verification_token(
    dek: bytes,
    vault_uuid: bytes,
    *,
    aead_algorithm: str = AEAD_AES_256_GCM,
) -> bytes:
    """Create the verification token stored in ``config.verification``.

    The token is the AES-256-GCM (or ChaCha20-Poly1305) encryption of
    ``VERIFICATION_PLAINTEXT`` under *dek* with associated data binding
    to *vault_uuid* (and a zero credential UUID sentinel).

    At unlock time, successful decryption of this token proves the caller
    possesses the correct master password.
    """
    return encrypt_field(
        dek,
        _make_verification_associated_data(vault_uuid),
        VERIFICATION_PLAINTEXT.decode(),
        aead_algorithm=aead_algorithm,
    )


def verify_token(
    dek: bytes,
    vault_uuid: bytes,
    ciphertext: bytes,
    *,
    aead_algorithm: str = AEAD_AES_256_GCM,
) -> bool:
    """Verify the stored verification token.

    Returns ``True`` if *ciphertext* decrypts to the expected verification
    plaintext.  Returns ``False`` (without raising) on any decryption
    failure, including authentication failures.
    """
    try:
        plaintext = decrypt_field(
            dek,
            _make_verification_associated_data(vault_uuid),
            ciphertext,
            aead_algorithm=aead_algorithm,
        )
        return plaintext == VERIFICATION_PLAINTEXT.decode()
    except Exception:
        return False
