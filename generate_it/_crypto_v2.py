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

# Argon2id min/max bounds for config validation.
# Hardened to OWASP 2023 low recommendation (19 MiB / ~19,456 KiB, time>=2)
# to prevent downgrade attacks via tampered vault config. Defaults remain
# at 64 MiB / 3 iter for stronger posture.
MIN_ARGON2_MEMORY: int = 19456    # 19 MiB (OWASP low)
MAX_ARGON2_MEMORY: int = 1048576  # 1 GiB
MIN_ARGON2_TIME: int = 2
MAX_ARGON2_TIME: int = 100
MIN_ARGON2_PARALLELISM: int = 1
MAX_ARGON2_PARALLELISM: int = 64

# Recognised KDF algorithms.
KDF_ARGON2ID: str = "argon2id"
KDF_SCRYPT: str = "scrypt"
_VALID_KDF_ALGORITHMS: frozenset[str] = frozenset({KDF_ARGON2ID})

# AEAD algorithms recognised by the vault config.
AEAD_AES_256_GCM: str = "aes-256-gcm"
AEAD_CHACHA20_POLY1305: str = "chacha20-poly1305"
_VALID_AEAD_ALGORITHMS: frozenset[str] = frozenset({AEAD_AES_256_GCM, AEAD_CHACHA20_POLY1305})

# Verification associated-data field name.
_VERIFICATION_FIELD_NAME: str = "verification"

# Sentinel credential UUID for verification token associated data.
_VERIFICATION_CREDENTIAL_UUID: bytes = b"\x00" * CREDENTIAL_UUID_LEN

# Maximum plaintext sizes.
MAX_PASSWORD_BYTES: int = 1024
MAX_NOTE_BYTES: int = 64 * 1024


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


def _validate_kdf_config(
    kdf_algorithm: str,
    memory: int,
    time: int,
    parallelism: int,
    salt: bytes,
) -> None:
    """Validate KDF configuration before expensive key derivation.

    Checks all KDF parameters are within acceptable ranges so that a
    malformed or tampered vault config is caught before Argon2id runs.

    Raises:
        ValueError: if any parameter is out of range or unrecognised.
    """
    if kdf_algorithm not in _VALID_KDF_ALGORITHMS:
        raise ValueError(
            f"Unknown KDF algorithm: {kdf_algorithm!r}. "
            f"Valid choices: {', '.join(sorted(_VALID_KDF_ALGORITHMS))}"
        )

    if kdf_algorithm == KDF_ARGON2ID:
        if not (MIN_ARGON2_MEMORY <= memory <= MAX_ARGON2_MEMORY):
            raise ValueError(
                f"KDF memory cost {memory} out of range "
                f"[{MIN_ARGON2_MEMORY}, {MAX_ARGON2_MEMORY}]"
            )
        if not (MIN_ARGON2_TIME <= time <= MAX_ARGON2_TIME):
            raise ValueError(
                f"KDF time cost {time} out of range "
                f"[{MIN_ARGON2_TIME}, {MAX_ARGON2_TIME}]"
            )
        if not (MIN_ARGON2_PARALLELISM <= parallelism <= MAX_ARGON2_PARALLELISM):
            raise ValueError(
                f"KDF parallelism {parallelism} out of range "
                f"[{MIN_ARGON2_PARALLELISM}, {MAX_ARGON2_PARALLELISM}]"
            )

    if len(salt) != SALT_LEN:
        raise ValueError(
            f"KDF salt must be exactly {SALT_LEN} bytes, got {len(salt)}"
        )


def _validate_vault_metadata(
    vault_uuid: bytes,
    wrapped_dek: bytes,
    aead_algorithm: str,
    verification_ct: bytes,
) -> None:
    """Validate vault metadata before expensive crypto operations.

    Checks sizes of vault UUID, wrapped DEK, and verification ciphertext
    so that obviously-corrupt or tampered vaults are caught before
    Argon2id key derivation or AEAD construction.

    Raises:
        ValueError: if any field is wrong-sized or unrecognised.
    """
    if len(vault_uuid) != VAULT_UUID_LEN:
        raise ValueError(
            f"Vault UUID must be exactly {VAULT_UUID_LEN} bytes, got {len(vault_uuid)}"
        )

    if len(wrapped_dek) != WRAPPED_DEK_LEN:
        raise ValueError(
            f"Wrapped DEK must be exactly {WRAPPED_DEK_LEN} bytes, got {len(wrapped_dek)}"
        )

    if aead_algorithm not in _VALID_AEAD_ALGORITHMS:
        raise ValueError(
            f"Unknown AEAD algorithm: {aead_algorithm!r}. "
            f"Valid choices: {', '.join(sorted(_VALID_AEAD_ALGORITHMS))}"
        )

    # Ciphertext must be at least nonce (12) + tag (16) = 28 bytes.
    if len(verification_ct) < NONCE_LEN + 16:
        raise ValueError(
            f"Verification ciphertext too short: {len(verification_ct)} bytes "
            f"(minimum {NONCE_LEN + 16})"
        )


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

    This is the AAD v1 format (``aad_version`` absent or 1):

    * *vault_uuid* — 16 bytes (prevents cross-vault ciphertext substitution).
    * *credential_uuid* — 16 bytes (prevents cross-credential substitution).
    * *field_name* — UTF-8 encoded (prevents field-name substitution).
    * version — uint16 big-endian ``VAULT_VERSION`` (prevents format
      confusion).

    All encryption and decryption in v2 MUST use this function to produce
    consistent associated data.

    For the metadata-bound AAD v2 format, use :func:`make_associated_data_v2`.
    """
    return _make_aad_v1(vault_uuid, credential_uuid, field_name)


def _make_aad_v1(
    vault_uuid: bytes,
    credential_uuid: bytes,
    field_name: str,
) -> bytes:
    """Legacy AAD v1 — no metadata binding beyond vault/credential UUIDs."""
    return b"".join(
        [
            vault_uuid,
            credential_uuid,
            field_name.encode(),
            struct.pack(">H", VAULT_VERSION),
        ]
    )


def make_associated_data_v2(
    vault_uuid: bytes,
    credential_uuid: bytes,
    field_name: str,
    service: str,
    username: str,
) -> bytes:
    """Build AAD v2 with length-prefixed fields and metadata binding.

    AAD v2 binds ciphertext to:

    * *vault_uuid* — 16 bytes, length-prefixed
    * *credential_uuid* — 16 bytes, length-prefixed
    * *field_name* — UTF-8 encoded (no length prefix; last fixed element)
    * *service* — normalised (lowercased, stripped), UTF-8 encoded
    * *username* — normalised (lowercased, stripped), UTF-8 encoded

    The AAD version (uint16 = 2) is prepended so receivers can detect
    which format was used.

    This prevents:
    - Cross-vault swaps (vault_uuid binding)
    - Cross-credential swaps (credential_uuid binding)
    - Field-name swaps (field_name binding)
    - Metadata swaps — re-labelling a credential's service or username
      without re-encrypting (service + username binding)
    """
    normalised_service = service.strip().lower()
    normalised_username = username.strip().lower()
    parts = [
        struct.pack(">H", 2),                     # aad_version
        struct.pack(">B", VAULT_UUID_LEN),        # vault_uuid length
        vault_uuid,                                # vault_uuid
        struct.pack(">B", CREDENTIAL_UUID_LEN),   # credential_uuid length
        credential_uuid,                           # credential_uuid
        field_name.encode(),                       # field_name
        normalised_service.encode(),               # service (normalised)
        normalised_username.encode(),              # username (normalised)
    ]
    return b"".join(parts)


def make_associated_data_v3(
    vault_uuid: bytes,
    credential_uuid: bytes,
    field_name: str,
    service: str,
    username: str,
) -> bytes:
    """Build AAD v3 with explicit uint32 BE length-prefixed components.

    AAD v3 resolves the concatenation ambiguity present in AAD v2 by
    prefixing EVERY variable-length component (field_name, canonical
    service_key, canonical username_key) with an explicit 32-bit big-endian
    length prefix.

    Component layout:
    - uint16 BE: aad_version = 3
    - uint8 BE: vault_uuid length (16)
    - bytes(16): vault_uuid
    - uint8 BE: credential_uuid length (16)
    - bytes(16): credential_uuid
    - uint32 BE: len(field_name_utf8) + bytes
    - uint32 BE: len(service_key_utf8) + bytes (canonical: NFC+strip+casefold)
    - uint32 BE: len(username_key_utf8) + bytes (canonical: NFC+strip+casefold)
    """
    from .identity import canonical_identity

    fn_bytes = field_name.encode("utf-8")
    svc_bytes = canonical_identity(service).encode("utf-8")
    usr_bytes = canonical_identity(username).encode("utf-8")

    parts = [
        struct.pack(">H", 3),                      # aad_version = 3
        struct.pack(">B", VAULT_UUID_LEN),         # vault_uuid length (16)
        vault_uuid,                                 # vault_uuid (16 bytes)
        struct.pack(">B", CREDENTIAL_UUID_LEN),    # credential_uuid length (16)
        credential_uuid,                            # credential_uuid (16 bytes)
        struct.pack(">I", len(fn_bytes)),          # uint32 BE field_name length
        fn_bytes,
        struct.pack(">I", len(svc_bytes)),         # uint32 BE service_key length
        svc_bytes,
        struct.pack(">I", len(usr_bytes)),         # uint32 BE username_key length
        usr_bytes,
    ]
    return b"".join(parts)


def _make_verification_associated_data(vault_uuid: bytes) -> bytes:
    """Build associated data for the verification token.

    Uses the zero credential UUID sentinel and ``"verification"`` as the
    field name, per the spec.
    """
    return make_associated_data(
        vault_uuid, _VERIFICATION_CREDENTIAL_UUID, _VERIFICATION_FIELD_NAME
    )


def make_associated_data_v4(
    vault_uuid: bytes,
    credential_uuid: bytes,
    field_name: str,
    service: str,
    username: str,
) -> bytes:
    """Build AAD v4 with explicit uint32 BE length-prefixed components.

    Identical layout to AAD v3, but the canonical service/username
    components use the zero-width-stripped canonicalization
    (``canonical_identity_stripped``) instead of the frozen
    ``canonical_identity``.  The version marker distinguishes the two so
    v3 ciphertext (legacy canonicalization) and v4 ciphertext (stripped
    canonicalization) can never be confused during decryption.

    Component layout:
    - uint16 BE: aad_version = 4
    - uint8 BE: vault_uuid length (16)
    - bytes(16): vault_uuid
    - uint8 BE: credential_uuid length (16)
    - bytes(16): credential_uuid
    - uint32 BE: len(field_name_utf8) + bytes
    - uint32 BE: len(service_key_utf8) + bytes (stripped canonical)
    - uint32 BE: len(username_key_utf8) + bytes (stripped canonical)
    """
    from .identity import canonical_identity_stripped

    fn_bytes = field_name.encode("utf-8")
    svc_bytes = canonical_identity_stripped(service).encode("utf-8")
    usr_bytes = canonical_identity_stripped(username).encode("utf-8")

    parts = [
        struct.pack(">H", 4),                      # aad_version = 4
        struct.pack(">B", VAULT_UUID_LEN),         # vault_uuid length (16)
        vault_uuid,                                 # vault_uuid (16 bytes)
        struct.pack(">B", CREDENTIAL_UUID_LEN),    # credential_uuid length (16)
        credential_uuid,                            # credential_uuid (16 bytes)
        struct.pack(">I", len(fn_bytes)),          # uint32 BE field_name length
        fn_bytes,
        struct.pack(">I", len(svc_bytes)),         # uint32 BE service_key length
        svc_bytes,
        struct.pack(">I", len(usr_bytes)),         # uint32 BE username_key length
        usr_bytes,
    ]
    return b"".join(parts)


# ---------------------------------------------------------------------------
# AEAD encryption / decryption
# ---------------------------------------------------------------------------


def _get_aead(dek: bytes, aead_algorithm: str) -> AESGCM | ChaCha20Poly1305:
    """Return the AEAD cipher for *aead_algorithm* keyed with *dek*.

    Raises:
        ValueError: if *aead_algorithm* is not a recognised AEAD algorithm.
    """
    if aead_algorithm == AEAD_AES_256_GCM:
        return AESGCM(dek)
    if aead_algorithm == AEAD_CHACHA20_POLY1305:
        return ChaCha20Poly1305(dek)
    raise ValueError(
        f"Unknown AEAD algorithm: {aead_algorithm!r}. "
        f"Valid choices: {', '.join(sorted(_VALID_AEAD_ALGORITHMS))}"
    )


def encrypt_field(
    dek: bytes,
    associated_data: bytes,
    plaintext: str,
    *,
    aead_algorithm: str = AEAD_AES_256_GCM,
    max_plaintext_bytes: int = MAX_PASSWORD_BYTES,
    field_name: str = "password",
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
    plaintext_bytes = plaintext.encode("utf-8")
    if len(plaintext_bytes) > max_plaintext_bytes:
        raise ValueError(f"{field_name} plaintext exceeds {max_plaintext_bytes} bytes")
    aead = _get_aead(dek, aead_algorithm)
    nonce = os.urandom(NONCE_LEN)
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
    if not isinstance(ciphertext, bytes):
        raise ValueError("ciphertext must be bytes")
    minimum_length = NONCE_LEN + 16
    if len(ciphertext) < minimum_length:
        raise ValueError(f"ciphertext must be at least {minimum_length} bytes")
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
