"""Canonical credential identity.

Credential identity — the (service, username) pair used for duplicate
detection, indexed lookups, and AAD v3/v4 metadata binding — is defined by
the normalization rules implemented here:

1. ``unicodedata.normalize("NFC", value)`` — fold canonically-equivalent
   Unicode sequences (e.g. "é" as U+00E9 vs "e" + U+0301) into one byte
   representation.  NFC (not NFKC) is used deliberately: compatibility
   folding (NFKC) would collapse visually-similar-but-distinct strings
   (e.g. "ﬁ" ligature vs "fi", superscript "²" vs "2"), which would be
   surprising for credential identities.
2. ``strip()`` — remove surrounding whitespace.
3. ``casefold()`` — aggressive Unicode case folding (stronger than
   ``lower()``; e.g. German "ß" folds to "ss").

:func:`canonical_identity` is **frozen** (NFC + strip + casefold) for
cryptographic backward compatibility with AAD v3.  It MUST NOT change —
existing v3 ciphertext depends on these exact bytes.

:func:`canonical_identity_stripped` extends the frozen canonicalization
by also removing zero-width format characters (U+200B..U+200F and U+FEFF).
It is used for new data writes, index lookups, and AAD v4.

AAD v2 (legacy) uses a different, frozen normalization
(``strip().lower()``) and MUST NOT switch to this helper — existing AAD v2
ciphertext depends on the legacy byte representation.
"""

from __future__ import annotations

import unicodedata

_ZW_RANGE = range(0x200B, 0x2010)  # 0x200B..0x200F
_ZW_EXTRAS: frozenset[int] = frozenset({0xFEFF})


def _remove_zero_width(value: str) -> str:
    """Return *value* with zero-width format characters removed."""
    return "".join(
        character
        for character in value
        if not (ord(character) in _ZW_RANGE or ord(character) in _ZW_EXTRAS)
    )


def canonical_identity(value: str) -> str:
    """Frozen canonical identity (crypto-bound for AAD v3).

    ``unicodedata.normalize("NFC", value).strip().casefold()``.
    Zero-width characters are NOT removed — this behaviour is frozen so
    that existing AAD v3 ciphertext continues to decrypt.  For new writes
    and lookups use :func:`canonical_identity_stripped`.

    The result may be empty.
    """
    return unicodedata.normalize("NFC", value).strip().casefold()


def canonical_identity_stripped(value: str) -> str:
    """Return the canonical identity with zero-width format chars removed.

    ``unicodedata.normalize("NFC", value)``, then strip zero-width
    characters (U+200B..U+200F and U+FEFF), then ``strip()``, then
    ``casefold()``.  This is the canonical form used for new data writes,
    index lookups, and AAD v4.
    """
    normalized = unicodedata.normalize("NFC", value)
    stripped = _remove_zero_width(normalized).strip().casefold()
    return stripped


def canonical_service_username(service: str, username: str) -> tuple[str, str]:
    """Return the stripped canonical (service_key, username_key) identity pair."""
    return canonical_identity_stripped(service), canonical_identity_stripped(username)


def validate_identity(service: str, username: str) -> tuple[str, str]:
    """Return the canonical identity pair, rejecting empty components.

    Write boundaries (save/update/import) must call this so that a
    credential whose service or username canonicalizes to empty (e.g.
    whitespace-only or unprintable-only input) is refused instead of being
    stored with an unusable identity.

    Raises:
        ValueError: if the canonical service or username is empty.
    """
    service_key, username_key = canonical_service_username(service, username)
    if not service_key:
        raise ValueError("Service must not be empty.")
    if not username_key:
        raise ValueError("Username must not be empty.")
    return service_key, username_key


def contains_zero_width(value: str) -> bool:
    """Return True if *value* contains any zero-width format characters."""
    return any(ord(c) in _ZW_RANGE or ord(c) in _ZW_EXTRAS for c in value)