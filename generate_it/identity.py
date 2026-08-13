"""Canonical credential identity.

Credential identity — the (service, username) pair used for duplicate
detection, indexed lookups, and AAD v3 metadata binding — is defined by
exactly one normalization rule, implemented here:

1. ``unicodedata.normalize("NFC", value)`` — fold canonically-equivalent
   Unicode sequences (e.g. "é" as U+00E9 vs "e" + U+0301) into one byte
   representation.  NFC (not NFKC) is used deliberately: compatibility
   folding (NFKC) would collapse visually-similar-but-distinct strings
   (e.g. "ﬁ" ligature vs "fi", superscript "²" vs "2"), which would be
   surprising for credential identities.
2. ``strip()`` — remove surrounding whitespace.
3. ``casefold()`` — aggressive Unicode case folding (stronger than
   ``lower()``; e.g. German "ß" folds to "ss").

The order is fixed: normalize, strip, then casefold.

AAD v2 (legacy) uses a different, frozen normalization
(``strip().lower()``) and MUST NOT switch to this helper — existing AAD v2
ciphertext depends on the legacy byte representation.  Only AAD v3 binds
canonical keys.
"""

from __future__ import annotations

import unicodedata


def _remove_identity_format_chars(value: str) -> str:
    """Remove Unicode format characters from stored identity keys."""
    return "".join(char for char in value if unicodedata.category(char) != "Cf")


def canonical_identity(value: str) -> str:
    """Return the canonical identity form of a service or username string.

    ``unicodedata.normalize("NFC", value).strip().casefold()`` — see the
    module docstring for the rationale.  The result may be empty.
    """
    normalized = unicodedata.normalize("NFC", value).strip().casefold()
    return _remove_identity_format_chars(normalized)


def canonical_service_username(service: str, username: str) -> tuple[str, str]:
    """Return the canonical (service_key, username_key) identity pair."""
    return canonical_identity(service), canonical_identity(username)


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
