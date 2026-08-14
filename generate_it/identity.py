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

The order is fixed: normalize, strip, then casefold.  Dangerous invisible
format characters are rejected at write validation boundaries rather than
silently removed; this preserves the canonical bytes used by existing AAD v3
records while preventing new deceptive identities.

AAD v2 (legacy) uses a different, frozen normalization
(``strip().lower()``) and MUST NOT switch to this helper — existing AAD v2
ciphertext depends on the legacy byte representation.  Only AAD v3 binds
canonical keys.
"""

from __future__ import annotations

import unicodedata


_REJECTED_FORMAT_CHARS = frozenset(
    "\u061c\u180e\u200b\u200e\u200f\u202a\u202b\u202c\u202d\u202e"
    "\u2060\u2061\u2062\u2063\u2064\u2065\u2066\u2067\u2068\u2069\ufeff"
)


def _has_rejected_format_characters(value: str) -> bool:
    """Return whether *value* contains an invisible security-sensitive marker."""
    return any(char in _REJECTED_FORMAT_CHARS for char in value)


def canonical_identity(value: str) -> str:
    """Return the canonical identity form of a service or username string.

    ``unicodedata.normalize("NFC", value).strip().casefold()`` — see the
    module docstring for the rationale.  The result may be empty.
    """
    return unicodedata.normalize("NFC", value).strip().casefold()


def canonical_identity_aad_v3(value: str) -> str:
    """Return the frozen AAD v3 identity form used by existing ciphertext.

    Historical AAD v3 records removed Unicode ``Cf`` format characters before
    binding service and username metadata.  Keep that wire-format behavior
    separate from the current identity policy so old records remain decryptable.
    New writes reject the dangerous subset at :func:`validate_identity`.
    """
    normalized = canonical_identity(value)
    return "".join(char for char in normalized if unicodedata.category(char) != "Cf")


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
    normalized_service = unicodedata.normalize("NFC", service)
    normalized_username = unicodedata.normalize("NFC", username)
    if _has_rejected_format_characters(normalized_service):
        raise ValueError("Service contains a prohibited invisible format character.")
    if _has_rejected_format_characters(normalized_username):
        raise ValueError("Username contains a prohibited invisible format character.")

    service_key, username_key = canonical_service_username(service, username)
    if not service_key:
        raise ValueError("Service must not be empty.")
    if not username_key:
        raise ValueError("Username must not be empty.")
    return service_key, username_key
