"""Domain-specific exceptions for consistent error handling in Generate It.

Single source of truth is ``generate_it.storage`` for storage-layer
exceptions; this module re-exports them for public API stability and adds
application-level helpers.  Keeping them here prevents drift between
``storage.py`` and public ``exceptions``.
"""

from __future__ import annotations

# Re-export canonical storage exceptions — single source of truth lives in
# ``storage.py`` to avoid duplicate class identities (``except StorageError``
# must catch the same object regardless of import path).
from .storage import (
    CredentialIdentityConflictError,
    InvalidPasswordError,
    StorageError,
    VaultAlreadyInitializedError,
    VaultNotInitializedError,
    WeakMasterPasswordError,
)

# Public aliases — keep historic names for backwards compat
WeakPasswordError = WeakMasterPasswordError
VaultFormatError: type[StorageError] = StorageError  # legacy alias


class AppError(StorageError):
    """Base application error."""


class CropError(StorageError):
    """For CSV/export errors."""


class TuiError(Exception):
    """For TUI-specific errors."""