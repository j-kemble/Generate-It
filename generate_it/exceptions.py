"""Domain-specific exceptions for consistent error handling in Generate It."""

from __future__ import annotations

from typing import Dict, List, Optional


class StorageError(Exception):
    """Base exception for storage errors."""


class CredentialIdentityConflictError(StorageError):
    """Raised when rows collide under canonical identity rules."""

    def __init__(self, message: str, conflicts: Optional[List[Dict[str, object]]] = None):
        super().__init__(message)
        self.conflicts: List[Dict[str, object]] = list(conflicts or [])


class AppError(StorageError):
    """Base application error."""


class WeakPasswordError(StorageError):
    """For password policy violations."""


class VaultFormatError(StorageError):
    """For unsupported vault formats."""


class CropError(StorageError):
    """For CSV/export errors."""


class TuiError(Exception):
    """For TUI-specific errors."""