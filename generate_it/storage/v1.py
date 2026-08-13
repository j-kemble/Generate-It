"""Version 1 vault operations for Generate It storage.

This module contains v1 (PBKDF2 + Fernet) vault operations.
The actual methods are implemented on StorageManager in core.py,
with this module providing a logical grouping for migration purposes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..logging import get_logger

_log = get_logger(__name__)

if TYPE_CHECKING:
    from .core import StorageManager
