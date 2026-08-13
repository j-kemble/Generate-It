"""Version 2 vault operations for Generate It storage.

This module contains v2 (Argon2id + AEAD) vault operations.
The actual methods are implemented on StorageManager in core.py,
with this module providing a logical grouping for migration purposes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..logging import get_logger

_log = get_logger(__name__)

if TYPE_CHECKING:
    from .core import StorageManager
