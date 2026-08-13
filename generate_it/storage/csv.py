"""CSV import/export logic for Generate It storage.

This module provides CSV import/export functionality for credentials,
supporting multiple provider formats (generic, bitwarden, apple, nordpass).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..logging import get_logger

_log = get_logger(__name__)

if TYPE_CHECKING:
    from .core import StorageManager
