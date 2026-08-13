"""Storage package for Generate It - thin wrapper re-exporting from core.

This module maintains backward compatibility: all public and private names
that were available from ``generate_it.storage`` in the monolithic layout
remain importable from here.
"""

from __future__ import annotations

from .core import (
    APP_AUTHOR,
    APP_NAME,
    CredentialIdentityConflictError,
    InvalidPasswordError,
    StorageError,
    StorageManager,
    VaultAlreadyInitializedError,
    VaultNotInitializedError,
    WeakMasterPasswordError,
    _DEFAULT_PBKDF2_ITERATIONS,
    _DEFAULT_SALT_LENGTH,
    _IDENTITY_SCHEMA_VERSION,
    _IDX_IDENTITY_ORDER,
    _IDX_IDENTITY_UNIQUE,
    _LEGACY_PBKDF2_ITERATIONS,
    _MAX_CSV_FIELD_BYTES,
    _MAX_CSV_FILE_BYTES,
    _MAX_CSV_ROWS,
    _MAX_MASTER_PASSWORD_LENGTH,
    _WEAK_PASSWORDS,
    _estimate_password_entropy,
    _validate_master_password,
)

# Re-export modules for backward compatibility with tests that import
# os, Fernet etc. directly from generate_it.storage.
from .core import (  # noqa: F401
    base64 as base64,
    os as os,
    shutil as shutil,
    sqlite3 as sqlite3,
    tempfile as tempfile,
    uuid as uuid,
)

from cryptography.fernet import Fernet as Fernet, InvalidToken as InvalidToken  # noqa: F401
from cryptography.exceptions import InvalidTag as InvalidTag  # noqa: F401
from cryptography.hazmat.primitives import hashes as hashes  # noqa: F401
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as PBKDF2HMAC  # noqa: F401
from platformdirs import user_data_dir as user_data_dir  # noqa: F401

# Re-export submodules for direct import if needed.
from . import migration as migration  # noqa: F401
from . import v1 as v1  # noqa: F401
from . import v2 as v2  # noqa: F401

__all__ = [
    "APP_AUTHOR",
    "APP_NAME",
    "CredentialIdentityConflictError",
    "InvalidPasswordError",
    "InvalidToken",
    "InvalidTag",
    "PBKDF2HMAC",
    "StorageError",
    "StorageManager",
    "VaultAlreadyInitializedError",
    "VaultNotInitializedError",
    "WeakMasterPasswordError",
    "_DEFAULT_PBKDF2_ITERATIONS",
    "_DEFAULT_SALT_LENGTH",
    "_IDENTITY_SCHEMA_VERSION",
    "_IDX_IDENTITY_ORDER",
    "_IDX_IDENTITY_UNIQUE",
    "_LEGACY_PBKDF2_ITERATIONS",
    "_MAX_CSV_FIELD_BYTES",
    "_MAX_CSV_FILE_BYTES",
    "_MAX_CSV_ROWS",
    "_MAX_MASTER_PASSWORD_LENGTH",
    "_WEAK_PASSWORDS",
    "_validate_master_password",
    "_estimate_password_entropy",
    "base64",
    "hashes",
    "os",
    "shutil",
    "sqlite3",
    "tempfile",
    "uuid",
    "user_data_dir",
    "Fernet",
    "v1",
    "v2",
    "migration",
]
