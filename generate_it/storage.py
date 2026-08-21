import tempfile
import time as _time
import os
import shutil
import sqlite3
import base64
import csv
import uuid
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from platformdirs import user_data_dir
from . import _crypto_v2, csv_formats
from ._crypto_v2 import MAX_NOTE_BYTES, MAX_PASSWORD_BYTES
from .identity import (
    canonical_identity_stripped,
    canonical_service_username,
    validate_identity,
)
from .logging import get_logger

_log = get_logger("storage")

APP_NAME = "generate-it"
APP_AUTHOR = "j-kemble"

# Single source of truth for vault/crypto limits — see generate_it/constants.py
from .constants import (  # noqa: E402  (import after _log is intentional)
    _BACKUP_WARN_THRESHOLD,
    _DEFAULT_PBKDF2_ITERATIONS,
    _DEFAULT_SALT_LENGTH,
    _IDENTITY_SCHEMA_VERSION,
    _IDX_IDENTITY_UNIQUE,
    _LEGACY_PBKDF2_ITERATIONS,
    _MAX_BACKUP_RETAIN,
    _MAX_CSV_FIELD_BYTES,
    _MAX_CSV_FILE_BYTES,
    _MAX_CSV_ROWS,
    _MAX_MASTER_PASSWORD_LENGTH,
    _MAX_URL_BYTES,
    _SQLITE_BUSY_TIMEOUT_MS,
    _SQLITE_CACHE_SIZE_PAGES,
    _SQLITE_FOREIGN_KEYS,
    _VAULT_INTEGRITY_BATCH_SIZE,
    _VAULT_SEARCH_SQL_LIMIT,
    _VAULT_SEARCH_SQL_LIKE_LIMIT,
    _SQLITE_JOURNAL_MODE,
    _SQLITE_SYNCHRONOUS,
    _SQLITE_TEMP_STORE,
    _VAULT_PAGE_SIZE,
)

class StorageError(Exception):
    """Base exception for storage errors."""
    pass

class VaultNotInitializedError(StorageError):
    """Raised when attempting to access a vault that doesn't exist."""
    pass


class VaultAlreadyInitializedError(StorageError):
    """Raised when initialization would overwrite an existing vault."""
    pass


class InvalidPasswordError(StorageError):
    """Raised when the provided master password is incorrect."""
    pass


class WeakMasterPasswordError(StorageError):
    """Raised when the master password fails the strength policy."""
    pass


class CredentialIdentityConflictError(StorageError):
    """Raised when existing rows collide under canonical identity rules.

    Non-destructive: no rows are deleted or merged automatically.  The
    ``conflicts`` attribute lists ``{"service", "username", "ids"}`` dicts
    so the caller can show the user exactly which credentials conflict;
    the user must resolve the duplicates (rename or delete) before the
    identity-schema migration can be rerun.
    """

    def __init__(self, message: str, conflicts: Optional[List[Dict[str, object]]] = None):
        super().__init__(message)
        self.conflicts: List[Dict[str, object]] = list(conflicts or [])


# Common weak passwords that are unconditionally rejected (case-insensitive).
_WEAK_PASSWORDS: frozenset[str] = frozenset({
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball",
    "abc123", "football", "monkey", "letmein", "696969", "shadow",
    "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890",
    "michael", "654321", "pussy", "superman", "1qaz2wsx", "7777777",
    "fuckyou", "121212", "000000", "qazwsx", "123qwe", "killer",
    "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter",
    "buster", "soccer", "harley", "batman", "andrew", "tigger",
    "sunshine", "iloveyou", "fuckme", "2000", "charlie", "robert",
    "thomas", "hockey", "ranger", "daniel", "starwars", "klaster",
    "112233", "george", "asshole", "computer", "michelle", "jessica",
    "pepper", "1111", "zxcvbn", "555555", "11111111", "131313",
    "freedom", "777777", "pass", "fuck", "maggie", "159753", "aaaaaa",
    "ginger", "princess", "joshua", "cheese", "amanda", "summer",
    "love", "ashley", "nicole", "chelsea", "biteme", "matthew",
    "access", "yankees", "987654321", "dallas", "austin", "thunder",
    "taylor", "matrix", "mobilemail", "mom", "monitor", "monitoring",
    "qwerty123", "qwerty123!", "password1", "password123", "masterpass",
    "welcome1!", "admin123!",
})


def _validate_master_password(password: str) -> None:
    """Validate a master password against the security policy.

    Requirements:
        - Minimum 8 characters
        - At least 1 uppercase letter (A-Z)
        - At least 1 lowercase letter (a-z)
        - At least 1 digit (0-9)
        - At least 1 special character (non-alphanumeric)
        - Not in the common weak-password list

    Raises:
        WeakMasterPasswordError: if the password is empty, too short, too long,
            lacks required character classes, or matches a known common/weak value.
    """
    if not password:
        raise WeakMasterPasswordError("Master password cannot be empty.")
    if len(password) < 8:
        raise WeakMasterPasswordError(
            "Master password must be at least 8 characters."
        )
    if len(password) > _MAX_MASTER_PASSWORD_LENGTH:
        raise WeakMasterPasswordError(
            f"Master password must be at most {_MAX_MASTER_PASSWORD_LENGTH} characters."
        )
    if password.casefold() in _WEAK_PASSWORDS:
        raise WeakMasterPasswordError(
            "That password is too common and easily guessed. Please choose a stronger one."
        )
    if not any(c.isupper() for c in password):
        raise WeakMasterPasswordError(
            "Master password must contain at least 1 uppercase letter (A-Z)."
        )
    if not any(c.islower() for c in password):
        raise WeakMasterPasswordError(
            "Master password must contain at least 1 lowercase letter (a-z)."
        )
    if not any(c.isdigit() for c in password):
        raise WeakMasterPasswordError(
            "Master password must contain at least 1 digit (0-9)."
        )
    if not any(not c.isalnum() for c in password):
        raise WeakMasterPasswordError(
            "Master password must contain at least 1 special character (e.g., !@#$%^&*)."
        )


def _validate_field_size(password: str, note: str) -> None:
    """Reject credential fields that exceed their encoded byte limits."""
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise StorageError(f"password exceeds {MAX_PASSWORD_BYTES} bytes.")
    if len(note.encode("utf-8")) > MAX_NOTE_BYTES:
        raise StorageError(f"note exceeds {MAX_NOTE_BYTES} bytes.")


def _validate_url(url: str) -> None:
    """Reject url that exceeds byte limit."""
    if len(url.encode("utf-8")) > _MAX_URL_BYTES:
        raise StorageError(f"url exceeds {_MAX_URL_BYTES} bytes.")


def _sanitize_url(url: str) -> str:
    """Trim whitespace from url; empty string normalized to ''."""
    return url.strip()


def _has_url_column(cursor: sqlite3.Cursor) -> bool:
    cursor.execute("PRAGMA table_info(credentials)")
    return any(row["name"] == "url" for row in cursor.fetchall())


def _ensure_url_column(conn: sqlite3.Connection) -> None:
    """Add url column if missing (flat helper, idempotent)."""
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='credentials'")
    if cursor.fetchone() is None:
        return
    if not _has_url_column(cursor):
        cursor.execute("ALTER TABLE credentials ADD COLUMN url TEXT DEFAULT ''")
        conn.commit()
        _log.info("url column added to credentials")

class StorageManager:
    def __init__(self, db_path: Optional[Path] = None):
        if db_path:
            self.db_path = db_path
            self.data_dir = db_path.parent
            self.data_dir.mkdir(parents=True, exist_ok=True)
            self._ensure_private_permissions(self.data_dir, 0o700)
        else:
            self.data_dir = Path(user_data_dir(APP_NAME, APP_AUTHOR))
            self.data_dir.mkdir(parents=True, exist_ok=True)
            self._ensure_private_permissions(self.data_dir, 0o700)
            self.db_path = self.data_dir / "vault.db"

        self._fernet: Optional[Fernet] = None
        self._db_connection: Optional[sqlite3.Connection] = None

        # v2 state (set on unlock / init for v2 vaults)
        self._vault_version: Optional[int] = None
        self._dek: Optional[bytes] = None
        self._vault_uuid: Optional[bytes] = None
        self._aead_algorithm: str = _crypto_v2.AEAD_AES_256_GCM
        self._aad_version: int = 1  # 1=legacy, 2=metadata-bound

        # Set when the identity-schema migration found canonical duplicates in
        # an existing vault.  The vault remains fully usable (columns are
        # backfilled) but the unique index is deferred until the user resolves
        # the conflicts; the migration retries on the next unlock.
        self.identity_conflict: Optional[CredentialIdentityConflictError] = None

    @staticmethod
    def _ensure_private_permissions(path: Path, mode: int = 0o600) -> None:
        """Set owner-only permissions on a file or directory.

        On POSIX systems this enforces ``mode`` (default 0600 for files,
        0700 for directories).  On non-POSIX systems this is a no-op.
        Failures are logged but never raised — the database still works
        even when the filesystem doesn't support POSIX permissions.
        """
        if os.name != "posix":
            return
        try:
            os.chmod(str(path), mode)
        except OSError:
            _log.warning("Could not set permissions on %s", path)

    @staticmethod
    def _secure_temp_file(dir_path: Path, suffix: str) -> Path:
        """Create a securely-named temp file in *dir_path* with mode 0600.

        Uses :func:`tempfile.mkstemp` to generate an unpredictable name,
        avoiding symlink-following attacks on predictable temp-file paths.
        The returned file exists on disk with restricted permissions and
        an open file descriptor has been closed — callers are responsible
        for opening and writing to it.
        """
        fd, tmp_path = tempfile.mkstemp(suffix=suffix, dir=str(dir_path))
        os.close(fd)
        if os.name == "posix":
            os.chmod(tmp_path, 0o600)
        return Path(tmp_path)

    def _create_secure_backup(self, backup_suffix: str) -> Path:
        """Create a private on-disk backup of the vault and return its path.

        Writes to a securely-named temp file (0600) in the vault directory,
        then atomically renames it to ``<db_name><backup_suffix>``.  On any
        copy failure the temp file is removed so no partial backup is left
        behind.  Shared by the v1→v2, identity-schema, zero-width-identity,
        and AAD migrations so backup creation has one authoritative,
        security-critical implementation.

        After creating the backup, auto-prunes oldest backups when the
        total exceeds ``_MAX_BACKUP_RETAIN`` so disk usage stays bounded
        (low-risk disk-fill hardening).  Pruning failures are logged but
        never abort the caller.

        Raises:
            Any filesystem error from :func:`shutil.copy2` (the vault is
                left untouched).
        """
        backup_tmp = self._secure_temp_file(self.db_path.parent, backup_suffix)
        try:
            shutil.copy2(self.db_path, backup_tmp)
        except BaseException:
            if backup_tmp.exists():
                try:
                    backup_tmp.unlink()
                except OSError:
                    pass
            raise
        backup_path = self.db_path.with_suffix(self.db_path.suffix + backup_suffix)
        os.replace(str(backup_tmp), str(backup_path))
        self._ensure_private_permissions(backup_path, 0o600)
        # Auto-prune oldest backups if we exceed the retain limit (low-risk).
        try:
            if len(self.list_backups()) > _MAX_BACKUP_RETAIN:
                pruned = self.prune_backups(keep_latest=_MAX_BACKUP_RETAIN)
                if pruned:
                    _log.info("auto-pruned %d old backup(s) after %s", len(pruned), backup_suffix)
        except Exception:
            pass
        return backup_path

    def _configure_connection(self, conn: sqlite3.Connection) -> None:
        """Apply reusable SQLite pragmas for fast, safe data travel."""
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={_SQLITE_BUSY_TIMEOUT_MS}")
        conn.execute(f"PRAGMA journal_mode={_SQLITE_JOURNAL_MODE}")
        conn.execute(f"PRAGMA synchronous={_SQLITE_SYNCHRONOUS}")
        conn.execute(f"PRAGMA cache_size={_SQLITE_CACHE_SIZE_PAGES}")
        conn.execute(f"PRAGMA temp_store={_SQLITE_TEMP_STORE}")
        conn.execute(f"PRAGMA foreign_keys={_SQLITE_FOREIGN_KEYS}")

    def _get_conn(self) -> sqlite3.Connection:
        if not self._db_connection:
            self._db_connection = sqlite3.connect(self.db_path)
            self._configure_connection(self._db_connection)
            self._ensure_private_permissions(self.db_path, 0o600)
        return self._db_connection

    def _cached_has_url_column(self, cursor: sqlite3.Cursor) -> bool:
        """Cached wrapper around _has_url_column to avoid repeated PRAGMA."""
        cached = getattr(self, "_has_url_column_cache", None)
        if cached is not None:
            return bool(cached)
        result = _has_url_column(cursor)
        self._has_url_column_cache = result
        return result

    def _invalidate_url_column_cache(self) -> None:
        """Clear cached url-column presence after schema migration."""
        if hasattr(self, "_has_url_column_cache"):
            delattr(self, "_has_url_column_cache")

    def set_app_setting(self, key: str, value: str) -> None:
        """Persist a non-sensitive app preference in the config table."""
        conn = self._get_conn()
        cursor = conn.cursor()
        stored_key = f"app_setting:{key}"
        stored_value = value.encode("utf-8")
        cursor.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            (stored_key, stored_value),
        )
        conn.commit()

    @staticmethod
    def _decode_app_setting_value(value: Any, default: Optional[str]) -> Optional[str]:
        """Flat helper: decode a config value to str, reusable."""
        if value is None:
            return default
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError:
                return default
        return str(value)

    def get_app_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Read a persisted non-sensitive app preference from the config table."""
        result = self.get_app_settings([key], {key: default})
        return result.get(key, default)

    def get_app_settings(
        self, keys: List[str], defaults: Optional[Dict[str, Optional[str]]] = None
    ) -> Dict[str, Optional[str]]:
        """Batch fetch multiple app settings in one query — reusable."""
        if not keys:
            return {}
        defaults = defaults or {}
        conn = self._get_conn()
        cursor = conn.cursor()
        stored_keys = [f"app_setting:{k}" for k in keys]
        placeholders = ",".join("?" for _ in stored_keys)
        cursor.execute(
            f"SELECT key, value FROM config WHERE key IN ({placeholders})",  # nosec B608 — placeholders are '?' only, values are parameterized
            stored_keys,
        )
        found: Dict[str, Any] = {row["key"]: row["value"] for row in cursor.fetchall()}
        out: Dict[str, Optional[str]] = {}
        for key in keys:
            stored_key = f"app_setting:{key}"
            if stored_key in found:
                out[key] = self._decode_app_setting_value(found[stored_key], defaults.get(key))
            else:
                out[key] = defaults.get(key)
        return out

    def set_app_settings(self, items: Dict[str, str]) -> None:
        """Batch persist multiple app settings in one transaction — reusable."""
        if not items:
            return
        conn = self._get_conn()
        cursor = conn.cursor()
        rows = [(f"app_setting:{k}", v.encode("utf-8")) for k, v in items.items()]
        cursor.executemany(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            rows,
        )
        conn.commit()

    # --- Persistent lockout (survives restarts) -----------------------------
    _LOCKOUT_ATTEMPTS_KEY = "lockout_failed_attempts"
    _LOCKOUT_UNTIL_KEY = "lockout_until_epoch"
    _LOCKOUT_SET_KEY = "lockout_set_epoch"

    def _read_optional_float_config(self, cursor: sqlite3.Cursor, key: str) -> Optional[float]:
        """Read a float config value, returning None if absent."""
        cursor.execute("SELECT value FROM config WHERE key=?", (key,))
        row = cursor.fetchone()
        if row is None:
            return None
        raw = row["value"]
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        try:
            return float(str(raw))
        except (TypeError, ValueError):
            raise StorageError(f"Config key '{key}' has malformed value: {raw!r}")

    def get_persistent_lockout_state(self) -> Tuple[int, Optional[float]]:
        """Return (failed_attempts, lockout_until_epoch) from config table.

        Reads without requiring the vault to be unlocked.  Returns (0, None)
        if the vault does not exist or keys are absent.  Malformed values
        are treated as (0, None) and cleared.

        Note: ``lockout_until_epoch`` is a wall-clock epoch (``time.time()``)
        so it survives restarts, but is therefore subject to forward system-
        clock jumps that can clear the deadline early.  The attempt counter is
        preserved even after expiry so escalation is not reset by a jump
        (see ``tui_security._sync_persistent_lockout_from_storage``).  A
        ``lockout_set_epoch`` is also stored to detect backward jumps and cap
        the remaining window to the original delay.
        """
        if not self.vault_exists():
            return 0, None
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            attempts = self._read_optional_int_config(cursor, self._LOCKOUT_ATTEMPTS_KEY)
            until = self._read_optional_float_config(cursor, self._LOCKOUT_UNTIL_KEY)
        except StorageError:
            # Malformed lockout state — clear it.
            try:
                self.clear_persistent_lockout_state()
            except Exception:
                pass
            return 0, None
        except sqlite3.Error:
            return 0, None
        return (attempts if attempts is not None else 0, until)

    def get_persistent_lockout_set_epoch(self) -> Optional[float]:
        """Return wall-clock epoch when the current lockout was set, if stored."""
        if not self.vault_exists():
            return None
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            return self._read_optional_float_config(cursor, self._LOCKOUT_SET_KEY)
        except (StorageError, sqlite3.Error):
            return None

    def set_persistent_lockout_state(self, attempts: int, lockout_until_epoch: Optional[float]) -> None:
        """Persist lockout state to the config table (plaintext)."""
        if not self.vault_exists():
            return
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            (self._LOCKOUT_ATTEMPTS_KEY, str(max(0, attempts))),
        )
        if lockout_until_epoch is None:
            cursor.execute("DELETE FROM config WHERE key=?", (self._LOCKOUT_UNTIL_KEY,))
            cursor.execute("DELETE FROM config WHERE key=?", (self._LOCKOUT_SET_KEY,))
        else:
            cursor.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
                (self._LOCKOUT_UNTIL_KEY, str(float(lockout_until_epoch))),
            )
            cursor.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
                (self._LOCKOUT_SET_KEY, str(float(_time.time()))),
            )
        conn.commit()

    def clear_persistent_lockout_state(self) -> None:
        """Clear persisted lockout state after a successful unlock."""
        if not self.vault_exists():
            return
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM config WHERE key IN (?, ?, ?)",
                (self._LOCKOUT_ATTEMPTS_KEY, self._LOCKOUT_UNTIL_KEY, self._LOCKOUT_SET_KEY),
            )
            conn.commit()
        except sqlite3.Error:
            pass

    def _read_optional_int_config(self, cursor: sqlite3.Cursor, key: str) -> Optional[int]:
        """Read an integer config value, returning None if absent.

        Raises StorageError when the value is present but malformed, so callers
        can distinguish "genuinely absent → use legacy default" from "present
        but corrupt → refuse to proceed".
        """
        cursor.execute("SELECT value FROM config WHERE key=?", (key,))
        row = cursor.fetchone()
        if row is None:
            return None
        raw = row["value"]
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        try:
            return int(str(raw))
        except (TypeError, ValueError):
            raise StorageError(f"Config key '{key}' has malformed value: {raw!r}")

    def _load_kdf_params(self, cursor: sqlite3.Cursor) -> tuple[str, int, int, int]:
        """Load KDF algorithm and Argon2 params with defaults — single authoritative reader.

        Consolidates the 3 int lookups (memory/time/parallelism) plus algorithm
        that were duplicated across unlock, verify, password-change, and DEK rotation.
        All callers get the same defaults and validation path.
        """
        cursor.execute("SELECT value FROM config WHERE key='kdf_algorithm'")
        row = cursor.fetchone()
        if row is None or row["value"] is None:
            kdf_algorithm = "argon2id"
        else:
            raw = row["value"]
            kdf_algorithm = raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        memory_raw = self._read_optional_int_config(cursor, "kdf_memory_cost")
        memory = memory_raw if memory_raw is not None else _crypto_v2.DEFAULT_ARGON2_MEMORY
        time_raw = self._read_optional_int_config(cursor, "kdf_time_cost")
        time_cost = time_raw if time_raw is not None else _crypto_v2.DEFAULT_ARGON2_TIME
        parallelism_raw = self._read_optional_int_config(cursor, "kdf_parallelism")
        parallelism = parallelism_raw if parallelism_raw is not None else _crypto_v2.DEFAULT_ARGON2_PARALLELISM
        return kdf_algorithm, memory, time_cost, parallelism

    def _load_aead_algorithm(self, cursor: sqlite3.Cursor) -> str:
        """Load AEAD algorithm with default — single reader."""
        cursor.execute("SELECT value FROM config WHERE key='aead_algorithm'")
        row = cursor.fetchone()
        if row is None or row["value"] is None:
            return _crypto_v2.AEAD_AES_256_GCM
        raw = row["value"]
        return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)

    def _derive_key(self, password: str, salt: bytes, iterations: Optional[int] = None) -> bytes:
        """Derives a url-safe base64-encoded key from the password and salt."""
        iters = iterations if iterations is not None else _DEFAULT_PBKDF2_ITERATIONS
        if iters < 1:
            raise StorageError(f"Invalid iterations: {iters}. Value must be >= 1.")
        if iters > 10_000_000:
            raise StorageError(f"Iterations too high: {iters}. Maximum is 10,000,000.")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iters,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def initialize_vault(self, master_password: str) -> None:
        """Sets up the database schema and initializes security markers."""
        if self.vault_exists():
            raise VaultAlreadyInitializedError("Vault already initialized.")

        _validate_field_size(master_password, "")
        _validate_master_password(master_password)

        salt = os.urandom(_DEFAULT_SALT_LENGTH)
        key = self._derive_key(master_password, salt, _DEFAULT_PBKDF2_ITERATIONS)
        fernet = Fernet(key)

        # Encrypt a known value to verify password later
        verification_token = fernet.encrypt(b"VERIFICATION_TOKEN")

        conn = self._get_conn()
        cursor = conn.cursor()

        # Create tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value BLOB
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                encrypted_note BLOB,
                note_is_hidden INTEGER DEFAULT 0,
                service_key TEXT,
                username_key TEXT,
                url TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        try:
            cursor.execute("SELECT note_is_hidden FROM credentials LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE credentials ADD COLUMN note_is_hidden INTEGER DEFAULT 0")

        if not _has_url_column(cursor):
            try:
                cursor.execute("ALTER TABLE credentials ADD COLUMN url TEXT DEFAULT ''")
            except sqlite3.OperationalError:
                pass

        self._create_identity_indexes(cursor)

        # Store configuration
        cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", ("salt", salt))
        cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", ("verification", verification_token))
        cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", ("pbkdf2_iterations", str(_DEFAULT_PBKDF2_ITERATIONS)))
        cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", ("salt_length", str(_DEFAULT_SALT_LENGTH)))
        cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", ("identity_schema_version", str(_IDENTITY_SCHEMA_VERSION)))

        conn.commit()

        # Defense in depth: ensure the file is owner-only after creation.
        self._ensure_private_permissions(self.db_path, 0o600)

        # Automatically unlock after initialization
        self._fernet = fernet
        self._vault_version = 1
        _log.info("vault initialized at %s", self.db_path)

    def vault_exists(self) -> bool:
        if not self.db_path.exists():
            return False

        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='config'")
            return cursor.fetchone() is not None
        except sqlite3.Error:
            return False

    def unlock_vault(self, master_password: str) -> None:
        """Unlocks the vault with the master password.

        Detects the vault format version from the config table and
        dispatches to the appropriate unlock routine (v1 PBKDF2+Fernet or
        v2 Argon2id+AEAD).
        """
        if not self.vault_exists():
            raise VaultNotInitializedError("Vault not initialized.")

        conn = self._get_conn()
        cursor = conn.cursor()
        version = self._detect_vault_version(cursor)

        if version == 2:
            self._vault_version = 2  # pre-set so _unlock_vault_v2 can validate
            self._unlock_vault_v2(master_password)
            return

        if version != 1:
            raise StorageError(
                f"Unsupported vault format version: {version}. "
                "Only versions 1 and 2 are supported."
            )

        # ── v1 unlock ────────────────────────────────────────────────

        try:
            cursor.execute("SELECT value FROM config WHERE key=?", ("salt",))
            salt = cursor.fetchone()["value"]

            cursor.execute("SELECT value FROM config WHERE key=?", ("verification",))
            verification_token = cursor.fetchone()["value"]
        except TypeError:
             # Handle cases where config might be corrupted or missing keys
             raise StorageError("Vault configuration corrupted.")

        # Read the iteration count persisted for this vault. Fall back to the
        # legacy default (100k) for vaults created before this value was stored,
        # so existing vaults keep unlocking.
        stored_iters_raw = self._read_optional_int_config(cursor, "pbkdf2_iterations")
        if stored_iters_raw is None:
            stored_iters = _LEGACY_PBKDF2_ITERATIONS  # genuinely absent → legacy
        else:
            if stored_iters_raw < 1:
                raise StorageError(f"Invalid pbkdf2_iterations: {stored_iters_raw}. Value must be >= 1.")
            if stored_iters_raw > 10_000_000:
                raise StorageError(f"pbkdf2_iterations {stored_iters_raw} exceeds maximum (10,000,000).")
            stored_iters = stored_iters_raw

        key = self._derive_key(master_password, salt, stored_iters)
        fernet = Fernet(key)

        try:
            decrypted_verification = fernet.decrypt(verification_token)
            if decrypted_verification != b"VERIFICATION_TOKEN":
                raise InvalidPasswordError("Invalid master password.")
        except (InvalidPasswordError, InvalidToken):
            raise InvalidPasswordError("Invalid master password.")
        except sqlite3.Error as e:
            raise StorageError(f"Failed to decrypt vault verification: {e}") from e

        self._fernet = fernet
        self._vault_version = 1
        # Legacy iteration detection — warn and flag for upgrade.
        if stored_iters < _DEFAULT_PBKDF2_ITERATIONS:
            _log.warning(
                "v1 vault uses legacy PBKDF2 iterations=%d (recommended %d). "
                "Consider migrating to v2 (Argon2id) via vault health menu.",
                stored_iters, _DEFAULT_PBKDF2_ITERATIONS,
            )
            # Expose via attribute so UI can prompt upgrade.
            self._legacy_pbkdf2_needs_upgrade = True
        else:
            self._legacy_pbkdf2_needs_upgrade = False
        self._ensure_identity_schema()
        _log.info("vault unlocked")

    @staticmethod
    def _detect_vault_version(cursor: sqlite3.Cursor) -> int:
        """Detect the vault format version from the config table.

        Returns:
            1 if no ``version`` key exists (v1 baseline).
            The integer value of ``version`` otherwise.

        Raises:
            StorageError: if the version value is unrecognised.
        """
        cursor.execute("SELECT value FROM config WHERE key = 'version'")
        row = cursor.fetchone()
        if row is None:
            return 1
        value = row["value"]
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        try:
            return int(value)
        except (ValueError, TypeError):
            raise StorageError(f"Unrecognized vault version: {value!r}")

    def is_v2_vault(self) -> bool:
        """Return ``True`` if the on-disk vault is format v2.

        Must be called before unlocking (reads the config table).
        """
        if not self.vault_exists():
            return False
        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            return self._detect_vault_version(cursor) == 2
        except StorageError:
            return False

    # ------------------------------------------------------------------
    # Canonical identity schema (service_key / username_key)
    # ------------------------------------------------------------------

    @staticmethod
    def _create_identity_indexes(cursor: sqlite3.Cursor, *, include_unique: bool = True) -> None:
        """Create the canonical-identity indexes (idempotent)."""
        if include_unique:
            cursor.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_identity"
                " ON credentials (service_key, username_key)"
            )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_credentials_order"
            " ON credentials (service_key, username_key, id)"
        )

    @staticmethod
    def _identity_columns_present(cursor: sqlite3.Cursor) -> bool:
        cursor.execute("PRAGMA table_info(credentials)")
        columns = {row["name"] for row in cursor.fetchall()}
        return {"service_key", "username_key"}.issubset(columns)

    @staticmethod
    def _identity_unique_index_present(cursor: sqlite3.Cursor) -> bool:
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name=?",
            (_IDX_IDENTITY_UNIQUE,),
        )
        return cursor.fetchone() is not None

    def _detect_identity_conflicts(
        self, cursor: sqlite3.Cursor
    ) -> List[Dict[str, Any]]:
        """Group rows by canonical identity and return colliding groups.

        Each returned dict has ``service``/``username`` (from the first row
        of the group) and ``ids`` (all row ids sharing that canonical
        identity), sorted by id for deterministic reporting.
        """
        cursor.execute("SELECT id, service, username FROM credentials ORDER BY id")
        groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for row in cursor.fetchall():
            service = row["service"]
            username = row["username"]
            if not isinstance(service, str) or not isinstance(username, str):
                raise StorageError(
                    "Vault contains a credential with non-text service/username "
                    f"(id={row['id']}); cannot migrate identity schema."
                )
            service_key, username_key = canonical_service_username(service, username)
            if not service_key or not username_key:
                raise StorageError(
                    "Vault contains a credential with an empty canonical identity "
                    f"(id={row['id']}, service={service!r}, username={username!r}). "
                    "Rename or delete it, then retry."
                )
            key = (service_key, username_key)
            entry = groups.setdefault(
                key,
                {"service": service, "username": username, "ids": []},
            )
            ids_list: List[int] = entry["ids"]
            ids_list.append(row["id"])
        return [entry for entry in groups.values() if len(entry["ids"]) > 1]

    def _ensure_identity_schema(self) -> None:
        """Ensure canonical identity columns and indexes exist.

        Called automatically at the end of every successful unlock.  New
        vaults are created with the identity schema, so this is a no-op for
        them.  For pre-identity vaults it runs a migration-safe upgrade:
        private on-disk backup, single exclusive transaction, canonical
        backfill, then index creation.

        Canonical duplicates in existing data are handled non-destructively:
        the backfill commits but the unique index is deferred, and
        ``self.identity_conflict`` describes the colliding rows so the UI can
        guide the user to rename/delete them.  The migration retries on the
        next unlock.

        Raises:
            StorageError: for malformed data or migration I/O failures.  The
                database is rolled back and the backup preserved.
        """
        self.identity_conflict = None
        conn = self._get_conn()
        # Ensure url column exists before any other schema work.
        _ensure_url_column(conn)
        self._invalidate_url_column_cache()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='credentials'"
        )
        if cursor.fetchone() is None:
            return
        if not self._identity_columns_present(cursor):
            self._run_identity_migration()
        elif not self._identity_unique_index_present(cursor):
            # Columns exist but a previous migration deferred the unique index
            # due to canonical conflicts — retry now that they may be resolved.
            self._retry_identity_unique_index()
        # Last: rewrite zero-width-bearing keys (and re-encrypt to AAD v4
        # when the vault is at AAD v3) so stored identities match the
        # stripped canonicalization used by new writes and lookups.
        self._migrate_zero_width_identity()

    def _retry_identity_unique_index(self) -> None:
        """Create the deferred unique identity index once conflicts are gone."""
        conn = self._get_conn()
        cursor = conn.cursor()
        conflicts = self._detect_identity_conflicts(cursor)
        if conflicts:
            self._set_identity_conflict(conflicts)
            return
        try:
            conn.execute("BEGIN EXCLUSIVE")
            self._create_identity_indexes(cursor)
            cursor.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES ('identity_schema_version', ?)",
                (str(_IDENTITY_SCHEMA_VERSION),),
            )
            conn.commit()
            _log.info("identity unique index created after conflict resolution")
        except BaseException:
            try:
                conn.rollback()
            except Exception as rollback_exc:  # nosec B110 — best-effort cleanup
                _log.debug("rollback failed during identity index retry: %s", rollback_exc)
            raise

    def _set_identity_conflict(self, conflicts: List[Dict[str, Any]]) -> None:
        summary_items: List[str] = []
        for c in conflicts:
            c_ids: List[int] = c.get("ids", [])
            ids_str = ", ".join(str(i) for i in c_ids)
            summary_items.append(f"{c['service']} / {c['username']} (ids: {ids_str})")
        summary = "; ".join(summary_items)
        self.identity_conflict = CredentialIdentityConflictError(
            "Some stored credentials are duplicates under the canonical "
            "identity rules (same service/username ignoring case, surrounding "
            "whitespace, and equivalent Unicode). Nothing was changed or "
            "deleted. Rename or delete the duplicates in the vault explorer, "
            "then unlock again to finish the upgrade. Conflicts: " + summary,
            conflicts=conflicts,
        )
        _log.warning("identity schema migration deferred: %s", summary)

    def _run_identity_migration(self) -> None:
        """Backfill canonical identity columns for a pre-identity vault.

        Creates a private backup first, then runs in a single exclusive
        transaction: add nullable columns, backfill canonical keys, create
        indexes, and commit the schema marker last.  On canonical conflicts
        the backfill still commits (data is only enriched, never dropped or
        merged) but the unique index is deferred — see
        ``_ensure_identity_schema``.
        """
        # Back up before rewriting any existing data.
        backup_path = self._create_secure_backup(".identity.bak")
        _log.info("identity migration backup created at %s", backup_path)

        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            conn.execute("BEGIN EXCLUSIVE")

            # 1. Add nullable canonical columns.
            if not self._identity_columns_present(cursor):
                cursor.execute("ALTER TABLE credentials ADD COLUMN service_key TEXT")
                cursor.execute("ALTER TABLE credentials ADD COLUMN username_key TEXT")

            # 2. Backfill canonical keys (read with one cursor, write with a
            #    separate cursor to avoid disturbing the active result set).
            conflicts = self._detect_identity_conflicts(cursor)
            read_cursor = conn.cursor()
            write_cursor = conn.cursor()
            read_cursor.execute("SELECT id, service, username FROM credentials ORDER BY id")
            for row in read_cursor:
                service_key, username_key = canonical_service_username(
                    row["service"], row["username"]
                )
                write_cursor.execute(
                    "UPDATE credentials SET service_key = ?, username_key = ? WHERE id = ?",
                    (service_key, username_key, row["id"]),
                )

            # 3. Ordering index is always safe; the unique index is created
            #    only when no canonical conflicts exist.
            self._create_identity_indexes(cursor, include_unique=not conflicts)

            # 4. Commit the schema marker last (only on full completion).
            if not conflicts:
                cursor.execute(
                    "INSERT OR REPLACE INTO config (key, value) VALUES ('identity_schema_version', ?)",
                    (str(_IDENTITY_SCHEMA_VERSION),),
                )
            conn.commit()

            if conflicts:
                self._set_identity_conflict(conflicts)
            _log.info("identity schema migration complete (backup at %s)", backup_path)
        except BaseException:
            try:
                conn.rollback()
            except Exception as rollback_exc:  # nosec B110 — best-effort cleanup
                _log.debug("rollback failed during identity migration: %s", rollback_exc)
            _log.error(
                "identity schema migration failed; vault unchanged (backup at %s)",
                backup_path,
            )
            raise

    def _reencrypt_all_credentials_to_v4(self) -> None:
        """Re-encrypt every credential field from the current AAD to AAD v4.

        Must be invoked inside an open exclusive transaction on an unlocked
        v2 vault, with ``self._aad_version`` still set to the *source*
        version (the value used to decrypt each row's existing ciphertext).
        Reads credentials with a streaming cursor and writes the
        re-encrypted blobs with a separate cursor. Shared by
        :meth:`migrate_aad_to_v4` and :meth:`_migrate_zero_width_identity`
        so the re-encryption loop (decrypt -> validate -> AAD v4) has a
        single authoritative implementation.

        Raises:
            StorageError: if the vault is not fully unlocked, a row cannot
                be decrypted under the source AAD version, or a field
                violates its size limit.  The caller rolls back.
        """
        if self._dek is None or self._vault_uuid is None:
            raise StorageError("Vault is not fully unlocked.")
        dek = self._dek
        vault_uuid = self._vault_uuid
        conn = self._get_conn()
        read_cursor = conn.cursor()
        write_cursor = conn.cursor()
        read_cursor.execute(
            "SELECT id, credential_uuid, service, username,"
            " encrypted_password, encrypted_note FROM credentials"
        )
        for row in read_cursor:
            cred_uuid: bytes = row["credential_uuid"]
            svc: str = row["service"]
            usr: str = row["username"]
            try:
                password, note = self._decrypt_fields_v2(row)
            except Exception as exc:
                raise StorageError(
                    "Failed to decrypt credential id="
                    f"{row['id']} during AAD migration: {exc}"
                ) from exc
            _validate_field_size(password, note)
            new_password_ct = _crypto_v2.encrypt_field(
                dek,
                _crypto_v2.make_associated_data_v4(
                    vault_uuid, cred_uuid, "password", svc, usr,
                ),
                password,
                aead_algorithm=self._aead_algorithm,
                max_plaintext_bytes=MAX_PASSWORD_BYTES,
                field_name="password",
            )
            new_note_ct: bytes | None = None
            if note:
                new_note_ct = _crypto_v2.encrypt_field(
                    dek,
                    _crypto_v2.make_associated_data_v4(
                        vault_uuid, cred_uuid, "note", svc, usr,
                    ),
                    note,
                    aead_algorithm=self._aead_algorithm,
                    max_plaintext_bytes=MAX_NOTE_BYTES,
                    field_name="note",
                )
            write_cursor.execute(
                "UPDATE credentials SET encrypted_password = ?,"
                " encrypted_note = ? WHERE id = ?",
                (new_password_ct, new_note_ct, row["id"]),
            )

    def _migrate_zero_width_identity(self) -> None:
        """Rewrite zero-width-bearing identity keys and re-encrypt to AAD v4.

        Vaults created before zero-width canonicalization stored identity
        keys that preserve format characters (U+200B..U+200F, U+FEFF)
        because the frozen :func:`identity.canonical_identity` kept them.
        New writes store stripped keys, so those rows must be migrated.

        The AAD-version migration is a **separate decision from identity-key
        rewriting**.  A v2 vault at AAD v3 is re-encrypted to AAD v4
        (stripped canonicalization) on every unlock, even when no key needs
        rewriting (for example a previous/partial migration or a vault that
        stored stripped keys while still encrypting with AAD v3).  This
        guarantees every supported v2 vault reaches the current format and
        none is silently stranded at AAD v3.

        So the migration independently:
        * re-encrypts every credential field with AAD v4 when the vault is
          a v2 vault at AAD v3, and
        * rewrites stored ``service_key``/``username_key`` columns to the
          stripped canonical form when they differ.

        Follows the ``migrate_aad_to_v4`` pattern: a private backup
        (``vault.db.identity_zw.bak``) is created first, the rewrite and
        re-encryption run in a single exclusive transaction, and any
        failure rolls back leaving the vault unchanged.

        If two rows collapse onto the same stripped identity, the unique
        index is deferred and ``self.identity_conflict`` describes the
        colliding rows (same semantics as the identity schema migration).
        """
        if self._vault_version not in (1, 2):
            return
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, service, username, service_key, username_key FROM credentials"
        )
        rows_to_rewrite: List[Tuple[int, str, str]] = []
        for row in cursor.fetchall():
            stripped_svc = canonical_identity_stripped(row["service"])
            stripped_usr = canonical_identity_stripped(row["username"])
            if (
                row["service_key"] != stripped_svc
                or row["username_key"] != stripped_usr
            ):
                rows_to_rewrite.append((row["id"], stripped_svc, stripped_usr))

        # AAD-version migration is keyed off the format version, NOT off
        # whether any key must be rewritten: every v2 vault still at AAD v3
        # is re-encrypted to AAD v4 so it can never be left stranded on the
        # intermediate format.
        needs_reencrypt = self._vault_version == 2 and self._aad_version == 3

        if not rows_to_rewrite and not needs_reencrypt:
            return

        backup_path = self._create_secure_backup(".identity_zw.bak")
        _log.info("zero-width identity backup created at %s", backup_path)

        previous_aad = self._aad_version
        try:
            conn.execute("BEGIN EXCLUSIVE")

            if needs_reencrypt:
                self._reencrypt_all_credentials_to_v4()
                cursor.execute(
                    "INSERT OR REPLACE INTO config (key, value) VALUES ('aad_version', '4')"
                )
                self._aad_version = 4

            # Rewrite stored keys to stripped form.  Drop the unique index
            # first so two rows collapsing onto one stripped identity
            # cannot fail mid-transaction; recreate it only when no
            # conflicts remain (deferred otherwise, mirroring the identity
            # schema migration).
            if rows_to_rewrite:
                had_unique_index = self._identity_unique_index_present(cursor)
                if had_unique_index:
                    cursor.execute(f"DROP INDEX IF EXISTS {_IDX_IDENTITY_UNIQUE}")
                write_cursor = conn.cursor()
                for row_id, stripped_svc, stripped_usr in rows_to_rewrite:
                    write_cursor.execute(
                        "UPDATE credentials SET service_key = ?, username_key = ?"
                        " WHERE id = ?",
                        (stripped_svc, stripped_usr, row_id),
                    )
                if had_unique_index:
                    conflicts = self._detect_identity_conflicts(cursor)
                    self._create_identity_indexes(cursor, include_unique=not conflicts)
                    if conflicts:
                        self._set_identity_conflict(conflicts)
                    else:
                        cursor.execute(
                            "INSERT OR REPLACE INTO config (key, value) VALUES"
                            " ('identity_schema_version', ?)",
                            (str(_IDENTITY_SCHEMA_VERSION),),
                        )

            conn.commit()
            _log.info(
                "zero-width identity migration complete (backup at %s)",
                backup_path,
            )
        except BaseException:
            self._aad_version = previous_aad
            try:
                conn.rollback()
            except Exception as rollback_exc:  # nosec B110 — best-effort cleanup
                _log.debug("rollback failed during zero-width migration: %s", rollback_exc)
            _log.exception("zero-width identity migration failed; vault unchanged")
            raise

    def initialize_vault_v2(self, master_password: str) -> None:
        """Create a new v2 vault with Argon2id KDF and KEK/DEK split.

        This is the v2 counterpart of ``initialize_vault``.  It creates the
        SQLite schema, derives the KEK, generates a random DEK, wraps the
        DEK with the KEK, and stores all config entries required for v2
        unlock.

        Raises:
            VaultAlreadyInitializedError: if a vault already exists.
            WeakMasterPasswordError: if *master_password* fails the policy.
        """
        if self.vault_exists():
            raise VaultAlreadyInitializedError("Vault already initialized.")
        _validate_field_size(master_password, "")
        _validate_master_password(master_password)

        vault_uuid = uuid.uuid4().bytes
        salt = os.urandom(_crypto_v2.SALT_LEN)
        kek = _crypto_v2.derive_kek(master_password, salt)
        dek = _crypto_v2.generate_dek()
        wrapped_dek = _crypto_v2.wrap_dek(kek, dek)

        aead_algorithm = _crypto_v2.AEAD_AES_256_GCM
        verification_ct = _crypto_v2.create_verification_token(
            dek, vault_uuid, aead_algorithm=aead_algorithm,
        )

        conn = self._get_conn()
        cursor = conn.cursor()

        # Create tables (v2 schema has credential_uuid column).
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value BLOB
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                credential_uuid BLOB NOT NULL,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                encrypted_note BLOB,
                note_is_hidden INTEGER DEFAULT 0,
                service_key TEXT,
                username_key TEXT,
                url TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        if not _has_url_column(cursor):
            try:
                cursor.execute("ALTER TABLE credentials ADD COLUMN url TEXT DEFAULT ''")
            except sqlite3.OperationalError:
                pass
        self._create_identity_indexes(cursor)

        # Write v2 config.
        config_entries: list[tuple[str, object]] = [
            ("version", "2"),
            ("vault_uuid", vault_uuid),
            ("kdf_algorithm", "argon2id"),
            ("kdf_memory_cost", str(_crypto_v2.DEFAULT_ARGON2_MEMORY)),
            ("kdf_time_cost", str(_crypto_v2.DEFAULT_ARGON2_TIME)),
            ("kdf_parallelism", str(_crypto_v2.DEFAULT_ARGON2_PARALLELISM)),
            ("kdf_salt", salt),
            ("wrapped_dek", wrapped_dek),
            ("aead_algorithm", aead_algorithm),
            ("aad_version", "4"),
            ("verification", verification_ct),
            ("dek_generation", "1"),
            ("identity_schema_version", str(_IDENTITY_SCHEMA_VERSION)),
        ]
        for key, value in config_entries:
            cursor.execute(
                "INSERT INTO config (key, value) VALUES (?, ?)", (key, value)
            )

        conn.commit()
        self._ensure_private_permissions(self.db_path, 0o600)

        self._fernet = None
        self._vault_version = 2
        self._dek = dek
        self._vault_uuid = vault_uuid
        self._aead_algorithm = aead_algorithm
        self._aad_version = 4
        _log.info("vault v2 initialized at %s", self.db_path)

    def _unlock_vault_v2(self, master_password: str) -> None:
        """Unlock a v2 vault by deriving the KEK and unwrapping the DEK.

        Reads KDF parameters and wrapped DEK from the config table, derives
        the KEK from *master_password*, unwraps the DEK, and verifies the
        verification token.

        Raises:
            InvalidPasswordError: if *master_password* is wrong.
            StorageError: if the vault config is missing required keys
                or the wrapped DEK fails to unwrap.
        """
        if self._vault_version != 2:
            raise StorageError("Vault is not v2; use unlock_vault() instead.")

        conn = self._get_conn()
        cursor = conn.cursor()

        # Read required v2 config (salt/wrapped_dek/uuid/verification).
        try:
            cursor.execute("SELECT value FROM config WHERE key = 'kdf_salt'")
            kdf_salt = cursor.fetchone()["value"]
            cursor.execute("SELECT value FROM config WHERE key = 'wrapped_dek'")
            wrapped_dek = cursor.fetchone()["value"]
            cursor.execute("SELECT value FROM config WHERE key = 'vault_uuid'")
            vault_uuid = cursor.fetchone()["value"]
            cursor.execute("SELECT value FROM config WHERE key = 'verification'")
            verification_ct = cursor.fetchone()["value"]
        except (TypeError, KeyError) as exc:
            raise StorageError("Vault v2 configuration corrupted or missing keys.") from exc

        # KDF + AEAD via single authoritative helpers (deduped)
        kdf_algorithm, memory, time, parallelism = self._load_kdf_params(cursor)
        aead_algorithm = self._load_aead_algorithm(cursor)

        # Validate KDF config before running expensive Argon2id.
        try:
            _crypto_v2._validate_kdf_config(
                kdf_algorithm, memory, time, parallelism, kdf_salt,
            )
        except ValueError as exc:
            raise StorageError(f"Invalid KDF configuration: {exc}") from exc

        # Downgrade detection — any non-default KDF params may indicate
        # tampering.  This is a *detection* control (log only); the *prevention*
        # control is _validate_kdf_config() above which rejects anything below
        # the OWASP 2023 low minima (19 MiB / 2 iter / 1 lane) before Argon2id
        # runs.  Values between minima and defaults (e.g. 19 MiB) still unlock
        # but emit this warning so the user/health check can investigate.
        if (
            memory != _crypto_v2.DEFAULT_ARGON2_MEMORY
            or time != _crypto_v2.DEFAULT_ARGON2_TIME
            or parallelism != _crypto_v2.DEFAULT_ARGON2_PARALLELISM
        ):
            _log.warning(
                "vault KDF params differ from defaults (memory=%d time=%d parallelism=%d) — "
                "possible downgrade/tampering if not intentionally changed",
                memory, time, parallelism,
            )

        # Validate vault metadata before crypto operations.
        try:
            _crypto_v2._validate_vault_metadata(
                vault_uuid, wrapped_dek, aead_algorithm, verification_ct,
            )
        except ValueError as exc:
            raise StorageError(f"Invalid vault metadata: {exc}") from exc

        # Read AAD version (default 1 for legacy v2 vaults).
        aad_version_raw = self._read_optional_int_config(cursor, "aad_version")
        aad_version = aad_version_raw if aad_version_raw is not None else 1
        if aad_version not in (1, 2, 3, 4):
            raise StorageError(f"Unsupported aad_version: {aad_version}")

        # Derive KEK.
        kek = _crypto_v2.derive_kek(
            master_password, kdf_salt,
            memory=memory, time=time, parallelism=parallelism,
        )

        # Unwrap DEK.
        try:
            dek = _crypto_v2.unwrap_dek(kek, wrapped_dek)
        except _crypto_v2.InvalidUnwrap:
            raise InvalidPasswordError("Invalid master password.")

        # Verify the token.
        if not _crypto_v2.verify_token(
            dek, vault_uuid, verification_ct, aead_algorithm=aead_algorithm
        ):
            raise InvalidPasswordError("Invalid master password.")

        self._fernet = None
        self._vault_version = 2
        self._dek = dek
        self._vault_uuid = vault_uuid
        self._aead_algorithm = aead_algorithm
        self._aad_version = aad_version
        self._ensure_identity_schema()
        _log.info("vault v2 unlocked")

    def migrate_v1_to_v2(self, master_password: str) -> None:
        """Migrate an existing v1 vault to v2 format.

        The vault must be unlocked as v1 before calling this method.
        Migration is wrapped in a single SQLite transaction so a crash or
        interrupt leaves the v1 vault intact.

        A backup file ``vault.db.v1.bak`` is created before migration
        begins as an additional safety net.

        Raises:
            StorageError: if the vault is not v1, not unlocked, or
                migration fails.
        """
        if self._vault_version != 1:
            raise StorageError("Migration requires an unlocked v1 vault.")

        _validate_master_password(master_password)

        # Verify the password authenticates against the existing v1 vault
        # before any migration work begins.  This prevents a caller from
        # silently re-keying the vault with a different password.
        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT value FROM config WHERE key=?", ("salt",))
            v1_salt = cursor.fetchone()["value"]
            cursor.execute("SELECT value FROM config WHERE key=?", ("verification",))
            v1_verification_token = cursor.fetchone()["value"]
        except (TypeError, sqlite3.Error) as exc:
            raise StorageError(
                f"Cannot verify password: v1 vault config corrupted. {exc}"
            ) from exc

        stored_iters_raw = self._read_optional_int_config(cursor, "pbkdf2_iterations")
        if stored_iters_raw is None:
            v1_iters = _LEGACY_PBKDF2_ITERATIONS
        else:
            v1_iters = stored_iters_raw

        v1_key = self._derive_key(master_password, v1_salt, v1_iters)
        v1_fernet = Fernet(v1_key)
        try:
            decrypted_verification = v1_fernet.decrypt(v1_verification_token)
            if decrypted_verification != b"VERIFICATION_TOKEN":
                raise InvalidPasswordError("Password does not match existing v1 vault.")
        except InvalidToken as exc:
            raise InvalidPasswordError(
                "Password does not match existing v1 vault."
            ) from exc

        # 1. Create a secure private backup before rewriting.
        backup_path = self._create_secure_backup(".v1.bak")
        _log.info("v1 backup created at %s", backup_path)

        try:
            # 2. Begin exclusive transaction.
            conn.execute("BEGIN EXCLUSIVE")

            # 3. Generate v2 key material.
            vault_uuid = uuid.uuid4().bytes
            salt = os.urandom(_crypto_v2.SALT_LEN)
            kek = _crypto_v2.derive_kek(master_password, salt)
            dek = _crypto_v2.generate_dek()
            wrapped_dek = _crypto_v2.wrap_dek(kek, dek)
            aead_algorithm = _crypto_v2.AEAD_AES_256_GCM

            # 4. Add credential_uuid column and backfill.
            #    Check if column exists (it might from a partially migrated vault).
            cursor.execute("PRAGMA table_info(credentials)")
            columns = {row["name"] for row in cursor.fetchall()}
            if "credential_uuid" not in columns:
                cursor.execute(
                    "ALTER TABLE credentials ADD COLUMN credential_uuid BLOB"
                )

            # Backfill credential_uuid for existing rows using a separate write
            # cursor so the read iterator stays streaming.
            read_cursor = conn.cursor()
            write_cursor = conn.cursor()
            read_cursor.execute(
                "SELECT id FROM credentials WHERE credential_uuid IS NULL"
            )
            for row in read_cursor:
                new_uuid = uuid.uuid4().bytes
                write_cursor.execute(
                    "UPDATE credentials SET credential_uuid = ? WHERE id = ?",
                    (new_uuid, row["id"]),
                )

            # 5. Re-encrypt all credentials with v2 AEAD (streaming read cursor).
            if self._fernet is None:
                raise StorageError("v1 Fernet is not available; vault may not be unlocked as v1.")
            fernet = self._fernet
            read_cursor.execute(
                "SELECT id, credential_uuid, service, username, encrypted_password, encrypted_note"
                " FROM credentials"
            )
            for row in read_cursor:
                cred_uuid: bytes = row["credential_uuid"]

                # Decrypt v1 ciphertext.
                try:
                    v1_password = fernet.decrypt(row["encrypted_password"]).decode()
                except Exception:
                    raise StorageError(
                        f"Failed to decrypt v1 password for credential id={row['id']}"
                    )

                v1_note_bytes = row["encrypted_note"]
                v1_note = ""
                if v1_note_bytes:
                    try:
                        v1_note = fernet.decrypt(v1_note_bytes).decode()
                    except Exception:
                        raise StorageError(
                            f"Failed to decrypt v1 note for credential id={row['id']}"
                        )
                _validate_field_size(v1_password, v1_note)

                # Re-encrypt with v2 AEAD (AAD v4 — metadata-bound & length-delimited).
                svc: str = row["service"]
                usr: str = row["username"]
                new_password_ct = _crypto_v2.encrypt_field(
                    dek,
                    _crypto_v2.make_associated_data_v4(
                        vault_uuid, cred_uuid, "password", svc, usr,
                    ),
                    v1_password,
                    aead_algorithm=aead_algorithm,
                    max_plaintext_bytes=MAX_PASSWORD_BYTES,
                    field_name="password",
                )
                new_note_ct: bytes | None = None
                if v1_note:
                    new_note_ct = _crypto_v2.encrypt_field(
                        dek,
                        _crypto_v2.make_associated_data_v4(
                            vault_uuid, cred_uuid, "note", svc, usr,
                        ),
                        v1_note,
                        aead_algorithm=aead_algorithm,
                        max_plaintext_bytes=MAX_NOTE_BYTES,
                        field_name="note",
                    )

                write_cursor.execute(
                    "UPDATE credentials SET encrypted_password = ?, encrypted_note = ? WHERE id = ?",
                    (new_password_ct, new_note_ct, row["id"]),
                )

            # 6. Create v2 verification token.
            verification_ct = _crypto_v2.create_verification_token(
                dek, vault_uuid, aead_algorithm=aead_algorithm,
            )

            # 7. Write v2 config (new v2 vaults use AAD v4).
            v2_config: list[tuple[str, object]] = [
                ("version", "2"),
                ("vault_uuid", vault_uuid),
                ("kdf_algorithm", "argon2id"),
                ("kdf_memory_cost", str(_crypto_v2.DEFAULT_ARGON2_MEMORY)),
                ("kdf_time_cost", str(_crypto_v2.DEFAULT_ARGON2_TIME)),
                ("kdf_parallelism", str(_crypto_v2.DEFAULT_ARGON2_PARALLELISM)),
                ("kdf_salt", salt),
                ("wrapped_dek", wrapped_dek),
                ("aead_algorithm", aead_algorithm),
                ("aad_version", "4"),
                ("verification", verification_ct),
                ("dek_generation", "1"),
            ]
            for key, value in v2_config:
                cursor.execute(
                    "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
                    (key, value),
                )

            # 8. Remove v1 config keys.
            cursor.execute(
                "DELETE FROM config WHERE key IN ('salt', 'pbkdf2_iterations', 'salt_length')"
            )

            # 9. Commit.
            conn.commit()

            # 10. Transition to v2 state.
            self._fernet = None
            self._vault_version = 2
            self._dek = dek
            self._vault_uuid = vault_uuid
            self._aead_algorithm = aead_algorithm
            self._aad_version = 4
            _log.info("vault migrated from v1 to v2 (AAD v4)")

        except BaseException:
            # Rollback the transaction on any failure.
            try:
                conn.rollback()
            except Exception as rollback_exc:  # nosec B110 — best-effort cleanup
                _log.debug("rollback failed during v1→v2 migration: %s", rollback_exc)
            # The backup file remains as a safety net.
            _log.exception("v1→v2 migration failed; v1 vault is intact")
            raise

    def migrate_aad_v1_to_v2(self) -> None:
        """Alias for :meth:`migrate_aad_to_v4` (kept for backwards compatibility)."""
        self.migrate_aad_to_v4()

    def migrate_aad_to_v3(self) -> None:
        """Backward-compatible alias for :meth:`migrate_aad_to_v4`.

        The target AAD format for all supported migrations is now **v4**
        (explicit length-prefixed associated data with zero-width-stripped
        canonical identities).  The old ``v3`` name is retained so existing
        callers and tests keep working.
        """
        self.migrate_aad_to_v4()

    def migrate_aad_to_v4(self) -> None:
        """Migrate a v2 vault at AAD v1, v2, or v3 to the current AAD (v4).

        Re-encrypts all credential fields using AAD v4 which uses explicit
        length prefixes for every variable-length associated data field
        and zero-width-stripped canonical identities.
        The migration is wrapped in a single SQLite transaction; on failure
        the vault remains in its original AAD state.

        A backup file ``vault.db.aad_v<N>.bak`` is created before migration.

        Raises:
            StorageError: if the vault is not v2, not unlocked, or already
                at the current AAD version.
        """
        if self._vault_version != 2:
            raise StorageError("AAD migration requires an unlocked v2 vault.")
        if self._aad_version >= 4:
            raise StorageError("Vault is already at the current AAD version.")
        if self._dek is None or self._vault_uuid is None:
            raise StorageError("Vault is not fully unlocked.")

        current_aad = self._aad_version
        backup_suffix = f".aad_v{current_aad}.bak"
        backup_path = self._create_secure_backup(backup_suffix)
        _log.info("AAD backup created at %s", backup_path)

        conn = self._get_conn()
        cursor = conn.cursor()

        try:
            conn.execute("BEGIN EXCLUSIVE")

            # Decrypt under the *source* AAD version, re-encrypt to v4.
            self._reencrypt_all_credentials_to_v4()

            # Update aad_version in config.
            cursor.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES ('aad_version', '4')"
            )

            conn.commit()

            self._aad_version = 4
            _log.info("vault AAD migrated from v%d to v4", current_aad)

        except BaseException:
            self._aad_version = current_aad
            try:
                conn.rollback()
            except Exception as rollback_exc:  # nosec B110 — best-effort cleanup
                _log.debug("rollback failed during AAD migration: %s", rollback_exc)
            _log.exception("AAD migration failed; v2 vault is intact")
            raise

    # ------------------------------------------------------------------
    # Master password change (DEK re-wrap) — P0 flat helpers
    # ------------------------------------------------------------------

    def _verify_current_password(self, current_password: str) -> None:
        """Raise InvalidPasswordError if *current_password* does not unlock vault."""
        if self._vault_version == 2:
            self._verify_current_password_v2(current_password)
        elif self._vault_version == 1:
            self._verify_current_password_v1(current_password)
        else:
            raise StorageError("Vault is not unlocked.")

    def _verify_current_password_v2(self, current_password: str) -> None:
        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT value FROM config WHERE key='kdf_salt'")
            kdf_salt = cursor.fetchone()["value"]
            cursor.execute("SELECT value FROM config WHERE key='wrapped_dek'")
            wrapped_dek = cursor.fetchone()["value"]
            cursor.execute("SELECT value FROM config WHERE key='vault_uuid'")
            vault_uuid = cursor.fetchone()["value"]
            cursor.execute("SELECT value FROM config WHERE key='verification'")
            verification_ct = cursor.fetchone()["value"]
        except (TypeError, KeyError) as exc:
            raise StorageError("Vault v2 configuration corrupted.") from exc
        kdf_algorithm, memory, time_cost, paral = self._load_kdf_params(cursor)
        aead_algorithm = self._load_aead_algorithm(cursor)
        kek = _crypto_v2.derive_kek(current_password, kdf_salt, memory=memory, time=time_cost, parallelism=paral)
        try:
            dek = _crypto_v2.unwrap_dek(kek, wrapped_dek)
        except _crypto_v2.InvalidUnwrap as exc:
            raise InvalidPasswordError("Current master password is incorrect.") from exc
        if not _crypto_v2.verify_token(dek, vault_uuid, verification_ct, aead_algorithm=aead_algorithm):
            raise InvalidPasswordError("Current master password is incorrect.")

    def _verify_current_password_v1(self, current_password: str) -> None:
        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT value FROM config WHERE key='salt'")
            salt = cursor.fetchone()["value"]
            cursor.execute("SELECT value FROM config WHERE key='verification'")
            verification_token = cursor.fetchone()["value"]
        except TypeError as exc:
            raise StorageError("Vault configuration corrupted.") from exc
        stored_iters = self._read_optional_int_config(cursor, "pbkdf2_iterations")
        stored_iters = stored_iters if stored_iters is not None else _LEGACY_PBKDF2_ITERATIONS
        key = self._derive_key(current_password, salt, stored_iters)
        fernet = Fernet(key)
        try:
            decrypted = fernet.decrypt(verification_token)
            if decrypted != b"VERIFICATION_TOKEN":
                raise InvalidPasswordError("Current master password is incorrect.")
        except InvalidToken as exc:
            raise InvalidPasswordError("Current master password is incorrect.") from exc

    def change_master_password(self, current_password: str, new_password: str) -> None:
        """Change master password without re-encrypting credentials.

        Validates *new_password* against the strength policy, verifies
        *current_password* against the existing vault, then atomically
        re-wraps the DEK (v2) or re-encrypts the verification token (v1).

        Requires an unlocked vault.
        """
        if self._vault_version is None:
            raise StorageError("Vault is locked.")
        _validate_field_size(new_password, "")
        _validate_master_password(new_password)
        self._verify_current_password(current_password)
        if self._vault_version == 2:
            self._change_master_password_v2(new_password)
        else:
            self._change_master_password_v1(new_password)

    def _change_master_password_v2(self, new_password: str) -> None:
        if self._dek is None or self._vault_uuid is None:
            raise StorageError("Vault DEK is not available.")
        dek = self._dek
        conn = self._get_conn()
        cursor = conn.cursor()
        aead_algorithm = self._load_aead_algorithm(cursor)
        new_salt = os.urandom(_crypto_v2.SALT_LEN)
        new_kek = _crypto_v2.derive_kek(new_password, new_salt)
        new_wrapped_dek = _crypto_v2.wrap_dek(new_kek, dek)
        try:
            conn.execute("BEGIN EXCLUSIVE")
            cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('kdf_salt', ?)", (new_salt,))
            cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('wrapped_dek', ?)", (new_wrapped_dek,))
            cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('kdf_algorithm', 'argon2id')")
            cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('kdf_memory_cost', ?)", (str(_crypto_v2.DEFAULT_ARGON2_MEMORY),))
            cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('kdf_time_cost', ?)", (str(_crypto_v2.DEFAULT_ARGON2_TIME),))
            cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('kdf_parallelism', ?)", (str(_crypto_v2.DEFAULT_ARGON2_PARALLELISM),))
            cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('aead_algorithm', ?)", (aead_algorithm,))
            conn.commit()
            _log.info("master password changed (v2 re-wrap)")
        except BaseException:
            try:
                conn.rollback()
            except Exception as rollback_exc:  # nosec B110 — best-effort cleanup
                _log.debug("rollback failed during password change: %s", rollback_exc)
            raise

    def rotate_dek(self, current_password: str) -> None:
        """Rotate DEK: generate new DEK, re-encrypt all credentials atomically.

        Requires an unlocked v2 vault and the current master password to
        re-wrap the new DEK.  Increments ``dek_generation`` and refreshes
        the verification token.  Credentials keep their UUIDs and metadata.
        """
        if self._vault_version != 2:
            raise StorageError("DEK rotation requires an unlocked v2 vault.")
        if self._dek is None or self._vault_uuid is None:
            raise StorageError("Vault DEK is not available.")
        self._verify_current_password_v2(current_password)
        self._execute_dek_rotation(current_password)

    def _read_dek_generation(self, cursor: sqlite3.Cursor) -> int:
        raw = self._read_optional_int_config(cursor, "dek_generation")
        return raw if raw is not None else 1

    def _execute_dek_rotation(self, current_password: str) -> None:
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM config WHERE key='kdf_salt'")
        kdf_salt = cursor.fetchone()["value"]
        _, memory, time_cost, paral = self._load_kdf_params(cursor)
        aead_algorithm = self._load_aead_algorithm(cursor)
        vault_uuid: bytes = self._vault_uuid  # type: ignore[assignment]
        old_dek: bytes = self._dek  # type: ignore[assignment]
        dek_generation = self._read_dek_generation(cursor)
        kek = _crypto_v2.derive_kek(current_password, kdf_salt, memory=memory, time=time_cost, parallelism=paral)
        new_dek = _crypto_v2.generate_dek()
        new_wrapped_dek = _crypto_v2.wrap_dek(kek, new_dek)
        new_verification = _crypto_v2.create_verification_token(new_dek, vault_uuid, aead_algorithm=aead_algorithm)
        backup_path = self._create_secure_backup(".dek.bak")
        _log.info("DEK rotation backup at %s", backup_path)
        try:
            conn.execute("BEGIN EXCLUSIVE")
            read_cursor = conn.cursor()
            write_cursor = conn.cursor()
            read_cursor.execute("SELECT id, credential_uuid, service, username, encrypted_password, encrypted_note FROM credentials")
            for row in read_cursor:
                cred_uuid: bytes = row["credential_uuid"]
                svc: str = row["service"]
                usr: str = row["username"]
                password_ad = self._make_credential_aad(cred_uuid, "password", svc, usr)
                note_ad = self._make_credential_aad(cred_uuid, "note", svc, usr)
                try:
                    password = _crypto_v2.decrypt_field(old_dek, password_ad, row["encrypted_password"], aead_algorithm=aead_algorithm)
                except Exception as exc:
                    raise StorageError(f"Failed to decrypt credential id={row['id']} during DEK rotation: {exc}") from exc
                note = ""
                if row["encrypted_note"]:
                    try:
                        note = _crypto_v2.decrypt_field(old_dek, note_ad, row["encrypted_note"], aead_algorithm=aead_algorithm)
                    except Exception as exc:
                        raise StorageError(f"Failed to decrypt note id={row['id']} during DEK rotation: {exc}") from exc
                _validate_field_size(password, note)
                new_password_ct = _crypto_v2.encrypt_field(new_dek, password_ad, password, aead_algorithm=aead_algorithm, max_plaintext_bytes=MAX_PASSWORD_BYTES, field_name="password")
                new_note_ct: bytes | None = None
                if note:
                    new_note_ct = _crypto_v2.encrypt_field(new_dek, note_ad, note, aead_algorithm=aead_algorithm, max_plaintext_bytes=MAX_NOTE_BYTES, field_name="note")
                write_cursor.execute("UPDATE credentials SET encrypted_password=?, encrypted_note=? WHERE id=?", (new_password_ct, new_note_ct, row["id"]))
            cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('wrapped_dek', ?)", (new_wrapped_dek,))
            cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('verification', ?)", (new_verification,))
            cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('dek_generation', ?)", (str(dek_generation + 1),))
            conn.commit()
            self._dek = new_dek
            _log.info("DEK rotated: generation %d -> %d", dek_generation, dek_generation + 1)
        except BaseException:
            try:
                conn.rollback()
            except Exception as rollback_exc:  # nosec B110 — best-effort cleanup
                _log.debug("rollback failed during DEK rotation: %s", rollback_exc)
            _log.exception("DEK rotation failed; vault unchanged")
            raise

    def _change_master_password_v1(self, new_password: str) -> None:
        if self._fernet is None:
            raise StorageError("Vault is not unlocked.")
        old_fernet: Fernet = self._fernet
        new_salt = os.urandom(_DEFAULT_SALT_LENGTH)
        new_key = self._derive_key(new_password, new_salt, _DEFAULT_PBKDF2_ITERATIONS)
        new_fernet = Fernet(new_key)
        new_verification = new_fernet.encrypt(b"VERIFICATION_TOKEN")
        backup_path = self._create_secure_backup(".pwd.bak")
        _log.info("v1 password-change backup at %s", backup_path)
        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            conn.execute("BEGIN EXCLUSIVE")
            # Re-encrypt every credential field from old key to new key.
            read_cursor = conn.cursor()
            write_cursor = conn.cursor()
            read_cursor.execute("SELECT id, encrypted_password, encrypted_note FROM credentials")
            for row in read_cursor:
                try:
                    password = old_fernet.decrypt(row["encrypted_password"]).decode()
                except Exception as exc:
                    raise StorageError(f"Failed to decrypt v1 password id={row['id']}: {exc}") from exc
                note = ""
                if row["encrypted_note"]:
                    try:
                        note = old_fernet.decrypt(row["encrypted_note"]).decode()
                    except Exception as exc:
                        raise StorageError(f"Failed to decrypt v1 note id={row['id']}: {exc}") from exc
                _validate_field_size(password, note)
                new_password_ct = new_fernet.encrypt(password.encode())
                new_note_ct = new_fernet.encrypt(note.encode()) if note else None
                write_cursor.execute(
                    "UPDATE credentials SET encrypted_password=?, encrypted_note=? WHERE id=?",
                    (new_password_ct, new_note_ct, row["id"]),
                )
            cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('salt', ?)", (new_salt,))
            cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('verification', ?)", (new_verification,))
            cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('pbkdf2_iterations', ?)", (str(_DEFAULT_PBKDF2_ITERATIONS),))
            cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('salt_length', ?)", (str(_DEFAULT_SALT_LENGTH),))
            conn.commit()
            self._fernet = new_fernet
            _log.info("master password changed (v1 re-encrypt)")
        except BaseException:
            try:
                conn.rollback()
            except Exception as rollback_exc:  # nosec B110 — best-effort cleanup
                _log.debug("rollback failed during password change: %s", rollback_exc)
            raise

    def close(self):
        if self._db_connection:
            try:
                self._db_connection.close()
            except Exception:
                pass
            self._db_connection = None
        self._fernet = None
        self._vault_version = None
        self._dek = None
        self._vault_uuid = None
        self._invalidate_url_column_cache()
        _log.info("vault closed")

    def __enter__(self) -> "StorageManager":
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> Literal[False]:
        self.close()
        return False

    def _require_unlocked(self) -> Fernet:
        """Assert the vault is unlocked (v1 or v2) and return the v1 Fernet.

        For v2 vaults the returned Fernet is ``None`` and callers must use
        the per-version encrypt/decrypt helpers instead.

        Raises:
            StorageError: if the vault is locked (neither v1 nor v2 state
                is active).
        """
        if self._vault_version is None:
            raise StorageError("Vault is locked.")
        # mypy: Fernet may be None for v2 vaults; callers handle this.
        return self._fernet  # type: ignore[return-value]

    def _decrypt_credential_fields(
        self, row: sqlite3.Row, fernet: Fernet
    ) -> tuple[str, str]:
        """Decrypt password and note from a credential row.

        Dispatches to v1 or v2 decryption based on ``self._vault_version``.

        Raises:
            InvalidToken: if v1 ciphertext is corrupted or tampered with.
            ``cryptography.exceptions.InvalidTag``: if v2 AEAD
                authentication fails.
            UnicodeDecodeError: if decrypted bytes are not valid UTF-8.
        """
        if self._vault_version == 2:
            return self._decrypt_fields_v2(row)
        return self._decrypt_fields_v1(row, fernet)

    def _decrypt_fields_v1(
        self, row: sqlite3.Row, fernet: Fernet
    ) -> tuple[str, str]:
        """Decrypt using v1 Fernet."""
        password = fernet.decrypt(row["encrypted_password"]).decode()
        note = (
            fernet.decrypt(row["encrypted_note"]).decode()
            if row["encrypted_note"]
            else ""
        )
        return password, note

    def _decrypt_fields_v2(self, row: sqlite3.Row) -> tuple[str, str]:
        """Decrypt using v2 AEAD with associated data binding."""
        if self._dek is None:
            raise StorageError("Vault DEK is not available.")
        if self._vault_uuid is None:
            raise StorageError("Vault UUID is not available.")

        credential_uuid: bytes = row["credential_uuid"]
        service: str = row["service"]
        username: str = row["username"]

        password_ad = self._make_credential_aad(credential_uuid, "password", service, username)
        password = _crypto_v2.decrypt_field(
            self._dek, password_ad, row["encrypted_password"],
            aead_algorithm=self._aead_algorithm,
        )

        note = ""
        if row["encrypted_note"]:
            note_ad = self._make_credential_aad(credential_uuid, "note", service, username)
            note = _crypto_v2.decrypt_field(
                self._dek, note_ad, row["encrypted_note"],
                aead_algorithm=self._aead_algorithm,
            )

        return password, note

    def _encrypt_credential_fields(
        self, fernet: Fernet, password: str, note: str
    ) -> tuple[bytes, bytes | None]:
        """Encrypt password and note for storage.

        Dispatches to v1 or v2 encryption based on ``self._vault_version``.

        Returns (encrypted_password, encrypted_note).  ``encrypted_note`` is
        ``None`` when *note* is empty, matching the existing storage convention.
        """
        if self._vault_version == 2:
            # credential_uuid is assigned at save time; here we generate a
            # temporary one — the caller (save_credential) will overwrite the
            # result with the real credential_uuid.  For v2, the caller must
            # supply credential_uuid.
            raise StorageError(
                "v2 encryption requires credential_uuid; use _encrypt_fields_v2 directly"
            )
        return self._encrypt_fields_v1(fernet, password, note)

    def _encrypt_fields_v1(
        self, fernet: Fernet, password: str, note: str
    ) -> tuple[bytes, bytes | None]:
        """Encrypt using v1 Fernet."""
        encrypted_password = fernet.encrypt(password.encode())
        encrypted_note = fernet.encrypt(note.encode()) if note else None
        return encrypted_password, encrypted_note

    def _encrypt_fields_v2(
        self, password: str, note: str, credential_uuid: bytes,
        service: str, username: str,
    ) -> tuple[bytes, bytes | None]:
        """Encrypt using v2 AEAD with associated data binding to *credential_uuid*.

        Uses AAD v2 (metadata-bound) when ``self._aad_version >= 2``,
        otherwise falls back to legacy AAD v1.
        """
        if self._dek is None:
            raise StorageError("Vault DEK is not available.")
        if self._vault_uuid is None:
            raise StorageError("Vault UUID is not available.")

        password_ad = self._make_credential_aad(credential_uuid, "password", service, username)
        encrypted_password = _crypto_v2.encrypt_field(
            self._dek, password_ad, password,
            aead_algorithm=self._aead_algorithm,
            max_plaintext_bytes=MAX_PASSWORD_BYTES,
            field_name="password",
        )

        encrypted_note: bytes | None = None
        if note:
            note_ad = self._make_credential_aad(credential_uuid, "note", service, username)
            encrypted_note = _crypto_v2.encrypt_field(
                self._dek, note_ad, note,
                aead_algorithm=self._aead_algorithm,
                max_plaintext_bytes=MAX_NOTE_BYTES,
                field_name="note",
            )

        return encrypted_password, encrypted_note

    def _make_credential_aad(
        self, credential_uuid: bytes, field_name: str, service: str, username: str,
    ) -> bytes:
        """Build AEAD associated data for a credential field.

        Dispatches to AAD v4 (stripped canonicalization), AAD v3
        (frozen canonicalization), AAD v2 (legacy metadata-bound), or
        AAD v1 (legacy UUID-bound) based on ``_aad_version``.
        """
        if self._aad_version >= 4:
            return _crypto_v2.make_associated_data_v4(
                self._vault_uuid,  # type: ignore[arg-type]
                credential_uuid,
                field_name,
                service,
                username,
            )
        if self._aad_version == 3:
            return _crypto_v2.make_associated_data_v3(
                self._vault_uuid,  # type: ignore[arg-type]
                credential_uuid,
                field_name,
                service,
                username,
            )
        if self._aad_version == 2:
            return _crypto_v2.make_associated_data_v2(
                self._vault_uuid,  # type: ignore[arg-type]
                credential_uuid,
                field_name,
                service,
                username,
            )
        return _crypto_v2.make_associated_data(
            self._vault_uuid,  # type: ignore[arg-type]
            credential_uuid,
            field_name,
        )

    def _validated_identity_keys(self, service: str, username: str) -> Tuple[str, str]:
        """Return canonical keys, rejecting empty identities at write time."""
        try:
            return validate_identity(service, username)
        except ValueError as exc:
            raise StorageError(str(exc)) from exc

    def save_credential(self, service: str, username: str, password: str, note: str = "", note_is_hidden: bool = False, url: str = "") -> int:
        self._require_unlocked()
        service_key, username_key = self._validated_identity_keys(service, username)
        _validate_field_size(password, note)
        url = _sanitize_url(url)
        _validate_url(url)

        if self._vault_version == 2:
            return self._save_credential_v2(service, username, password, note, note_is_hidden, service_key, username_key, url)

        fernet = self._require_unlocked()
        encrypted_password, encrypted_note = self._encrypt_fields_v1(fernet, password, note)

        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO credentials (service, username, encrypted_password, encrypted_note, note_is_hidden, service_key, username_key, url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (service, username, encrypted_password, encrypted_note, 1 if note_is_hidden else 0, service_key, username_key, url)
            )
        except sqlite3.IntegrityError as exc:
            conn.rollback()
            raise StorageError(
                f"A credential for '{service} / {username}' already exists."
            ) from exc
        conn.commit()
        cred_id = int(cursor.lastrowid or 0)
        _log.info("credential saved (id=%d)", cred_id)
        return cred_id

    def _save_credential_v2(
        self, service: str, username: str, password: str, note: str, note_is_hidden: bool,
        service_key: str, username_key: str, url: str = "",
    ) -> int:
        """Save a credential in a v2 vault."""
        _validate_field_size(password, note)
        _validate_url(url)
        credential_uuid = uuid.uuid4().bytes
        encrypted_password, encrypted_note = self._encrypt_fields_v2(
            password, note, credential_uuid, service, username
        )

        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO credentials (credential_uuid, service, username, encrypted_password, encrypted_note, note_is_hidden, service_key, username_key, url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (credential_uuid, service, username, encrypted_password, encrypted_note, 1 if note_is_hidden else 0, service_key, username_key, url),
            )
        except sqlite3.IntegrityError as exc:
            conn.rollback()
            raise StorageError(
                f"A credential for '{service} / {username}' already exists."
            ) from exc
        conn.commit()
        cred_id = int(cursor.lastrowid or 0)
        _log.info("credential saved (id=%d)", cred_id)
        return cred_id

    def find_credential_by_identity(
        self, service: str, username: str, exclude_id: Optional[int] = None
    ) -> Optional[dict]:
        """Return metadata for the credential matching the canonical identity.

        Uses the ``idx_credentials_identity`` unique index, so duplicate
        decisions are indexed database lookups rather than Python scans of
        the full vault.  ``exclude_id`` skips one row (credential edits).

        Returns a dict with id/service/username/created_at/url keys, or None.
        """
        self._require_unlocked()
        service_key, username_key = canonical_service_username(service, username)
        if not service_key or not username_key:
            return None
        conn = self._get_conn()
        cursor = conn.cursor()
        # url column may be missing in legacy vaults — handle gracefully.
        has_url = self._cached_has_url_column(cursor)
        url_expr = ", url" if has_url else ", '' as url"  # allow-list, not user input
        if exclude_id is None:
            cursor.execute(
                f"SELECT id, service, username, created_at{url_expr} FROM credentials"  # nosec B608 — url_expr is allow-list
                " WHERE service_key = ? AND username_key = ?",
                (service_key, username_key),
            )
        else:
            cursor.execute(
                f"SELECT id, service, username, created_at{url_expr} FROM credentials"  # nosec B608 — url_expr is allow-list
                " WHERE service_key = ? AND username_key = ? AND id != ?",
                (service_key, username_key, exclude_id),
            )
        row = cursor.fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "service": row["service"],
            "username": row["username"],
            "created_at": row["created_at"],
            "url": row["url"] if "url" in row.keys() and row["url"] is not None else "",
        }

    def _fetch_credential_metadata_rows(
        self, cursor: sqlite3.Cursor, limit: Optional[int] = None, offset: Optional[int] = None
    ) -> List[sqlite3.Row]:
        """Flat helper: fetch metadata rows with optional pagination, reusable."""
        has_url = self._cached_has_url_column(cursor)
        url_expr = ", url" if has_url else ", '' as url"  # allow-list
        query = f"SELECT id, service, username, created_at{url_expr} FROM credentials ORDER BY service_key, username_key, id"  # nosec B608 — url_expr is allow-list
        params: List[Any] = []
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
            if offset is not None:
                query += " OFFSET ?"
                params.append(offset)
        cursor.execute(query, params)
        return cursor.fetchall()

    @staticmethod
    def _row_to_metadata(row: sqlite3.Row) -> dict:
        """Flat helper: convert a DB row to metadata dict, reusable."""
        return {
            "id": row["id"],
            "service": row["service"],
            "username": row["username"],
            "url": row["url"] if "url" in row.keys() and row["url"] is not None else "",
            "created_at": row["created_at"],
        }

    def list_credential_metadata(self) -> list[dict]:
        """Return metadata for all credentials without decrypting passwords/notes.

        Returns list of dicts with keys: id, service, username, url, created_at
        """
        self._require_unlocked()
        conn = self._get_conn()
        cursor = conn.cursor()
        rows = self._fetch_credential_metadata_rows(cursor)
        return [self._row_to_metadata(row) for row in rows]

    def list_credential_metadata_paginated(
        self, limit: int = _VAULT_PAGE_SIZE, offset: int = 0
    ) -> list[dict]:
        """Paginated metadata fetch for large vaults — reusable.

        Uses constants for default page size, no hard-coded inline limits.
        For large offsets (>1000) prefer ``list_credential_metadata_keyset`` to
        avoid OFFSET scan.
        """
        self._require_unlocked()
        conn = self._get_conn()
        cursor = conn.cursor()
        rows = self._fetch_credential_metadata_rows(cursor, limit=limit, offset=offset)
        return [self._row_to_metadata(row) for row in rows]

    def list_credential_metadata_keyset(
        self,
        limit: int = _VAULT_PAGE_SIZE,
        after: Tuple[str, str, int] | None = None,
    ) -> list[dict]:
        """Keyset pagination — O(log n) for large vaults, no OFFSET scan.

        ``after`` is the last tuple ``(service_key, username_key, id)`` from the
        previous page.  ``None`` returns the first page.
        """
        self._require_unlocked()
        conn = self._get_conn()
        cursor = conn.cursor()
        has_url = self._cached_has_url_column(cursor)
        url_expr = ", url" if has_url else ", '' as url"  # allow-list
        if after is None:
            cursor.execute(
                f"SELECT id, service, username, created_at{url_expr}, service_key, username_key "  # nosec B608 — url_expr allow-list
                "FROM credentials ORDER BY service_key, username_key, id LIMIT ?",
                (limit,),
            )
        else:
            sk, uk, last_id = after
            cursor.execute(
                f"SELECT id, service, username, created_at{url_expr}, service_key, username_key "  # nosec B608 — url_expr allow-list
                "FROM credentials WHERE (service_key, username_key, id) > (?, ?, ?) "
                "ORDER BY service_key, username_key, id LIMIT ?",
                (sk, uk, last_id, limit),
            )
        rows = cursor.fetchall()
        return [self._row_to_metadata(row) for row in rows]

    def count_credentials(self) -> int:
        """Return total credential count — reusable for pagination."""
        self._require_unlocked()
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as cnt FROM credentials")
        row = cursor.fetchone()
        return int(row["cnt"]) if row else 0

    def _build_search_filter_clause(self, query: str) -> tuple[str, List[Any]]:
        """Flat helper: build WHERE clause for 2B-scale indexed search, reusable."""
        q = query.strip().lower()
        if not q:
            return "", []
        # Use canonical stripped form to match service_key/username_key indexes
        from .identity import canonical_identity_stripped

        cq = canonical_identity_stripped(q)
        if not cq:
            return "", []
        # Escape LIKE wildcards in query
        escaped = cq.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        like = f"%{escaped}%"
        clause = " WHERE service_key LIKE ? ESCAPE '\\' OR username_key LIKE ? ESCAPE '\\' OR service LIKE ? ESCAPE '\\' OR username LIKE ? ESCAPE '\\' OR url LIKE ? ESCAPE '\\'"
        params = [like, like, like, like, like]
        return clause, params

    def search_credential_metadata(
        self,
        query: str,
        limit: int = _VAULT_SEARCH_SQL_LIMIT,
        offset: int = 0,
    ) -> list[dict]:
        """DB-side vault search — 60 fps streaming for 2B vaults, flat & reusable.

        Uses an indexed ``LIKE`` pre-filter (escaped, parameterized) ordered by
        ``service_key/username_key`` and capped by the ``limit`` argument
        (default ``_VAULT_SEARCH_SQL_LIMIT`` = 500).  The constant
        ``_VAULT_SEARCH_SQL_LIKE_LIMIT`` (2000) is *not* the ``LIMIT`` for
        this query; it only gates the ``import_from_csv`` identity-map preload
        decision (``count_credentials() <= _VAULT_SEARCH_SQL_LIKE_LIMIT``).
        No hard-coded inline limits.
        """
        self._require_unlocked()
        conn = self._get_conn()
        cursor = conn.cursor()
        has_url = self._cached_has_url_column(cursor)
        url_expr = ", url" if has_url else ", '' as url"  # allow-list
        base = f"SELECT id, service, username, created_at{url_expr} FROM credentials"  # nosec B608 — url_expr is allow-list
        clause, params = self._build_search_filter_clause(query)
        if not clause:
            # Empty query — fall back to paginated list
            return self.list_credential_metadata_paginated(limit=limit, offset=offset)
        # Result size is bounded by the caller's ``limit`` (default 500);
        # full FTS5 would be needed for true 2B-scale, but current indexed
        # service_key/username_key ORDER BY keeps scan bounded for typical vaults.
        query_sql = f"{base}{clause} ORDER BY service_key, username_key, id LIMIT ? OFFSET ?"  # nosec B608 — clause is fixed LIKE with parameterized ?
        params.extend([limit, offset])
        cursor.execute(query_sql, params)
        return [self._row_to_metadata(row) for row in cursor.fetchall()]

    def count_search_results(self, query: str) -> int:
        """Count matching rows for DB-side search, reusable."""
        self._require_unlocked()
        conn = self._get_conn()
        cursor = conn.cursor()
        clause, params = self._build_search_filter_clause(query)
        if not clause:
            return self.count_credentials()
        cursor.execute(f"SELECT COUNT(*) as cnt FROM credentials{clause}", params)  # nosec B608 — clause is fixed LIKE
        row = cursor.fetchone()
        return int(row["cnt"]) if row else 0

    def _load_existing_identity_map(self, cursor: sqlite3.Cursor) -> Dict[Tuple[str, str], int]:
        """Flat helper: preload service_key->id map for batched import, reusable."""
        cursor.execute("SELECT service_key, username_key, id FROM credentials")
        return {(row["service_key"], row["username_key"]): row["id"] for row in cursor.fetchall()}

    def get_credential_secret(self, credential_id: int) -> dict:
        """Decrypt and return the password and note for one credential.

        Returns dict with keys: password, note, note_is_hidden, url
        """
        fernet = self._require_unlocked()
        conn = self._get_conn()
        cursor = conn.cursor()
        if self._vault_version == 2:
            cursor.execute(
                "SELECT credential_uuid, service, username, encrypted_password, encrypted_note, note_is_hidden, url FROM credentials WHERE id=?",
                (credential_id,),
            )
        else:
            cursor.execute(
                "SELECT encrypted_password, encrypted_note, note_is_hidden, url FROM credentials WHERE id=?",
                (credential_id,),
            )
        row = cursor.fetchone()
        if row is None:
            raise StorageError(f"Credential {credential_id} not found.")
        password, note = self._decrypt_credential_fields(row, fernet)
        note_is_hidden = bool(row["note_is_hidden"]) if row["note_is_hidden"] is not None else False
        url = row["url"] if "url" in row.keys() and row["url"] is not None else ""
        return {"password": password, "note": note, "note_is_hidden": note_is_hidden, "url": url}

    # Kept for CSV export/import and tests. Prefer list_credential_metadata()
    # + get_credential_secret() for UI operations.
    def _row_to_credential(self, row: sqlite3.Row, fernet: Fernet) -> dict:
        """Flat helper: decrypt row to credential dict, reusable for streaming."""
        try:
            password, note = self._decrypt_credential_fields(row, fernet)
            note_is_hidden = bool(row["note_is_hidden"]) if row["note_is_hidden"] is not None else False
            url = row["url"] if "url" in row.keys() and row["url"] is not None else ""
            return {
                "id": row["id"],
                "service": row["service"],
                "username": row["username"],
                "url": url,
                "password": password,
                "note": note,
                "note_is_hidden": note_is_hidden,
                "created_at": row["created_at"],
            }
        except (InvalidToken, InvalidTag, UnicodeDecodeError):
            return {
                "id": row["id"],
                "service": row["service"],
                "username": row["username"],
                "url": row["url"] if "url" in row.keys() and row["url"] is not None else "",
                "password": "<DECRYPTION_ERROR>",  # nosec B105 — error sentinel
                "note": "<DECRYPTION_ERROR>",  # nosec B105 — error sentinel
                "note_is_hidden": False,
                "created_at": row["created_at"],
            }

    def iter_credentials(self, batch_size: int = _VAULT_PAGE_SIZE):
        """Streaming iterator over decrypted credentials — 60 fps / 2B friendly.

        Yields dicts one-by-one using a server-side cursor so data travels
        without fetchall materialization. Reusable, flat, bounded by constants.
        """
        fernet = self._require_unlocked()
        conn = self._get_conn()
        cursor = conn.cursor()
        if self._vault_version == 2:
            cursor.execute(
                "SELECT id, credential_uuid, service, username, url, encrypted_password, encrypted_note, note_is_hidden, created_at "
                "FROM credentials ORDER BY service_key, username_key, id"
            )
        else:
            cursor.execute(
                "SELECT id, service, username, url, encrypted_password, encrypted_note, note_is_hidden, created_at "
                "FROM credentials ORDER BY service_key, username_key, id"
            )
        for row in cursor:
            yield self._row_to_credential(row, fernet)

    def list_credentials(self) -> List[dict]:
        """Returns a list of credentials with decrypted passwords and notes."""
        # Flat: delegate to streaming iterator for 2B-scale data travel.
        return list(self.iter_credentials())

    def delete_credential(self, credential_id: int) -> None:
        self._require_unlocked()

        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM credentials WHERE id = ?", (credential_id,))
        conn.commit()
        _log.info("credential deleted: id=%d", credential_id)

    def update_credential(self, credential_id: int, service: str, username: str, password: str, note: str = "", note_is_hidden: bool = False, url: str = "") -> None:
        """Update an existing credential by id."""
        self._require_unlocked()
        service_key, username_key = self._validated_identity_keys(service, username)
        _validate_field_size(password, note)
        url = _sanitize_url(url)
        _validate_url(url)

        if self._vault_version == 2:
            self._update_credential_v2(credential_id, service, username, password, note, note_is_hidden, service_key, username_key, url)
            return

        fernet = self._require_unlocked()
        encrypted_password, encrypted_note = self._encrypt_fields_v1(fernet, password, note)

        conn = self._get_conn()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "UPDATE credentials SET service = ?, username = ?, encrypted_password = ?, encrypted_note = ?, note_is_hidden = ?, service_key = ?, username_key = ?, url = ? WHERE id = ?",
                (service, username, encrypted_password, encrypted_note, 1 if note_is_hidden else 0, service_key, username_key, url, credential_id),
            )
        except sqlite3.IntegrityError as exc:
            conn.rollback()
            raise StorageError(
                f"A credential for '{service} / {username}' already exists."
            ) from exc
        if cursor.rowcount == 0:
            conn.rollback()
            raise StorageError(f"Credential with id {credential_id} not found.")
        conn.commit()
        _log.info("credential updated: id=%d", credential_id)

    def _update_credential_v2(
        self, credential_id: int, service: str, username: str,
        password: str, note: str, note_is_hidden: bool,
        service_key: str, username_key: str, url: str = "",
    ) -> None:
        """Update an existing credential in a v2 vault."""
        _validate_field_size(password, note)
        _validate_url(url)
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT credential_uuid FROM credentials WHERE id = ?",
            (credential_id,),
        )
        row = cursor.fetchone()
        if row is None:
            raise StorageError(f"Credential with id {credential_id} not found.")
        credential_uuid: bytes = row["credential_uuid"]

        encrypted_password, encrypted_note = self._encrypt_fields_v2(
            password, note, credential_uuid, service, username
        )

        try:
            cursor.execute(
                "UPDATE credentials SET service = ?, username = ?, encrypted_password = ?, encrypted_note = ?, note_is_hidden = ?, service_key = ?, username_key = ?, url = ? WHERE id = ?",
                (service, username, encrypted_password, encrypted_note, 1 if note_is_hidden else 0, service_key, username_key, url, credential_id),
            )
        except sqlite3.IntegrityError as exc:
            conn.rollback()
            raise StorageError(
                f"A credential for '{service} / {username}' already exists."
            ) from exc
        conn.commit()
        _log.info("credential updated: id=%d", credential_id)

    def export_to_csv(
        self,
        csv_path: Path,
        export_format: str = "generic",
    ) -> Tuple[int, List[Dict[str, str]]]:
        """Export credentials to CSV file in provider-compatible format.

        Returns:
            Tuple of (exported_count, skipped_rows)
            skipped_rows is a list of dicts with 'service', 'username', 'error' keys
        """
        fernet = self._require_unlocked()
        try:
            normalized_format = csv_formats.normalize_export_format(export_format)
        except ValueError as e:
            raise StorageError(str(e))

        # Reject symlink and non-regular-file targets for security.
        if csv_path.exists():
            if csv_path.is_symlink():
                raise StorageError("Export path is a symlink — refused for security.")
            if not csv_path.is_file():
                raise StorageError("Export path exists but is not a regular file.")

        # Reject symlinked parent directory to avoid writing through a
        # directory symlink to an unintended location (e.g., /etc).
        try:
            parent_lst = csv_path.parent.lstat()
            import stat as _stat_parent

            if _stat_parent.S_ISLNK(parent_lst.st_mode):
                raise StorageError("Export parent directory is a symlink — refused for security.")
        except OSError as exc:
            raise StorageError(f"Cannot inspect export parent directory: {exc}") from exc

        conn = self._get_conn()
        cursor = conn.cursor()
        # Ensure url column exists even for legacy queries.
        has_url = self._cached_has_url_column(cursor)
        url_select = ", url" if has_url else ", '' as url"  # allow-list
        if self._vault_version == 2:
            cursor.execute(f"SELECT id, credential_uuid, service, username, encrypted_password, encrypted_note, created_at{url_select} FROM credentials ORDER BY service_key, username_key, id")  # nosec B608 — url_select is allow-list
        else:
            cursor.execute(f"SELECT id, service, username, encrypted_password, encrypted_note, created_at{url_select} FROM credentials ORDER BY service_key, username_key, id")  # nosec B608 — url_select is allow-list

        exported = 0
        skipped = []

        # Write to a securely-named temp file, then atomically replace.
        tmp_path = self._secure_temp_file(csv_path.parent, csv_path.suffix)
        try:
            with open(tmp_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(csv_formats.get_export_headers(normalized_format))

                # Stream the result set directly to the CSV writer without
                # materializing all rows into memory via fetchall().
                for row in cursor:
                    try:
                        password, _note = self._decrypt_credential_fields(row, fernet)
                        url_val = row["url"] if "url" in row.keys() and row["url"] is not None else ""
                        writer.writerow(
                            csv_formats.build_export_row(
                                normalized_format,
                                service=row["service"],
                                username=row["username"],
                                password=password,
                                note=_note,
                                url=url_val,
                            )
                        )
                        exported += 1
                    except (InvalidToken, InvalidTag, UnicodeDecodeError):
                        skipped.append({
                            'service': row["service"],
                            'username': row["username"],
                            'error': "Unable to decrypt credential"
                        })

                # Flush and sync while the file is still open for writing.  On
                # Windows, fsync() rejects a read-only descriptor.
                f.flush()
                os.fsync(f.fileno())

            # Atomic rename (os.replace is atomic on POSIX and Windows).
            os.replace(str(tmp_path), str(csv_path))
            # Defense in depth: ensure final file is owner-only even if
            # the predecessor had broader permissions or the filesystem
            # preserved mode bits.
            self._ensure_private_permissions(csv_path, 0o600)
        except BaseException:
            # Clean up temp file on any failure.
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
            raise

        _log.info("exported %d credentials to %s", exported, csv_path)
        return exported, skipped

    def import_from_csv(
        self,
        csv_path: Path,
        merge_duplicates: bool = False,
        dry_run: bool = False,
        import_format: str = "auto",
    ) -> Tuple[int, int, List[Dict[str, str]]]:
        """Import credentials from CSV file.

        Supports format presets for common providers.

        Detects duplicates by case-insensitive (service, username) match.

        Args:
            csv_path: Path to CSV file
            merge_duplicates: If True, overwrite existing duplicates. If False, skip them.
            dry_run: If True, do not modify the database; just report counts/issues.
            import_format: One of auto/generic/bitwarden/apple/nordpass.

        Returns:
            Tuple of (imported_count, skipped_count, duplicate_list)
            duplicate_list contains dicts with 'service', 'username', 'reason' keys
        """
        fernet = self._require_unlocked()
        try:
            requested_format = csv_formats.normalize_import_format(import_format)
        except ValueError as e:
            raise StorageError(str(e))

        # Duplicates are detected via the canonical identity index
        # (find_credential_by_identity) instead of loading and scanning all
        # vault metadata in Python.
        conn = self._get_conn()
        cursor = conn.cursor()

        imported = 0
        skipped = 0
        duplicates = []
        total_rows = 0
        seen_keys: set[Tuple[str, str]] = set()

        # Resource limit + symlink hardening: validate via lstat before any
        # open, and use O_NOFOLLOW on POSIX so a symlink swap between the
        # check and the open cannot be exploited.
        import stat as _stat

        try:
            lst = csv_path.lstat()
        except OSError as exc:
            raise StorageError(f"Cannot read CSV file: {exc}") from exc
        if _stat.S_ISLNK(lst.st_mode):
            raise StorageError("CSV path is a symlink — refused for security.")
        if not _stat.S_ISREG(lst.st_mode):
            raise StorageError("CSV file is not a regular file.")
        if lst.st_size > _MAX_CSV_FILE_BYTES:
            raise StorageError(
                f"CSV file too large ({lst.st_size} bytes). "
                f"Maximum: {_MAX_CSV_FILE_BYTES} bytes."
            )

        # Validate the file and headers before opening any transaction so
        # malformed inputs (bad format, missing headers, oversized files)
        # raise StorageError without leaving an implicit transaction open.
        #
        # A write transaction is opened ONLY for real imports, immediately
        # before the first possible insert/update (below). Dry runs never
        # begin a transaction, so `connection.in_transaction` is False after
        # a dry run and a subsequent real import on the same connection does
        # not collide with a leftover transaction.
        transaction_opened = False
        try:
            # Secure open: O_NOFOLLOW on POSIX prevents symlink TOCTOU between
            # lstat and read. Falls back to regular open on Windows / missing
            # O_NOFOLLOW. Size already checked via lstat, but re-verify via
            # fstat after open to catch a concurrent replacement.
            csv_file = None
            try:
                no_follow = getattr(os, "O_NOFOLLOW", None)
                if os.name == "posix" and no_follow is not None:
                    try:
                        fd = os.open(str(csv_path), os.O_RDONLY | no_follow)
                    except OSError as exc:
                        import errno as _errno

                        if exc.errno in (_errno.ELOOP, _errno.EMLINK) or "symlink" in str(exc).lower() or "Too many levels" in str(exc):
                            raise StorageError("CSV path is a symlink — refused for security.") from exc
                        raise StorageError(f"Cannot read CSV file: {exc}") from exc
                    try:
                        st = os.fstat(fd)
                        if _stat.S_ISLNK(st.st_mode):
                            raise StorageError("CSV path is a symlink — refused for security.")
                        if not _stat.S_ISREG(st.st_mode):
                            raise StorageError("CSV file is not a regular file.")
                        if st.st_size > _MAX_CSV_FILE_BYTES:
                            raise StorageError(
                                f"CSV file too large ({st.st_size} bytes). "
                                f"Maximum: {_MAX_CSV_FILE_BYTES} bytes."
                            )
                        csv_file = os.fdopen(fd, "r", newline="", encoding="utf-8-sig")
                    except BaseException:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                        raise
                else:
                    csv_file = open(csv_path, "r", newline="", encoding="utf-8-sig")
            except StorageError:
                raise
            except OSError as exc:
                raise StorageError(f"Cannot read CSV file: {exc}") from exc
            with csv_file as f:
                reader = csv.DictReader(f)

                if not reader.fieldnames:
                    raise StorageError("CSV file has no headers.")

                resolved_format = csv_formats.resolve_import_format(
                    reader.fieldnames,
                    requested_format=requested_format,
                )
                missing_headers = csv_formats.missing_required_headers(
                    reader.fieldnames,
                    import_format=resolved_format,
                )
                if missing_headers:
                    raise StorageError(f"CSV missing required columns: {', '.join(missing_headers)}")

                # Begin the write transaction only for real imports, right
                # before the row loop. Dry runs skip this so the connection
                # stays in autocommit mode and `in_transaction` is False.
                if not dry_run:
                    conn.execute("BEGIN")
                    transaction_opened = True

                # Flat helper: preload identity map for 2B-scale batched import, reusable.
                existing_map: Dict[Tuple[str, str], int] = {}
                use_preload = False
                if not dry_run:
                    try:
                        # Avoid 2B fetch: only preload for modest vaults
                        if self.count_credentials() <= _VAULT_SEARCH_SQL_LIKE_LIMIT:
                            existing_map = self._load_existing_identity_map(cursor)
                            use_preload = True
                    except StorageError:
                        use_preload = False

                for row_num, row in enumerate(reader, start=2):  # Start at 2 (header is row 1)
                    total_rows += 1
                    if total_rows > _MAX_CSV_ROWS:
                        raise StorageError(f"CSV exceeds maximum row count ({_MAX_CSV_ROWS}).")
                    parsed, parse_issue = csv_formats.parse_import_row(
                        row,
                        import_format=resolved_format,
                        row_num=row_num,
                    )

                    if parse_issue:
                        row_service, row_username = csv_formats.extract_row_identity(
                            row,
                            import_format=resolved_format,
                        )
                        skipped += 1
                        duplicates.append({
                            'service': row_service or '(unknown)',
                            'username': row_username or '(unknown)',
                            'reason': parse_issue,
                        })
                        continue

                    if not parsed:
                        continue

                    # Field length limits (url allows larger limit)
                    for field_name, value in parsed.items():
                        limit = _MAX_URL_BYTES if field_name == "url" else _MAX_CSV_FIELD_BYTES
                        if len(value.encode('utf-8')) > limit:
                            raise StorageError(
                                f"Field '{field_name}' in row {row_num} exceeds "
                                f"{limit} bytes."
                            )

                    service = parsed["service"]
                    username = parsed["username"]
                    password = parsed["password"]
                    note = parsed.get("note", "")
                    url = _sanitize_url(parsed.get("url", ""))
                    _validate_url(url)

                    # Canonical identity for duplicate detection.  The indexed
                    # lookup also sees rows inserted earlier in this same
                    # transaction, so in-file duplicates are caught too; the
                    # seen_keys set covers the dry-run case (no inserts happen
                    # during a preview).
                    service_key, username_key = self._validated_identity_keys(service, username)
                    identity_key = (service_key, username_key)
                    # Flat: use preloaded map for 2B batched path, else indexed lookup
                    if use_preload:
                        _cid = existing_map.get(identity_key)
                        existing = {"id": _cid} if _cid is not None else None
                    else:
                        existing = self.find_credential_by_identity(service, username)
                    if existing is not None or identity_key in seen_keys:
                        if merge_duplicates and not dry_run and existing is not None:
                            # Update existing credential — preserve url if provided, else keep existing.
                            cred_id = existing["id"]
                            if self._vault_version == 2:
                                cursor.execute(
                                    "SELECT credential_uuid, url FROM credentials WHERE id = ?",
                                    (cred_id,),
                                )
                                cred_uuid_row = cursor.fetchone()
                                if cred_uuid_row:
                                    encrypted_password, encrypted_note = self._encrypt_fields_v2(
                                        password, note, cred_uuid_row["credential_uuid"], service, username
                                    )
                                    # If import row has no url, keep existing url.
                                    existing_url = cred_uuid_row["url"] if "url" in cred_uuid_row.keys() and cred_uuid_row["url"] else ""
                                    url_to_store = url if url else _sanitize_url(existing_url)
                                    cursor.execute(
                                        "UPDATE credentials SET encrypted_password = ?, encrypted_note = ?, note_is_hidden = 0, url = ? WHERE id = ?",
                                        (encrypted_password, encrypted_note, url_to_store, cred_id)
                                    )
                            else:
                                encrypted_password, encrypted_note = self._encrypt_fields_v1(fernet, password, note)
                                cursor.execute("SELECT url FROM credentials WHERE id=?", (cred_id,))
                                existing_row = cursor.fetchone()
                                existing_url = existing_row["url"] if existing_row and "url" in existing_row.keys() and existing_row["url"] else ""
                                url_to_store = url if url else _sanitize_url(existing_url)
                                cursor.execute(
                                    "UPDATE credentials SET encrypted_password = ?, encrypted_note = ?, note_is_hidden = 0, url = ? WHERE id = ?",
                                    (encrypted_password, encrypted_note, url_to_store, cred_id)
                                )
                            imported += 1
                        else:
                            skipped += 1
                            duplicates.append({
                                'service': service,
                                'username': username,
                                'reason': 'Duplicate (not merged)'
                            })
                    else:
                        # Insert new credential
                        if not dry_run:
                            if self._vault_version == 2:
                                cred_uuid = uuid.uuid4().bytes
                                encrypted_password, encrypted_note = self._encrypt_fields_v2(
                                    password, note, cred_uuid, service, username
                                )
                                cursor.execute(
                                    "INSERT INTO credentials (credential_uuid, service, username, encrypted_password, encrypted_note, note_is_hidden, service_key, username_key, url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                    (cred_uuid, service, username, encrypted_password, encrypted_note, 0, service_key, username_key, url)
                                )
                            else:
                                fernet = self._require_unlocked()
                                encrypted_password, encrypted_note = self._encrypt_fields_v1(fernet, password, note)
                                cursor.execute(
                                    "INSERT INTO credentials (service, username, encrypted_password, encrypted_note, note_is_hidden, service_key, username_key, url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                    (service, username, encrypted_password, encrypted_note, 0, service_key, username_key, url)
                                )
                        imported += 1
                        # Track canonical identities handled by this import so
                        # duplicate rows later in the same file are skipped.
                        seen_keys.add(identity_key)
                        if use_preload:
                            # Keep preload map in sync for later rows in same file
                            try:
                                _new_id = int(cursor.lastrowid or 0)
                                if _new_id:
                                    existing_map[identity_key] = _new_id
                            except Exception:
                                pass

            # Commit the real import atomically. An empty import commits a
            # no-op transaction, matching the previous behavior.
            if transaction_opened:
                conn.commit()
                transaction_opened = False
        finally:
            # Defensive: never leak an open transaction to the caller. If the
            # success path failed to clear the flag or any error path left a
            # transaction open, roll it back so subsequent operations on the
            # same connection (e.g. a real import right after a dry-run
            # preview) keep working.
            if transaction_opened:
                try:
                    conn.rollback()
                except Exception:  # nosec B110 — best-effort cleanup
                    pass

        _log.info("imported %d credentials from %s", imported, csv_path)
        return imported, skipped, duplicates

    # ------------------------------------------------------------------
    # Vault health / status / backup pruning — flat helpers
    # ------------------------------------------------------------------

    def list_backups(self) -> List[Path]:
        """Return sorted list of backup files next to the vault."""
        if not self.db_path.parent.exists():
            return []
        pattern = f"{self.db_path.name}.*.bak"
        backups = list(self.db_path.parent.glob(pattern))
        # Exclude the original db itself, symlinks, and non-files.
        # is_file() follows symlinks, so check is_symlink() first.
        backups = [p for p in backups if not p.is_symlink() and p.is_file() and p != self.db_path]

        def _backup_ctime(path: Path) -> float:
            """Sort key for backup files.

            On POSIX ``st_ctime`` is the inode *change* time (updated when file
            content or metadata changes), not creation time; on Windows it is
            creation time.  In either case it cannot be set with ``touch -m``
            (which only changes *mtime*), so it is harder to forge than
            ``st_mtime``, though an attacker with write access to the backup
            directory can still affect it by rewriting the file.  Within the
            same second ``st_ctime`` may collide, so ``sort()`` stability
            preserves ``glob()`` order for ties.
            """
            try:
                st = path.stat()
                return getattr(st, "st_ctime", st.st_mtime)
            except OSError:
                return 0

        backups.sort(key=_backup_ctime)
        return backups

    def prune_backups(self, keep_latest: int = 1) -> List[Path]:
        """Delete oldest backups keeping *keep_latest* newest files.

        Returns list of deleted paths.  ``keep_latest=0`` deletes all.
        """
        backups = self.list_backups()
        if keep_latest < 0:
            keep_latest = 0
        if len(backups) <= keep_latest:
            return []
        to_delete = backups[: len(backups) - keep_latest]
        deleted: List[Path] = []
        for path in to_delete:
            try:
                if path.is_symlink():
                    continue
                path.unlink()
                deleted.append(path)
            except OSError:
                _log.warning("Could not prune backup %s", path)
        if deleted:
            _log.info("pruned %d backup(s)", len(deleted))
        return deleted

    def get_vault_status(self) -> Dict[str, object]:
        """Return non-sensitive vault status for health checks."""
        backups = self.list_backups()
        status: Dict[str, object] = {
            "vault_path": str(self.db_path),
            "exists": self.vault_exists(),
            "is_unlocked": self._vault_version is not None,
            "version": self._vault_version,
            "aad_version": self._aad_version if self._vault_version == 2 else None,
            "credential_count": 0,
            "backup_count": len(backups),
            "backups": [str(p) for p in backups],
            "backup_retain": _MAX_BACKUP_RETAIN,
            "backup_warning": len(backups) > _BACKUP_WARN_THRESHOLD,
        }
        if self._vault_version is not None:
            try:
                conn = self._get_conn()
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM credentials")
                row = cursor.fetchone()
                status["credential_count"] = int(row[0]) if row else 0
                if self._vault_version == 2:
                    dek_gen = self._read_optional_int_config(cursor, "dek_generation")
                    status["dek_generation"] = dek_gen if dek_gen is not None else 1
            except sqlite3.Error:
                pass
        else:
            # Not unlocked — try to detect version without unlocking.
            try:
                conn = self._get_conn()
                cursor = conn.cursor()
                version = self._detect_vault_version(cursor)
                status["version"] = version
            except Exception:
                pass
        return status

    def _iter_integrity_rows(self):
        """Flat helper: streaming rows for integrity check, reusable."""
        conn = self._get_conn()
        cursor = conn.cursor()
        if self._vault_version == 2:
            cursor.execute(
                "SELECT id, credential_uuid, service, username, encrypted_password, encrypted_note FROM credentials"
            )
        else:
            cursor.execute("SELECT id, service, username, encrypted_password, encrypted_note FROM credentials")
        for row in cursor:
            yield row

    def iter_integrity_issues(self, batch_size: int = 0):
        """Streaming integrity check — 60 fps / 2B friendly, flat & reusable.

        Yields issues one-by-one without materializing all rows. If batch_size >0,
        yields in chunks for progress UI. No hard-coded inline limits.
        """
        if batch_size == 0:
            batch_size = _VAULT_INTEGRITY_BATCH_SIZE
        self._require_unlocked()
        fernet = self._fernet
        batch: List[Dict[str, object]] = []
        for row in self._iter_integrity_rows():
            try:
                self._decrypt_credential_fields(row, fernet)  # type: ignore[arg-type]
            except Exception as exc:
                issue = {"id": row["id"], "service": row["service"], "error": str(exc)}
                if batch_size <= 1:
                    yield issue
                else:
                    batch.append(issue)
                    if len(batch) >= batch_size:
                        for item in batch:
                            yield item
                        batch.clear()
        if batch:
            for item in batch:
                yield item

    def check_vault_integrity(self) -> List[Dict[str, object]]:
        """Decrypt every credential and report failures — flat delegation to streaming."""
        return list(self.iter_integrity_issues())
