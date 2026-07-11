import tempfile
import os
import shutil
import sqlite3
import base64
import csv
import uuid
from pathlib import Path
from typing import List, Literal, Optional, Dict, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from platformdirs import user_data_dir
from . import _crypto_v2, csv_formats
from .logging import get_logger

_log = get_logger("storage")

APP_NAME = "generate-it"
APP_AUTHOR = "j-kemble"

# Default PBKDF2 parameters for newly created vaults.
# Persisted per-vault in the config table so existing vaults keep unlocking.
_DEFAULT_PBKDF2_ITERATIONS = 480_000
_DEFAULT_SALT_LENGTH = 32

# Legacy defaults for vaults created before these params were persisted.
_LEGACY_PBKDF2_ITERATIONS = 100_000

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


# Common weak passwords that are unconditionally rejected (case-insensitive).
_WEAK_PASSWORDS: frozenset[str] = frozenset({
    "password", "12345678", "123456789012", "qwertyuiop", "masterpass",
})

_MAX_MASTER_PASSWORD_LENGTH = 1024

# CSV import resource limits
_MAX_CSV_FILE_BYTES = 10 * 1024 * 1024  # 10 MB
_MAX_CSV_ROWS = 10_000
_MAX_CSV_FIELD_BYTES = 500


def _validate_master_password(password: str) -> None:
    """Validate a master password against the security policy.

    Raises:
        WeakMasterPasswordError: if the password is empty, too short, too long,
            or matches a known common/weak value.
    """
    if not password:
        raise WeakMasterPasswordError("Master password cannot be empty.")
    if len(password) < 12:
        raise WeakMasterPasswordError(
            "Master password must be at least 12 characters (15+ recommended)."
        )
    if len(password) > _MAX_MASTER_PASSWORD_LENGTH:
        raise WeakMasterPasswordError(
            f"Master password must be at most {_MAX_MASTER_PASSWORD_LENGTH} characters."
        )
    if password.casefold() in _WEAK_PASSWORDS:
        raise WeakMasterPasswordError(
            "That password is too common and easily guessed. Please choose a stronger one."
        )

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

    @staticmethod
    def _ensure_private_permissions(path: Path, mode: int = 0o600) -> None:
        """Set owner-only permissions on a file or directory.

        On POSIX systems this enforces ``mode`` (default 0600 for files,
        0700 for directories).  On non-POSIX systems this is a no-op.
        Failures are logged but never raised — the database still works
        even when the filesystem doesn't support POSIX permissions.
        """
        if not hasattr(os, "chmod"):
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
        os.chmod(tmp_path, 0o600)
        return Path(tmp_path)

    def _get_conn(self) -> sqlite3.Connection:
        if not self._db_connection:
            self._db_connection = sqlite3.connect(self.db_path)
            self._db_connection.row_factory = sqlite3.Row
            self._db_connection.execute("PRAGMA busy_timeout=5000")
            self._ensure_private_permissions(self.db_path, 0o600)
        return self._db_connection

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

    def get_app_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Read a persisted non-sensitive app preference from the config table."""
        conn = self._get_conn()
        cursor = conn.cursor()
        stored_key = f"app_setting:{key}"
        cursor.execute("SELECT value FROM config WHERE key = ?", (stored_key,))
        row = cursor.fetchone()
        if not row:
            return default

        value = row["value"]
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError:
                return default
        if value is None:
            return default
        return str(value)

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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        try:
            cursor.execute("SELECT note_is_hidden FROM credentials LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE credentials ADD COLUMN note_is_hidden INTEGER DEFAULT 0")
        
        # Store configuration
        cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", ("salt", salt))
        cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", ("verification", verification_token))
        cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", ("pbkdf2_iterations", str(_DEFAULT_PBKDF2_ITERATIONS)))
        cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", ("salt_length", str(_DEFAULT_SALT_LENGTH)))
        
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

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
            ("verification", verification_ct),
            ("dek_generation", "1"),
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

        # Read all required config values.
        try:
            cursor.execute("SELECT value FROM config WHERE key = 'kdf_algorithm'")
            kdf_algorithm_row = cursor.fetchone()
            kdf_algorithm = (
                kdf_algorithm_row["value"].decode("utf-8")
                if isinstance(kdf_algorithm_row["value"], bytes)
                else str(kdf_algorithm_row["value"])
            ) if kdf_algorithm_row else "argon2id"

            cursor.execute("SELECT value FROM config WHERE key = 'kdf_salt'")
            kdf_salt = cursor.fetchone()["value"]

            cursor.execute("SELECT value FROM config WHERE key = 'wrapped_dek'")
            wrapped_dek = cursor.fetchone()["value"]

            cursor.execute("SELECT value FROM config WHERE key = 'vault_uuid'")
            vault_uuid = cursor.fetchone()["value"]

            cursor.execute("SELECT value FROM config WHERE key = 'aead_algorithm'")
            aead_row = cursor.fetchone()
            aead_algorithm = (
                aead_row["value"].decode("utf-8")
                if aead_row and isinstance(aead_row["value"], bytes)
                else _crypto_v2.AEAD_AES_256_GCM
            ) if aead_row else _crypto_v2.AEAD_AES_256_GCM

            cursor.execute("SELECT value FROM config WHERE key = 'verification'")
            verification_ct = cursor.fetchone()["value"]
        except (TypeError, KeyError) as exc:
            raise StorageError("Vault v2 configuration corrupted or missing keys.") from exc

        # Read optional KDF parameters.
        memory_raw = self._read_optional_int_config(cursor, "kdf_memory_cost")
        memory = memory_raw if memory_raw is not None else _crypto_v2.DEFAULT_ARGON2_MEMORY

        time_raw = self._read_optional_int_config(cursor, "kdf_time_cost")
        time = time_raw if time_raw is not None else _crypto_v2.DEFAULT_ARGON2_TIME

        parallelism_raw = self._read_optional_int_config(cursor, "kdf_parallelism")
        parallelism = (
            parallelism_raw if parallelism_raw is not None
            else _crypto_v2.DEFAULT_ARGON2_PARALLELISM
        )

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

        # 1. Create a secure backup with an unpredictable name, then atomically
        #    rename to the predictable .v1.bak path.  This avoids symlink-following
        #    attacks on the well-known backup filename.
        backup_tmp = self._secure_temp_file(self.db_path.parent, ".v1.bak")
        try:
            shutil.copy2(self.db_path, backup_tmp)
        except BaseException:
            if backup_tmp.exists():
                try:
                    backup_tmp.unlink()
                except OSError:
                    pass
            raise
        backup_path = self.db_path.with_suffix(self.db_path.suffix + ".v1.bak")
        os.replace(str(backup_tmp), str(backup_path))
        _log.info("v1 backup created at %s", backup_path)

        conn = self._get_conn()
        cursor = conn.cursor()

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

            # Backfill credential_uuid for existing rows.
            cursor.execute(
                "SELECT id FROM credentials WHERE credential_uuid IS NULL"
            )
            for row in cursor.fetchall():
                new_uuid = uuid.uuid4().bytes
                cursor.execute(
                    "UPDATE credentials SET credential_uuid = ? WHERE id = ?",
                    (new_uuid, row["id"]),
                )

            # 5. Re-encrypt all credentials with v2 AEAD.
            assert self._fernet is not None  # v1 is unlocked
            fernet = self._fernet
            cursor.execute(
                "SELECT id, credential_uuid, encrypted_password, encrypted_note"
                " FROM credentials"
            )
            for row in cursor.fetchall():
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

                # Re-encrypt with v2 AEAD.
                new_password_ct = _crypto_v2.encrypt_field(
                    dek,
                    _crypto_v2.make_associated_data(vault_uuid, cred_uuid, "password"),
                    v1_password,
                    aead_algorithm=aead_algorithm,
                )
                new_note_ct: bytes | None = None
                if v1_note:
                    new_note_ct = _crypto_v2.encrypt_field(
                        dek,
                        _crypto_v2.make_associated_data(vault_uuid, cred_uuid, "note"),
                        v1_note,
                        aead_algorithm=aead_algorithm,
                    )

                cursor.execute(
                    "UPDATE credentials SET encrypted_password = ?, encrypted_note = ? WHERE id = ?",
                    (new_password_ct, new_note_ct, row["id"]),
                )

            # 6. Create v2 verification token.
            verification_ct = _crypto_v2.create_verification_token(
                dek, vault_uuid, aead_algorithm=aead_algorithm,
            )

            # 7. Write v2 config.
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
            _log.info("vault migrated from v1 to v2")

        except BaseException:
            # Rollback the transaction on any failure.
            try:
                conn.rollback()
            except Exception:
                pass
            # The backup file remains as a safety net.
            _log.exception("v1→v2 migration failed; v1 vault is intact")
            raise

    def close(self):
        if self._db_connection:
            self._db_connection.close()
            self._db_connection = None
        self._fernet = None
        self._vault_version = None
        self._dek = None
        self._vault_uuid = None
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
        assert self._dek is not None
        assert self._vault_uuid is not None

        credential_uuid: bytes = row["credential_uuid"]

        password_ad = _crypto_v2.make_associated_data(
            self._vault_uuid, credential_uuid, "password"
        )
        password = _crypto_v2.decrypt_field(
            self._dek, password_ad, row["encrypted_password"],
            aead_algorithm=self._aead_algorithm,
        )

        note = ""
        if row["encrypted_note"]:
            note_ad = _crypto_v2.make_associated_data(
                self._vault_uuid, credential_uuid, "note"
            )
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
        self, password: str, note: str, credential_uuid: bytes
    ) -> tuple[bytes, bytes | None]:
        """Encrypt using v2 AEAD with associated data binding to *credential_uuid*."""
        assert self._dek is not None
        assert self._vault_uuid is not None

        password_ad = _crypto_v2.make_associated_data(
            self._vault_uuid, credential_uuid, "password"
        )
        encrypted_password = _crypto_v2.encrypt_field(
            self._dek, password_ad, password,
            aead_algorithm=self._aead_algorithm,
        )

        encrypted_note: bytes | None = None
        if note:
            note_ad = _crypto_v2.make_associated_data(
                self._vault_uuid, credential_uuid, "note"
            )
            encrypted_note = _crypto_v2.encrypt_field(
                self._dek, note_ad, note,
                aead_algorithm=self._aead_algorithm,
            )

        return encrypted_password, encrypted_note

    def save_credential(self, service: str, username: str, password: str, note: str = "", note_is_hidden: bool = False) -> int:
        self._require_unlocked()

        if self._vault_version == 2:
            return self._save_credential_v2(service, username, password, note, note_is_hidden)

        fernet = self._require_unlocked()
        encrypted_password, encrypted_note = self._encrypt_fields_v1(fernet, password, note)
        
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO credentials (service, username, encrypted_password, encrypted_note, note_is_hidden) VALUES (?, ?, ?, ?, ?)",
            (service, username, encrypted_password, encrypted_note, 1 if note_is_hidden else 0)
        )
        conn.commit()
        cred_id = int(cursor.lastrowid or 0)
        _log.info("credential saved (id=%d)", cred_id)
        return cred_id

    def _save_credential_v2(
        self, service: str, username: str, password: str, note: str, note_is_hidden: bool
    ) -> int:
        """Save a credential in a v2 vault."""
        credential_uuid = uuid.uuid4().bytes
        encrypted_password, encrypted_note = self._encrypt_fields_v2(
            password, note, credential_uuid
        )

        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO credentials (credential_uuid, service, username, encrypted_password, encrypted_note, note_is_hidden) VALUES (?, ?, ?, ?, ?, ?)",
            (credential_uuid, service, username, encrypted_password, encrypted_note, 1 if note_is_hidden else 0),
        )
        conn.commit()
        cred_id = int(cursor.lastrowid or 0)
        _log.info("credential saved (id=%d)", cred_id)
        return cred_id

    def list_credential_metadata(self) -> list[dict]:
        """Return metadata for all credentials without decrypting passwords/notes.

        Returns list of dicts with keys: id, service, username, created_at
        """
        self._require_unlocked()
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, service, username, created_at FROM credentials ORDER BY service"
        )
        return [
            {
                "id": row["id"],
                "service": row["service"],
                "username": row["username"],
                "created_at": row["created_at"],
            }
            for row in cursor.fetchall()
        ]

    def get_credential_secret(self, credential_id: int) -> dict:
        """Decrypt and return the password and note for one credential.

        Returns dict with keys: password, note, note_is_hidden
        """
        fernet = self._require_unlocked()
        conn = self._get_conn()
        cursor = conn.cursor()
        if self._vault_version == 2:
            cursor.execute(
                "SELECT credential_uuid, encrypted_password, encrypted_note, note_is_hidden FROM credentials WHERE id=?",
                (credential_id,),
            )
        else:
            cursor.execute(
                "SELECT encrypted_password, encrypted_note, note_is_hidden FROM credentials WHERE id=?",
                (credential_id,),
            )
        row = cursor.fetchone()
        if row is None:
            raise StorageError(f"Credential {credential_id} not found.")
        password, note = self._decrypt_credential_fields(row, fernet)
        note_is_hidden = bool(row["note_is_hidden"]) if row["note_is_hidden"] is not None else False
        return {"password": password, "note": note, "note_is_hidden": note_is_hidden}

    # Kept for CSV export/import and tests. Prefer list_credential_metadata()
    # + get_credential_secret() for UI operations.
    def list_credentials(self) -> List[dict]:
        """Returns a list of credentials with decrypted passwords and notes."""
        fernet = self._require_unlocked()

        conn = self._get_conn()
        cursor = conn.cursor()
        if self._vault_version == 2:
            cursor.execute("SELECT id, credential_uuid, service, username, encrypted_password, encrypted_note, note_is_hidden, created_at FROM credentials ORDER BY service")
        else:
            cursor.execute("SELECT id, service, username, encrypted_password, encrypted_note, note_is_hidden, created_at FROM credentials ORDER BY service")
        
        results = []
        for row in cursor.fetchall():
            try:
                password, note = self._decrypt_credential_fields(row, fernet)
                note_is_hidden = bool(row["note_is_hidden"]) if row["note_is_hidden"] is not None else False
                results.append({
                    "id": row["id"],
                    "service": row["service"],
                    "username": row["username"],
                    "password": password,
                    "note": note,
                    "note_is_hidden": note_is_hidden,
                    "created_at": row["created_at"]
                })
            except (InvalidToken, InvalidTag, UnicodeDecodeError):
                results.append({
                    "id": row["id"],
                    "service": row["service"],
                    "username": row["username"],
                    "password": "<DECRYPTION_ERROR>",
                    "note": "<DECRYPTION_ERROR>",
                    "note_is_hidden": False,
                    "created_at": row["created_at"]
                })
        
        return results

    def delete_credential(self, credential_id: int) -> None:
        self._require_unlocked()
            
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM credentials WHERE id = ?", (credential_id,))
        conn.commit()
        _log.info("credential deleted: id=%d", credential_id)

    def update_credential(self, credential_id: int, service: str, username: str, password: str, note: str = "", note_is_hidden: bool = False) -> None:
        """Update an existing credential by id."""
        self._require_unlocked()

        if self._vault_version == 2:
            self._update_credential_v2(credential_id, service, username, password, note, note_is_hidden)
            return

        fernet = self._require_unlocked()
        encrypted_password, encrypted_note = self._encrypt_fields_v1(fernet, password, note)

        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE credentials SET service = ?, username = ?, encrypted_password = ?, encrypted_note = ?, note_is_hidden = ? WHERE id = ?",
            (service, username, encrypted_password, encrypted_note, 1 if note_is_hidden else 0, credential_id),
        )
        if cursor.rowcount == 0:
            raise StorageError(f"Credential with id {credential_id} not found.")
        conn.commit()
        _log.info("credential updated: id=%d", credential_id)

    def _update_credential_v2(
        self, credential_id: int, service: str, username: str,
        password: str, note: str, note_is_hidden: bool,
    ) -> None:
        """Update an existing credential in a v2 vault."""
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
            password, note, credential_uuid
        )

        cursor.execute(
            "UPDATE credentials SET service = ?, username = ?, encrypted_password = ?, encrypted_note = ?, note_is_hidden = ? WHERE id = ?",
            (service, username, encrypted_password, encrypted_note, 1 if note_is_hidden else 0, credential_id),
        )
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

        conn = self._get_conn()
        cursor = conn.cursor()
        if self._vault_version == 2:
            cursor.execute("SELECT id, credential_uuid, service, username, encrypted_password, encrypted_note, created_at FROM credentials ORDER BY service")
        else:
            cursor.execute("SELECT id, service, username, encrypted_password, encrypted_note, created_at FROM credentials ORDER BY service")

        exported = 0
        skipped = []

        # Write to a securely-named temp file, then atomically replace.
        tmp_path = self._secure_temp_file(csv_path.parent, csv_path.suffix)
        try:
            with open(tmp_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(csv_formats.get_export_headers(normalized_format))

                for row in cursor.fetchall():
                    try:
                        password, _note = self._decrypt_credential_fields(row, fernet)
                        writer.writerow(
                            csv_formats.build_export_row(
                                normalized_format,
                                service=row["service"],
                                username=row["username"],
                                password=password,
                                note=_note,
                            )
                        )
                        exported += 1
                    except (InvalidToken, InvalidTag, UnicodeDecodeError):
                        skipped.append({
                            'service': row["service"],
                            'username': row["username"],
                            'error': "Unable to decrypt credential"
                        })

            # Ensure data is flushed to disk before atomic rename.
            fd = os.open(str(tmp_path), os.O_RDONLY)
            os.fsync(fd)
            os.close(fd)

            # Atomic rename (os.replace is atomic on POSIX, fails if
            # destination exists on Windows but that's a minor edge-case).
            os.replace(str(tmp_path), str(csv_path))
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

        # Load existing credentials for duplicate detection (no decryption needed)
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT id, service, username FROM credentials")
        existing_keys = set()
        existing_map = {}  # Maps (service.lower(), username.lower()) -> credential id
        for row in cursor.fetchall():
            key = (row["service"].lower(), row["username"].lower())
            existing_keys.add(key)
            existing_map[key] = row["id"]

        imported = 0
        skipped = 0
        duplicates = []

        # Resource limit: file size
        file_size = csv_path.stat().st_size
        if file_size > _MAX_CSV_FILE_BYTES:
            raise StorageError(
                f"CSV file too large ({file_size} bytes). "
                f"Maximum: {_MAX_CSV_FILE_BYTES} bytes."
            )

        # Wrap the import in a transaction for atomicity
        conn.execute("BEGIN")
        try:
            with open(csv_path, 'r', newline='', encoding='utf-8-sig') as f:
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
                for row_num, row in enumerate(reader, start=2):  # Start at 2 (header is row 1)
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

                    # Row limit
                    if imported + skipped > _MAX_CSV_ROWS:
                        raise StorageError(f"CSV exceeds maximum row count ({_MAX_CSV_ROWS}).")

                    # Field length limits
                    for field_name, value in parsed.items():
                        if len(value.encode('utf-8')) > _MAX_CSV_FIELD_BYTES:
                            raise StorageError(
                                f"Field '{field_name}' in row {row_num} exceeds "
                                f"{_MAX_CSV_FIELD_BYTES} bytes."
                            )

                    service = parsed["service"]
                    username = parsed["username"]
                    password = parsed["password"]
                    note = parsed.get("note", "")

                    # Check for duplicates
                    key = (service.lower(), username.lower())
                    if key in existing_keys:
                        if merge_duplicates and not dry_run:
                            # Update existing credential
                            cred_id = existing_map[key]
                            if self._vault_version == 2:
                                conn_inner = self._get_conn()
                                cur_inner = conn_inner.cursor()
                                cur_inner.execute(
                                    "SELECT credential_uuid FROM credentials WHERE id = ?",
                                    (cred_id,),
                                )
                                cred_uuid_row = cur_inner.fetchone()
                                if cred_uuid_row:
                                    encrypted_password, encrypted_note = self._encrypt_fields_v2(
                                        password, note, cred_uuid_row["credential_uuid"]
                                    )
                                    cursor.execute(
                                        "UPDATE credentials SET encrypted_password = ?, encrypted_note = ?, note_is_hidden = 0 WHERE id = ?",
                                        (encrypted_password, encrypted_note, cred_id)
                                    )
                            else:
                                encrypted_password, encrypted_note = self._encrypt_fields_v1(fernet, password, note)
                                cursor.execute(
                                    "UPDATE credentials SET encrypted_password = ?, encrypted_note = ?, note_is_hidden = 0 WHERE id = ?",
                                    (encrypted_password, encrypted_note, cred_id)
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
                                    password, note, cred_uuid
                                )
                                cursor.execute(
                                    "INSERT INTO credentials (credential_uuid, service, username, encrypted_password, encrypted_note, note_is_hidden) VALUES (?, ?, ?, ?, ?, ?)",
                                    (cred_uuid, service, username, encrypted_password, encrypted_note, 0)
                                )
                            else:
                                fernet = self._require_unlocked()
                                encrypted_password, encrypted_note = self._encrypt_fields_v1(fernet, password, note)
                                cursor.execute(
                                    "INSERT INTO credentials (service, username, encrypted_password, encrypted_note, note_is_hidden) VALUES (?, ?, ?, ?, ?)",
                                    (service, username, encrypted_password, encrypted_note, 0)
                                )
                            existing_map[key] = cursor.lastrowid
                        imported += 1
                        # Add to existing keys to avoid duplicate inserts in the same import
                        existing_keys.add(key)

            if not dry_run:
                conn.commit()
        except BaseException:
            if not dry_run:
                conn.rollback()
            raise

        _log.info("imported %d credentials from %s", imported, csv_path)
        return imported, skipped, duplicates
