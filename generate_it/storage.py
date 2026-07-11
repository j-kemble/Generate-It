import os
import sqlite3
import base64
import csv
from pathlib import Path
from typing import List, Literal, Optional, Dict, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from platformdirs import user_data_dir
from . import csv_formats

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

class StorageManager:
    def __init__(self, db_path: Optional[Path] = None):
        if db_path:
            self.db_path = db_path
        else:
            self.data_dir = Path(user_data_dir(APP_NAME, APP_AUTHOR))
            self.data_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = self.data_dir / "vault.db"
        
        self._fernet: Optional[Fernet] = None
        self._db_connection: Optional[sqlite3.Connection] = None

    def _get_conn(self) -> sqlite3.Connection:
        if not self._db_connection:
            self._db_connection = sqlite3.connect(self.db_path)
            self._db_connection.row_factory = sqlite3.Row
            self._db_connection.execute("PRAGMA busy_timeout=5000")
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

    def _read_int_config(self, cursor: sqlite3.Cursor, key: str, default: int) -> int:
        """Read an integer-valued config entry, falling back to `default` if absent."""
        try:
            cursor.execute("SELECT value FROM config WHERE key=?", (key,))
            row = cursor.fetchone()
            if row is None:
                return default
            raw = row["value"]
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            return int(str(raw))
        except (sqlite3.OperationalError, TypeError, ValueError):
            return default

    def _derive_key(self, password: str, salt: bytes, iterations: Optional[int] = None) -> bytes:
        """Derives a url-safe base64-encoded key from the password and salt."""
        iters = iterations if iterations is not None else _DEFAULT_PBKDF2_ITERATIONS
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
        
        # Automatically unlock after initialization
        self._fernet = fernet

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
        """Unlocks the vault with the master password."""
        if not self.vault_exists():
            raise VaultNotInitializedError("Vault not initialized.")

        conn = self._get_conn()
        cursor = conn.cursor()
        
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
        stored_iters = self._read_int_config(cursor, "pbkdf2_iterations", _LEGACY_PBKDF2_ITERATIONS)

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

    def close(self):
        if self._db_connection:
            self._db_connection.close()
            self._db_connection = None
        self._fernet = None

    def __enter__(self) -> "StorageManager":
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> Literal[False]:
        self.close()
        return False

    def _require_unlocked(self) -> Fernet:
        if self._fernet is None:
            raise StorageError("Vault is locked.")
        return self._fernet

    def _decrypt_credential_fields(
        self, row: sqlite3.Row, fernet: Fernet
    ) -> tuple[str, str]:
        """Decrypt password and note from a credential row.

        Raises:
            InvalidToken: if ciphertext is corrupted or tampered with.
            UnicodeDecodeError: if decrypted bytes are not valid UTF-8.
        """
        password = fernet.decrypt(row["encrypted_password"]).decode()
        note = (
            fernet.decrypt(row["encrypted_note"]).decode()
            if row["encrypted_note"]
            else ""
        )
        return password, note

    def _encrypt_credential_fields(
        self, fernet: Fernet, password: str, note: str
    ) -> tuple[bytes, bytes | None]:
        """Encrypt password and note for storage.

        Returns (encrypted_password, encrypted_note).  ``encrypted_note`` is
        ``None`` when *note* is empty, matching the existing storage convention.
        """
        encrypted_password = fernet.encrypt(password.encode())
        encrypted_note = fernet.encrypt(note.encode()) if note else None
        return encrypted_password, encrypted_note

    def save_credential(self, service: str, username: str, password: str, note: str = "", note_is_hidden: bool = False) -> int:
        fernet = self._require_unlocked()

        encrypted_password, encrypted_note = self._encrypt_credential_fields(fernet, password, note)
        
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO credentials (service, username, encrypted_password, encrypted_note, note_is_hidden) VALUES (?, ?, ?, ?, ?)",
            (service, username, encrypted_password, encrypted_note, 1 if note_is_hidden else 0)
        )
        conn.commit()
        return int(cursor.lastrowid or 0)

    def list_credentials(self) -> List[dict]:
        """Returns a list of credentials with decrypted passwords and notes."""
        fernet = self._require_unlocked()

        conn = self._get_conn()
        cursor = conn.cursor()
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
            except (InvalidToken, UnicodeDecodeError):
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

    def update_credential(self, credential_id: int, service: str, username: str, password: str, note: str = "", note_is_hidden: bool = False) -> None:
        """Update an existing credential by id."""
        fernet = self._require_unlocked()

        encrypted_password, encrypted_note = self._encrypt_credential_fields(fernet, password, note)

        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE credentials SET service = ?, username = ?, encrypted_password = ?, encrypted_note = ?, note_is_hidden = ? WHERE id = ?",
            (service, username, encrypted_password, encrypted_note, 1 if note_is_hidden else 0, credential_id),
        )
        if cursor.rowcount == 0:
            raise StorageError(f"Credential with id {credential_id} not found.")
        conn.commit()

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

        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT id, service, username, encrypted_password, encrypted_note, created_at FROM credentials ORDER BY service")
        
        exported = 0
        skipped = []

        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
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
                except (InvalidToken, UnicodeDecodeError):
                    skipped.append({
                        'service': row["service"],
                        'username': row["username"],
                        'error': "Unable to decrypt credential"
                    })
        
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
                        fernet = self._require_unlocked()
                        encrypted_password, encrypted_note = self._encrypt_credential_fields(fernet, password, note)
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
                        fernet = self._require_unlocked()
                        encrypted_password, encrypted_note = self._encrypt_credential_fields(fernet, password, note)
                        cursor.execute(
                            "INSERT INTO credentials (service, username, encrypted_password, encrypted_note, note_is_hidden) VALUES (?, ?, ?, ?, ?)",
                            (service, username, encrypted_password, encrypted_note, 0)
                        )
                        existing_map[key] = cursor.lastrowid
                    imported += 1
                    # Add to existing keys to avoid duplicate inserts in the same import
                    existing_keys.add(key)
        
        conn.commit()
        return imported, skipped, duplicates
