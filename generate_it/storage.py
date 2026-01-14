import os
import sqlite3
import base64
import csv
from pathlib import Path
from typing import List, Optional, Dict, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from platformdirs import user_data_dir

APP_NAME = "generate-it"
APP_AUTHOR = "j-kemble"

class StorageError(Exception):
    """Base exception for storage errors."""
    pass

class VaultNotInitializedError(StorageError):
    """Raised when attempting to access a vault that doesn't exist."""
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
        return self._db_connection

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derives a url-safe base64-encoded key from the password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def initialize_vault(self, master_password: str) -> None:
        """Sets up the database schema and initializes security markers."""
        salt = os.urandom(16)
        key = self._derive_key(master_password, salt)
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Store configuration
        cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", ("salt", salt))
        cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", ("verification", verification_token))
        
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

        key = self._derive_key(master_password, salt)
        fernet = Fernet(key)

        try:
            decrypted_verification = fernet.decrypt(verification_token)
            if decrypted_verification != b"VERIFICATION_TOKEN":
                raise InvalidPasswordError("Invalid master password.")
        except Exception:
             raise InvalidPasswordError("Invalid master password.")
        
        self._fernet = fernet

    def close(self):
        if self._db_connection:
            self._db_connection.close()
            self._db_connection = None
        self._fernet = None

    def save_credential(self, service: str, username: str, password: str) -> int:
        if not self._fernet:
            raise StorageError("Vault is locked.")

        encrypted_password = self._fernet.encrypt(password.encode())
        
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO credentials (service, username, encrypted_password) VALUES (?, ?, ?)",
            (service, username, encrypted_password)
        )
        conn.commit()
        return cursor.lastrowid

    def list_credentials(self) -> List[dict]:
        """Returns a list of credentials with decrypted passwords."""
        if not self._fernet:
            raise StorageError("Vault is locked.")

        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT id, service, username, encrypted_password, created_at FROM credentials ORDER BY service")
        
        results = []
        for row in cursor.fetchall():
            try:
                password = self._fernet.decrypt(row["encrypted_password"]).decode()
                results.append({
                    "id": row["id"],
                    "service": row["service"],
                    "username": row["username"],
                    "password": password,
                    "created_at": row["created_at"]
                })
            except Exception:
                # If a single password fails to decrypt (corruption?), skip or mark it
                results.append({
                    "id": row["id"],
                    "service": row["service"],
                    "username": row["username"],
                    "password": "<DECRYPTION_ERROR>",
                    "created_at": row["created_at"]
                })
        
        return results

    def delete_credential(self, credential_id: int) -> None:
        if not self._fernet:
            raise StorageError("Vault is locked.")
            
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM credentials WHERE id = ?", (credential_id,))
        conn.commit()

    def export_to_csv(self, csv_path: Path) -> Tuple[int, List[Dict[str, str]]]:
        """Export credentials to CSV file in browser-style format.
        
        Returns:
            Tuple of (exported_count, skipped_rows)
            skipped_rows is a list of dicts with 'service', 'username', 'error' keys
        """
        if not self._fernet:
            raise StorageError("Vault is locked.")

        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT id, service, username, encrypted_password, created_at FROM credentials ORDER BY service")
        
        exported = 0
        skipped = []
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Browser-style format: name, url, username, password, note
            writer.writerow(['name', 'url', 'username', 'password', 'note'])
            
            for row in cursor.fetchall():
                try:
                    password = self._fernet.decrypt(row["encrypted_password"]).decode()
                    # We don't store url or note, so leave them empty
                    writer.writerow([row["service"], '', row["username"], password, ''])
                    exported += 1
                except Exception as e:
                    skipped.append({
                        'service': row["service"],
                        'username': row["username"],
                        'error': str(e)
                    })
        
        return exported, skipped

    def import_from_csv(
        self,
        csv_path: Path,
        merge_duplicates: bool = False,
        dry_run: bool = False,
    ) -> Tuple[int, int, List[Dict[str, str]]]:
        """Import credentials from CSV file.
        
        Accepts flexible column names:
        - Service: name, service, title (case-insensitive)
        - Username: username, login, user
        - Password: password, pass
        - Optional: url, uri, note, notes
        
        Detects duplicates by case-insensitive (service, username) match.
        
        Args:
            csv_path: Path to CSV file
            merge_duplicates: If True, overwrite existing duplicates. If False, skip them.
            dry_run: If True, do not modify the database; just report counts/issues.
        
        Returns:
            Tuple of (imported_count, skipped_count, duplicate_list)
            duplicate_list contains dicts with 'service', 'username', 'reason' keys
        """
        if not self._fernet:
            raise StorageError("Vault is locked.")

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
            
            # Normalize header names (lowercase)
            headers_lower = {h.lower(): h for h in reader.fieldnames}
            
            # Map flexible column names to our fields
            service_col = None
            username_col = None
            password_col = None
            
            for name_variant in ['name', 'service', 'title']:
                if name_variant in headers_lower:
                    service_col = headers_lower[name_variant]
                    break
            
            for user_variant in ['username', 'login', 'user']:
                if user_variant in headers_lower:
                    username_col = headers_lower[user_variant]
                    break
            
            for pass_variant in ['password', 'pass']:
                if pass_variant in headers_lower:
                    password_col = headers_lower[pass_variant]
                    break
            
            if not service_col or not username_col or not password_col:
                missing = []
                if not service_col:
                    missing.append('name/service/title')
                if not username_col:
                    missing.append('username/login/user')
                if not password_col:
                    missing.append('password/pass')
                raise StorageError(f"CSV missing required columns: {', '.join(missing)}")
            
            for row_num, row in enumerate(reader, start=2):  # Start at 2 (header is row 1)
                service = (row.get(service_col) or '').strip()
                username = (row.get(username_col) or '').strip()
                password = (row.get(password_col) or '').strip()
                
                # Skip blank rows
                if not service or not username or not password:
                    skipped += 1
                    duplicates.append({
                        'service': service or '(empty)',
                        'username': username or '(empty)',
                        'reason': f'Row {row_num}: Missing required field(s)'
                    })
                    continue
                
                # Check for duplicates
                key = (service.lower(), username.lower())
                if key in existing_keys:
                    if merge_duplicates and not dry_run:
                        # Update existing credential
                        cred_id = existing_map[key]
                        encrypted_password = self._fernet.encrypt(password.encode())
                        cursor.execute(
                            "UPDATE credentials SET encrypted_password = ? WHERE id = ?",
                            (encrypted_password, cred_id)
                        )
                        conn.commit()
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
                        encrypted_password = self._fernet.encrypt(password.encode())
                        cursor.execute(
                            "INSERT INTO credentials (service, username, encrypted_password) VALUES (?, ?, ?)",
                            (service, username, encrypted_password)
                        )
                        conn.commit()
                        existing_map[key] = cursor.lastrowid
                    imported += 1
                    # Add to existing keys to avoid duplicate inserts in the same import
                    existing_keys.add(key)
        
        return imported, skipped, duplicates
