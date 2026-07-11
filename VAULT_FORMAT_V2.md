# Vault Format v2

## Status: Draft — not yet implemented

This document specifies a versioned, breaking migration of the Generate-It credential vault from Fernet-based encryption (v1) to contextual AEAD with memory-hard key derivation and KEK/DEK key rotation (v2). It is a design document; no code changes are implied until the specification is independently reviewed and explicitly approved.

**Related documents:**

- `SECURITY_REVIEW.md` — findings M4 (unbound ciphertext), M1 (full-vault decryption), H2 (weak KDF)
- `SECURITY_REMEDIATION_PLAN.md` — Phase 4, Task 4.3 (this specification) and Task 4.4 (implementation)
- `generate_it/storage.py` — current v1 `StorageManager` (PBKDF2 + Fernet + SQLite)

---

## 1. Threat Model

### 1.1 Assets Under Protection

- **Master password** — never stored; used only transiently for KEK derivation
- **Credential secrets** — passwords and notes for stored services
- **Key material** — KEK, DEK, and derived keying material
- **Integrity bindings** — the relationship between a credential, its metadata, and its encrypted fields

### 1.2 Adversary Capabilities (In Scope)

| # | Attacker can… | Mitigation |
|---|---------------|------------|
| A1 | Obtain the vault file (stolen disk, backup, sync) | All secrets are encrypted under DEK; DEK is wrapped under KEK derived from master password |
| A2 | Modify ciphertext in the database (swap fields, rows, or substitute old values) | AEAD with associated data binds each ciphertext to vault, credential, field, and format version |
| A3 | Brute-force the master password offline | Argon2id with 64 MiB memory, 3 iterations, 4 lanes makes parallel brute-force expensive |
| A4 | Attempt to downgrade the vault to a weaker format | Version tag in config; unknown versions rejected |
| A5 | Interrupt a migration (crash, power loss) | SQLite transaction + backup; v1 vault remains intact on rollback |
| A6 | Obtain a decrypted credential and attempt to link it to another vault | Credential UUIDs are vault-scoped; associated data binds to vault UUID |

### 1.3 Adversary Capabilities (Out of Scope)

| # | Scenario | Rationale |
|---|----------|-----------|
| O1 | Malware executing as the same user with memory read access | The application must decrypt secrets to use them; no in-process defense against a debugger or `/proc/<pid>/mem` |
| O2 | Physical keyboard logging, TEMPEST, or camera-based shoulder surfing | Hardware/perimeter concerns |
| O3 | Compromised `cryptography` library or Python runtime | Supply-chain integrity is addressed at the release/packaging layer (Phase 5) |
| O4 | Side-channel attacks on AES-GCM in software | The `cryptography` library uses constant-time OpenSSL/BoringSSL primitives where available |
| O5 | Active network adversary | Generate-It has no network surface; credentials are local-only |

### 1.4 Trust Boundaries

```
┌──────────────────────────────────────────────┐
│  User Process (generate-it TUI)              │
│  ┌──────────┐    ┌──────────────────────┐    │
│  │ Master   │───▶│ KEK = Argon2id(pw,   │    │
│  │ Password │    │          salt)        │    │
│  └──────────┘    └──────────┬───────────┘    │
│                             │                 │
│                    ┌────────▼───────────┐    │
│                    │ Wrapped DEK (config│    │
│                    │ table, AES-KW)     │    │
│                    └────────┬───────────┘    │
│                             │                 │
│                    ┌────────▼───────────┐    │
│                    │ DEK (in-memory     │    │
│                    │ only, never on     │    │
│                    │ disk in plaintext) │    │
│                    └────────┬───────────┘    │
│                             │                 │
│                    ┌────────▼───────────┐    │
│                    │ AES-256-GCM        │    │
│                    │ encrypt/decrypt    │    │
│                    │ per-field          │    │
│                    └────────────────────┘    │
└──────────────────────────────────────────────┘
         │                        │
         ▼                        ▼
┌─────────────────┐    ┌──────────────────────┐
│ SQLite vault.db │    │ Plaintext metadata:   │
│ (on disk)       │    │ service, username,    │
│                 │    │ created_at            │
│ - config table  │    │ (searchable without  │
│ - credentials   │    │  decryption)          │
│   table         │    └──────────────────────┘
└─────────────────┘
```

---

## 2. Cryptographic Design

### 2.1 Key Derivation — Argon2id

The Key Encryption Key (KEK) is derived from the master password using Argon2id.

**Parameters:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Algorithm | Argon2id | Resistant to both side-channel and time-memory trade-off attacks |
| Memory | 64 MiB (`memory_cost=65536`) | OWASP 2023 recommendation for password hashing; balances security and startup time |
| Time | 3 iterations (`time_cost=3`) | Sufficient with 64 MiB memory; avoids excessive unlock latency |
| Parallelism | 4 lanes (`parallelism=4`) | Matches common consumer CPU core counts |
| Salt | 32 bytes, random (`os.urandom(32)`) | Unique per vault; prevents precomputation across vaults |
| Output length | 32 bytes (256 bits) | Matches AES-256 key size |
| Hash type | `argon2id` (from `argon2-cffi` or `cryptography.hazmat.primitives.kdf.argon2`) | |

**Alternative:** scrypt (N=2^14, r=8, p=1) may be supported as a secondary option, configured at vault creation. The vault config records which KDF was used and its parameters. At unlock, the stored parameters are honored.

**Rationale for Argon2id over PBKDF2:** The current v1 KDF (PBKDF2-HMAC-SHA256, 480k iterations, 32-byte salt) is GPU-friendly and does not impose a memory cost. Argon2id's memory hardness raises the cost of ASIC/GPU cracking by requiring 64 MiB per guess. This is the primary remediation for SECURITY_REVIEW.md finding H2.

**KDF parameter persistence (same pattern as v1):**

```text
config table:
  kdf_algorithm   = "argon2id" | "scrypt"
  kdf_memory_cost = "65536"       # KiB, Argon2id only
  kdf_time_cost   = "3"           # iterations (Argon2id) or N exponent (scrypt)
  kdf_parallelism = "4"           # Argon2id only
  kdf_salt        = <32 bytes>
```

All parameters are stored at vault creation and honored at unlock. This allows future parameter upgrades without breaking existing vaults.

### 2.2 KEK/DEK Split

**Design:**

- **KEK** (Key Encryption Key, 256 bits): Derived from the master password via Argon2id. Never stored in plaintext. Used only to wrap/unwrap the DEK.
- **DEK** (Data Encryption Key, 256 bits): Randomly generated at vault creation (`os.urandom(32)`). Used to encrypt/decrypt all credential fields. Stored encrypted (wrapped) in the config table.

**Benefits:**

- **Master password change:** Only re-wrap the DEK with the new KEK. No credential re-encryption needed.
- **DEK rotation:** Generate a new DEK, re-encrypt all credentials (full pass), wrap new DEK.
- **KEK never touches credential data directly:** Limits exposure if an implementation bug leaks derived key material.

**Random DEK generation:**

```python
import os
dek = os.urandom(32)  # 256 bits from OS CSPRNG
```

### 2.3 DEK Wrapping

The DEK is wrapped (encrypted) using AES-256 Key Wrap (AES-KW, RFC 3394) with the KEK. AES-KW is chosen over AES-GCM for key wrapping because:

- It provides integrity without requiring nonce management.
- It is a NIST standard (SP 800-38F) designed specifically for key wrapping.
- The `cryptography` library provides `AESKW` via `cryptography.hazmat.primitives.keywrap.aes_key_wrap`.

**Format on disk:**

```text
wrapped_dek = AES-KW(KEK, DEK)  # 40 bytes (32 + 8 integrity)
```

Stored in `config` table as `wrapped_dek` (BLOB, 40 bytes).

**Unwrap at unlock:**

```
KEK  = Argon2id(master_password, salt, params)
DEK  = AES-KW-unwrap(KEK, wrapped_dek)  # raises InvalidUnwrap if wrong KEK
verify DEK by attempting AEAD decrypt of a known verification token
```

**Verification token:** A known plaintext value (`b"VAULT_V2_VERIFICATION_TOKEN"`) encrypted under the DEK with AES-256-GCM and associated data binding to the vault UUID. Stored in config as `verification` (BLOB). If decryption succeeds, the password is correct. This replaces v1's Fernet verification token pattern.

### 2.4 AEAD — AES-256-GCM and ChaCha20-Poly1305

**Primary algorithm:** AES-256-GCM (via `cryptography.hazmat.primitives.ciphers.aead.AESGCM`).

- 256-bit key = DEK
- 96-bit (12-byte) random nonce generated per encryption (`os.urandom(12)`)
- 128-bit authentication tag (appended to ciphertext by the library)

**Alternative:** ChaCha20-Poly1305 (via `cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`) for platforms without AES-NI. Vault config records `aead_algorithm`.

**Nonce strategy:**

- Nonces are random, not sequential.
- 96-bit nonces with a 256-bit key: collision probability is negligible for the expected credential count (< 10,000 credentials, < 2 fields each = < 20,000 encryptions).
- For ChaCha20-Poly1305, the nonce is 96 bits as well (the `cryptography` library uses the IETF variant with 12-byte nonces).

**Nonce reuse detection:** The vault records `dek_generation` (monotonically incrementing integer) and a bitmap or Bloom filter of used nonces for the current DEK generation. If a nonce collision is detected (probability ~2^-64 for 10^4 encryptions), a new DEK is generated (DEK rotation). This is a defense-in-depth measure; the probability is astronomically low in practice.

### 2.5 Associated Data

Each encrypted field binds the following associated data:

| Component | Size | Description |
|-----------|------|-------------|
| `vault_uuid` | 16 bytes | UUID v4, stable for vault lifetime, stored in config |
| `credential_uuid` | 16 bytes | UUID v4, generated when the credential is created, stored in the credentials table |
| `field_name` | variable | UTF-8 string: `"password"` or `"note"` |
| `version` | 2 bytes | `uint16` big-endian: `2` |

**Construction:**

```python
associated_data = b"".join([
    vault_uuid,              # 16 bytes
    credential_uuid,         # 16 bytes
    field_name.encode(),     # "password" (8 bytes) or "note" (4 bytes)
    struct.pack(">H", 2),    # version: 2
])
```

**Rationale for each binding:**

- **vault_uuid:** Prevents copying ciphertext between vaults (different DEKs + different associated data).
- **credential_uuid:** Prevents swapping ciphertext between credentials within the same vault.
- **field_name:** Prevents swapping password and note ciphertext for the same credential.
- **version:** Prevents ciphertext from being interpreted under a different format's scheme.

This directly remediates SECURITY_REVIEW.md finding M4: "Valid ciphertext is not bound to its row, field, or metadata."

**Encrypted field wire format:** The AEAD ciphertext is stored as-is (nonce + ciphertext + tag, concatenated by the library). AES-256-GCM produces:

```text
nonce (12 bytes) || ciphertext (len(plaintext) bytes) || tag (16 bytes)
```

ChaCha20-Poly1305 produces:

```text
nonce (12 bytes) || ciphertext (len(plaintext) bytes) || tag (16 bytes)
```

Both are stored as BLOB in the `encrypted_password` and `encrypted_note` columns.

---

## 3. On-Disk Format

### 3.1 Config Schema Changes

The v2 config table contains the following keys (additions from v1 marked with ★):

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `version` ★ | `"2"` | Yes | Format version; unknown versions rejected at unlock |
| `vault_uuid` ★ | BLOB (16) | Yes | UUID v4, generated at vault creation |
| `kdf_algorithm` ★ | `"argon2id"` or `"scrypt"` | Yes | Key derivation function |
| `kdf_memory_cost` ★ | `"65536"` | Argon2id only | Memory in KiB |
| `kdf_time_cost` ★ | `"3"` | Yes | Iterations or scrypt N |
| `kdf_parallelism` ★ | `"4"` | Argon2id only | Lanes |
| `kdf_salt` ★ | BLOB (32) | Yes | Random salt for KDF |
| `wrapped_dek` ★ | BLOB (40) | Yes | DEK wrapped with KEK via AES-KW |
| `aead_algorithm` ★ | `"aes-256-gcm"` or `"chacha20-poly1305"` | Yes | AEAD cipher |
| `verification` ★ | BLOB | Yes | Known plaintext encrypted under DEK with AEAD + associated data (vault_uuid, zeroed credential UUID, "verification", version=2) |
| `dek_generation` ★ | `"1"` | Yes | Monotonically incrementing counter for DEK rotation |
| `salt` | BLOB (32) | v1 only | **Removed** — replaced by `kdf_salt` |
| `pbkdf2_iterations` | STRING | v1 only | **Removed** — replaced by `kdf_time_cost` |
| `salt_length` | STRING | v1 only | **Removed** — subsumed by `kdf_salt` size |
| `app_setting:*` | BLOB/STRING | No | Application preferences (unchanged from v1) |

**Verification token details:**

```python
verification_plaintext = b"VAULT_V2_VERIFICATION_TOKEN"
verification_associated_data = b"".join([
    vault_uuid,              # 16 bytes
    b"\x00" * 16,            # zeroed credential UUID (sentinel)
    b"verification",          # 10 bytes
    struct.pack(">H", 2),    # version: 2
])
verification_ciphertext = aead.encrypt(
    nonce=os.urandom(12),
    data=verification_plaintext,
    associated_data=verification_associated_data,
)
```

At unlock, decrypt with expected associated data and check plaintext matches `b"VAULT_V2_VERIFICATION_TOKEN"`. If AES-KW unwrap succeeds but verification decryption fails, the password is wrong (or vault is corrupted).

### 3.2 Credential Schema Changes

The v2 credentials table:

```sql
CREATE TABLE credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_uuid BLOB NOT NULL,       -- ★ NEW: 16-byte UUID v4
    service TEXT NOT NULL,               -- plaintext (unchanged)
    username TEXT NOT NULL,              -- plaintext (unchanged)
    encrypted_password BLOB NOT NULL,    -- AEAD ciphertext (format changed)
    encrypted_note BLOB,                 -- AEAD ciphertext (format changed)
    note_is_hidden INTEGER DEFAULT 0,   -- unchanged
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Changes from v1:**

| Column | v1 | v2 |
|--------|----|----|
| `credential_uuid` | Not present | BLOB(16), NOT NULL, UNIQUE |
| `encrypted_password` | Fernet token (base64-encoded BLOB) | AEAD ciphertext (raw BLOB: nonce + ciphertext + tag) |
| `encrypted_note` | Fernet token or NULL | AEAD ciphertext (raw BLOB) or NULL |

**Metadata (plaintext):** `service`, `username`, `created_at`, `note_is_hidden`, `credential_uuid`, and `id` remain in plaintext. This is a deliberate tradeoff:

- These fields are needed for listing, searching, and display without decryption.
- Encrypting them would require decrypting every row for a simple filter or sort, defeating the purpose of Task 4.1 (on-demand decryption).
- An attacker with filesystem access already learns which services the user has accounts with — this is inherent to a local password manager with list/search UX.
- The binding to `credential_uuid` in associated data means that substituting a different `service`/`username` for a ciphertext will cause AEAD decryption to fail (the ciphertext was created with the original credential's UUID).

### 3.3 Encrypted Field Format (Wire Format)

Each encrypted field (password or note) is stored as a single BLOB:

**AES-256-GCM:**

| Offset | Size | Field |
|--------|------|-------|
| 0 | 12 | Nonce (random) |
| 12 | N | Ciphertext (same length as plaintext) |
| 12+N | 16 | Authentication tag |

**ChaCha20-Poly1305:**

| Offset | Size | Field |
|--------|------|-------|
| 0 | 12 | Nonce (random) |
| 12 | N | Ciphertext |
| 12+N | 16 | Authentication tag |

The `cryptography` library's `AESGCM.encrypt()` and `ChaCha20Poly1305.encrypt()` return the concatenation directly, so:

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, struct

aead = AESGCM(dek)
nonce = os.urandom(12)
associated_data = vault_uuid + cred_uuid + b"password" + struct.pack(">H", 2)
ciphertext = aead.encrypt(nonce, plaintext.encode(), associated_data)
# ciphertext is nonce (12) || encrypted (N) || tag (16)
# Store ciphertext directly in the DB
```

Decryption:

```python
# Only the nonce needs to be extracted; the library handles the rest
nonce = ciphertext[:12]
plaintext = aead.decrypt(nonce, ciphertext[12:], associated_data).decode()
```

**Maximum plaintext sizes:** Password ≤ 1024 bytes, Note ≤ 64 KiB (enforced at save time). These are independent of the AEAD overhead.

---

## 4. Migration from v1

### 4.1 Detection

A vault is identified as v1 if the `config` table has no `version` key, OR if the `version` key has value `"1"` (future-proofing: v1 vaults may have the key added retroactively).

```python
def _detect_vault_version(cursor: sqlite3.Cursor) -> int:
    cursor.execute("SELECT value FROM config WHERE key = 'version'")
    row = cursor.fetchone()
    if row is None:
        return 1  # absence of version key → v1
    value = row["value"]
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    try:
        return int(value)
    except (ValueError, TypeError):
        raise StorageError(f"Unrecognized vault version: {value!r}")
```

### 4.2 Migration Procedure

Migration runs on vault unlock when the detected version is 1. The user's master password is already available (they just unlocked the v1 vault).

**Precondition:** Vault is successfully unlocked under v1 scheme (PBKDF2 + Fernet verification token validates).

**Procedure:**

1. **Create backup:** Copy `vault.db` to `vault.db.v1.bak` in the same directory. Verify the copy succeeded (same size, readable).

2. **Begin transaction:** `conn.execute("BEGIN EXCLUSIVE")` to prevent concurrent access during migration.

3. **Generate v2 key material:**
   - Generate `vault_uuid` (UUID v4, 16 bytes)
   - Generate `dek` (32 random bytes)
   - Derive `kek` from the current master password using Argon2id (with v2 parameters: 64 MiB, 3 iterations, 4 lanes, 32-byte salt)
   - Wrap `dek` with `kek` via AES-KW → `wrapped_dek`
   - Initialize AES-256-GCM (or ChaCha20-Poly1305) with `dek`

4. **Add `credential_uuid` column and backfill:**
   ```sql
   ALTER TABLE credentials ADD COLUMN credential_uuid BLOB;
   ```
   For each credential row, generate a UUID v4 and `UPDATE` it.

5. **Re-encrypt all credentials:**
   For each row in `credentials`:
   - Decrypt `encrypted_password` and `encrypted_note` using v1 Fernet
   - Generate fresh nonces
   - Encrypt under v2 AEAD with associated data binding (vault_uuid, credential_uuid, field_name, version=2)
   - `UPDATE` the row with the new ciphertext

6. **Write v2 config:**
   ```sql
   INSERT OR REPLACE INTO config (key, value) VALUES ('version', '2');
   INSERT OR REPLACE INTO config (key, value) VALUES ('vault_uuid', ?);
   INSERT OR REPLACE INTO config (key, value) VALUES ('kdf_algorithm', ?);
   INSERT OR REPLACE INTO config (key, value) VALUES ('kdf_memory_cost', '65536');
   INSERT OR REPLACE INTO config (key, value) VALUES ('kdf_time_cost', '3');
   INSERT OR REPLACE INTO config (key, value) VALUES ('kdf_parallelism', '4');
   INSERT OR REPLACE INTO config (key, value) VALUES ('kdf_salt', ?);
   INSERT OR REPLACE INTO config (key, value) VALUES ('wrapped_dek', ?);
   INSERT OR REPLACE INTO config (key, value) VALUES ('aead_algorithm', ?);
   INSERT OR REPLACE INTO config (key, value) VALUES ('verification', ?);
   INSERT OR REPLACE INTO config (key, value) VALUES ('dek_generation', '1');
   ```

7. **Remove v1 config keys:**
   ```sql
   DELETE FROM config WHERE key IN ('salt', 'pbkdf2_iterations', 'salt_length');
   ```

8. **Commit:** `conn.commit()`

9. **Delete backup (optional, user-configurable):** By default, keep `vault.db.v1.bak` for one unlock cycle. Delete on the next successful unlock if the previous backup is older than the migration timestamp.

**If any step fails:** The transaction is rolled back. The v1 vault is untouched. The backup file remains as an extra safety net.

### 4.3 Crash Safety

Migration is wrapped in a single SQLite transaction with `BEGIN EXCLUSIVE`. SQLite guarantees that:

- Either all changes are committed atomically, or none are.
- A crash during the transaction leaves the database in its pre-transaction state (v1, intact).
- The WAL or rollback journal ensures consistency.

**Additional protections:**

- The `.v1.bak` backup is a safety net independent of the transaction.
- The migration code path catches all exceptions (including `KeyboardInterrupt`) and explicitly rolls back before re-raising.
- A `migration_in_progress` flag is NOT used — it would itself be a durability problem. Instead, the presence of the `version='2'` key is the atomic indicator of migration completion.

### 4.4 Rollback

**Automatic rollback (crash/interrupt):** SQLite transaction rollback restores v1 state. User unlocks again with v1 password; migration retries.

**Manual rollback (user wants to revert to v1):**

1. Close Generate-It.
2. Copy `vault.db.v1.bak` to `vault.db` (overwriting the migrated v2 file).
3. Restart Generate-It. It will detect the v1 vault and unlock normally.

**Backup retention:**

- The `.v1.bak` file persists until the user successfully unlocks the v2 vault at least twice, OR until explicitly deleted.
- The second successful unlock deletes the backup (configurable via `app_setting:keep_v1_backup`).
- This gives the user one full session to verify everything migrated correctly before the v1 backup is removed.

---

## 5. Key Rotation

### 5.1 Master Password Change (DEK Re-Wrap)

Changing the master password does NOT require re-encrypting any credentials.

**Procedure:**

1. User provides current master password → unlock vault normally (KEK → DEK).
2. User provides new master password.
3. Validate new password against master password policy (same as vault creation).
4. Derive new KEK from new password via Argon2id (new `kdf_salt`).
5. Re-wrap DEK with new KEK via AES-KW → new `wrapped_dek`.
6. Update config:
   ```sql
   UPDATE config SET value = ? WHERE key = 'kdf_salt';
   UPDATE config SET value = ? WHERE key = 'wrapped_dek';
   ```
7. Commit transaction.

**Atomicity:** Wrapped in a single transaction. If it fails, the old KEK/DEK pair is still valid and the vault unlocks with the old password.

**Parameter upgrade opportunity:** Master password change is a natural time to upgrade KDF parameters if stronger defaults are available. The new KDF parameters are stored alongside the new salt.

### 5.2 DEK Rotation (Full Re-Encrypt)

DEK rotation generates a new DEK and re-encrypts all credentials. This is needed if:

- A nonce collision is detected (defense-in-depth, astronomically unlikely).
- The user wants to cycle key material (e.g., after a suspected exposure window).
- The AEAD algorithm is upgraded.

**Procedure:**

1. Vault is unlocked normally.
2. Generate new DEK (32 random bytes).
3. Wrap new DEK with existing KEK → new `wrapped_dek`.
4. Increment `dek_generation`.
5. For each credential, decrypt with old DEK, encrypt with new DEK (fresh nonces, same associated data).
6. Update config: `wrapped_dek`, `dek_generation`.
7. Commit transaction.

**Crash safety:** Same transaction approach as migration — single `BEGIN EXCLUSIVE` / `COMMIT`. On rollback, old DEK is still valid.

**Old DEK erasure:** After successful commit, the old DEK reference is overwritten in memory (best-effort; Python does not guarantee secure memory erasure). The old `wrapped_dek` on disk was overwritten by the `UPDATE`.

---

## 6. Test Vectors

Test vectors use the following conventions:

- All hex values are lowercase, no `0x` prefix, no spaces.
- Plaintext strings are UTF-8.
- Associated data is constructed as described in §2.5.

### 6.1 v2 Create and Unlock

**Purpose:** Verify that a freshly created v2 vault can be unlocked with the correct password and rejects a wrong password.

**Test fixture (deterministic):**

```
master_password = "correct-horse-battery-staple-v2"
kdf_salt        = hex:"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
dek             = hex:"101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
```

- Derive KEK: Argon2id(master_password, kdf_salt, memory=65536, time=3, parallelism=4, hash_len=32)
- Wrap DEK with KEK (AES-KW) → `wrapped_dek`
- Create verification token (AES-256-GCM with DEK, associated data as §2.5 verification)
- Write to config: version=2, vault_uuid, kdf_*, wrapped_dek, aead_algorithm, verification, dek_generation=1

**Expected KEK (computed offline):** _To be filled after implementation._
**Expected wrapped_dek:** _To be filled after implementation._

**Unlock tests:**

| Test | Input | Expected |
|------|-------|----------|
| Correct password | `"correct-horse-battery-staple-v2"` | Unlock succeeds; DEK recovered |
| Wrong password | `"wrong-password-v2"` | `InvalidPasswordError` |
| Empty password | `""` | `WeakMasterPasswordError` |
| Tampered wrapped_dek | Modify one byte in config | `StorageError` (AES-KW unwrap fails) |
| Tampered verification | Modify one byte in config | `InvalidPasswordError` |

### 6.2 v1 → v2 Migration

**Purpose:** Verify end-to-end migration of a real v1 vault.

**Setup:** Create a v1 vault with known master password and 3 credentials:

```
master_password = "test-migration-password-12"

Credential 1: service="github.com",  username="alice", password="gh-secret-123"
Credential 2: service="gmail.com",   username="alice", password="gm-secret-456", note="backup email"
Credential 3: service="aws.amazon.com", username="alice", password="aws-secret-789"
```

**Migration test:**

| Step | Assertion |
|------|-----------|
| 1. Unlock v1 vault | Succeeds with v1 password |
| 2. Detect v1 | `_detect_vault_version()` returns 1 |
| 3. Trigger migration | Returns without error |
| 4. Check backup exists | `vault.db.v1.bak` exists, same size as pre-migration v1 DB |
| 5. Check version | `version` key = `"2"` in config |
| 6. Re-open v2 vault | Succeeds with same password |
| 7. List credentials | All 3 credentials present with correct plaintext |
| 8. Verify each field | password matches original, note matches original |

**Migration rollback test:**

| Step | Assertion |
|------|-----------|
| 1. Cause failure mid-migration | Simulate by raising after re-encrypting 1st credential |
| 2. Assert transaction rolled back | v1 vault still opens, all 3 credentials intact |
| 3. Assert backup exists | `.v1.bak` file present |
| 4. Restart migration | Unlock v1 again, migration retries and succeeds |

### 6.3 Associated Data Validation

**Purpose:** Verify that AEAD associated data prevents ciphertext substitution.

**Setup:** v2 vault with two credentials:

```
cred_a: service="github.com", username="alice", password="pass-a"
cred_b: service="gmail.com",  username="alice", password="pass-b"
```

**Substitution tests:**

| # | Tamper | Expected |
|---|--------|----------|
| 1 | Swap `encrypted_password` between cred_a and cred_b | Both fail decryption (`InvalidTag`) |
| 2 | Swap `encrypted_password` with `encrypted_note` for same credential | Both fail decryption (field_name mismatch) |
| 3 | Copy cred_a's `encrypted_password` into a v2 vault with different `vault_uuid` | Fails decryption (vault_uuid mismatch) |
| 4 | Modify `credential_uuid` in DB but keep ciphertext | Fails decryption (credential_uuid mismatch) |
| 5 | Modify `service` in plaintext but keep ciphertext | Fails decryption (credential_uuid unchanged but data now semantically wrong — this is a metadata integrity gap; see §8 Open Questions) |

**Expected behavior on decryption failure:** `InvalidTag` exception from `cryptography` library. The credential is returned with `<DECRYPTION_ERROR>` placeholders (same pattern as v1's `list_credentials()` error handling).

### 6.4 Nonce Uniqueness

**Purpose:** Verify that encryption generates unique nonces.

**Test:** Encrypt the same plaintext ("test") 10,000 times for the same credential UUID, field name "password". Assert all 10,000 nonces (first 12 bytes of each ciphertext) are unique. This validates that `os.urandom(12)` produces no collisions within realistic vault sizes.

---

## 7. Non-Goals

| Non-Goal | Rationale |
|----------|-----------|
| Encrypting `service`/`username` metadata | Needed for listing/search without decryption (Task 4.1). Encrypting them would require decrypting every row for any UI operation. The credential UUID binding in associated data means swapping plaintext metadata without also swapping ciphertext causes AEAD failure. |
| Searchable encryption | Generate-It is a local app; full-table scans are acceptable for the credential count (< 10,000). No need for encrypted indexes. |
| Multi-user / shared vault | Single-user tool. No access control, no key sharing. |
| Network / cloud sync awareness | Local-only. Sync conflicts are out of scope. If a sync tool modifies the database, AEAD integrity checks will detect tampering. |
| Hardware security module (HSM) / TPM integration | Out of scope for a local TUI credential manager. |
| Post-quantum cryptography | Out of scope. AES-256-GCM and Argon2id are not quantum-resistant, but no practical quantum attacks on these primitives exist today. |
| Secure memory erasure in Python | Python strings are immutable and the GC may duplicate them. Best-effort: overwrite bytearrays; do not log secrets; minimize plaintext lifetime. This is documented as a limitation. |
| Non-SQLite backends | SQLite is the only supported storage backend. |

---

## 8. Open Questions

### 8.1 Metadata Integrity: Authenticate service/username?

**Current design:** `service` and `username` remain plaintext and are NOT included in the AEAD associated data. An attacker with write access to the DB could:

1. Copy `encrypted_password` from credential A to credential B.
2. Also copy credential A's `credential_uuid` to credential B's row.
3. This WOULD pass AEAD decryption (associated data matches), but the `service`/`username` would be B's values — the user sees the wrong service for credential A's password.

**Options:**

- **Option A (current):** Accept this as out of scope. The credential UUID binding prevents naive field-swapping. An attacker who can modify both the UUID and the ciphertext has write access to the vault file, which implies a level of compromise where they could also just read the decrypted values after the user unlocks.
- **Option B:** Include `service` and `username` in associated data. This means the metadata also cannot be changed without re-encryption. Updates to service/username would require decrypt+re-encrypt with new associated data (acceptable cost).
- **Option C:** Add a row-level HMAC or AEAD tag over `(service, username, credential_uuid)` using a sub-key derived from DEK.

**Recommendation:** Option B — include `service` and `username` in associated data. The re-encryption on metadata update is trivial (one field per update) and the integrity gain is worth it.

### 8.2 Row Deletion / Rollback Detection

**Question:** Should the vault detect that a credential was deleted and later restored from a stale backup (rollback attack)?

**Background:** An attacker with filesystem access could:
1. Copy a credential ciphertext and row data.
2. Wait for the user to delete that credential.
3. Restore the old row from the backup copy.

**Options:**

- **Option A:** Do not detect. This is a niche threat for a local password manager — the attacker needs write access to the vault AND knowledge of the user's deletion patterns.
- **Option B:** Add a `version_counter` or `tree_id` per credential, monotonically incremented. Track the highest seen counter in config. On restore, stale counters are detected.
- **Option C:** Use a global `vault_generation` counter that increments on every mutation. Each credential records its creation generation. Detect mismatches.

**Recommendation:** Defer to v2.1. This adds complexity (counter management, tombstone tracking) for a threat that requires the attacker to have both read and write access to the vault over time. Document the limitation.

### 8.3 DEK Wrapping Algorithm

**Current choice:** AES-256 Key Wrap (AES-KW, RFC 3394).

**Alternative:** AES-256-GCM with a fixed/nil nonce and associated data. This is simpler (reuses the same AEAD primitive) but AES-KW is purpose-built for key wrapping and doesn't require nonce management for a single key.

**Recommendation:** Keep AES-KW. It's the standard choice for key wrapping and avoids any risk of nonce reuse in the key-wrapping layer.

### 8.4 Nonce Reuse Detection Detail

**Question:** Is explicit nonce collision detection worth implementing?

**Analysis:** With 96-bit random nonces, the birthday bound for 50% collision probability is ~2^48 encryptions. For a vault with 10,000 credentials × 2 fields = 20,000 encryptions, collision probability is ~(20,000²)/(2×2^96) ≈ 5×10^-20. This is negligible.

**Recommendation:** Skip explicit detection. Include a comment in the implementation noting that `dek_generation` exists for manual DEK rotation; if a nonce collision is ever suspected, increment `dek_generation` and re-encrypt. The test vector in §6.4 validates uniqueness empirically.

### 8.5 Upgrade In-Place vs. New Vault

**Question:** Should migration modify the existing `vault.db` in place, or create a new `vault.v2.db` and leave v1 untouched?

**Current design:** In-place migration with backup. This avoids:
- Two copies of the vault (v1 + v2) that could diverge after migration.
- Confusion about which file is "current."
- Having to replicate app settings.

The `.v1.bak` backup serves as the rollback path.

**Recommendation:** Keep in-place migration. It's simpler and the backup provides an adequate rollback mechanism.

### 8.6 Argon2id Library Dependencies

**Options:**

1. `argon2-cffi` package (pure Python bindings to C Argon2 reference implementation)
2. `cryptography.hazmat.primitives.kdf.argon2` (requires `cryptography` ≥ 40.0.0, uses OpenSSL ≥ 3.2 or BoringSSL)

**Recommendation:** Use `cryptography`'s built-in Argon2 support if the minimum `cryptography` version can be bumped to ≥ 40.0.0. This avoids an additional dependency. If not, fall back to `argon2-cffi`.

### 8.7 Should `id` (AUTOINCREMENT) be Removed in Favor of `credential_uuid`?

**Question:** v2 adds `credential_uuid` (UUID v4). Should `id` (INTEGER PRIMARY KEY AUTOINCREMENT) be removed?

**Analysis:** `id` is used for:
- Foreign key references (none exist currently).
- Ordering (list credentials ORDER BY service, not by id).
- User-facing display (not exposed).

`credential_uuid` is used for:
- AEAD associated data binding.
- Stable cross-backup identity.

**Recommendation:** Keep both. `id` is the SQLite row identifier (useful for internal operations). `credential_uuid` is the cryptographic identity. Removing `id` would require refactoring all internal references for no security benefit.

---

## Appendix A: Dependency Changes

| Dependency | v1 | v2 | Purpose |
|------------|----|----|---------|
| `cryptography` | Any (PBKDF2, Fernet) | ≥ 40.0.0 (Argon2id, AES-GCM, ChaCha20-Poly1305, AES-KW) | Core crypto |
| `argon2-cffi` | Not used | Optional fallback | Argon2id if `cryptography` < 40.0.0 |
| `platformdirs` | Yes | Yes (unchanged) | Vault path |

## Appendix B: Constants Summary

```python
# Key sizes
DEK_SIZE = 32          # bytes (256 bits)
KEK_SIZE = 32          # bytes (256 bits)
VAULT_UUID_SIZE = 16   # bytes (UUID v4)
CREDENTIAL_UUID_SIZE = 16  # bytes (UUID v4)
WRAPPED_DEK_SIZE = 40  # bytes (32 + 8 AES-KW overhead)

# AEAD
GCM_NONCE_SIZE = 12    # bytes (96 bits)
GCM_TAG_SIZE = 16      # bytes (128 bits, appended by library)
CHACHA_NONCE_SIZE = 12 # bytes (96 bits, IETF variant)
CHACHA_TAG_SIZE = 16   # bytes (128 bits)

# Argon2id
ARGON2_MEMORY_COST = 65536  # KiB (64 MiB)
ARGON2_TIME_COST = 3        # iterations
ARGON2_PARALLELISM = 4      # lanes
ARGON2_SALT_SIZE = 32       # bytes

# Limits
MAX_PASSWORD_BYTES = 1024   # plaintext password max
MAX_NOTE_BYTES = 64 * 1024  # 64 KiB plaintext note max

# Version
VAULT_VERSION = 2           # this specification
```

## Appendix C: Comparison with v1

| Feature | v1 | v2 |
|---------|----|----|
| KDF | PBKDF2-HMAC-SHA256 (480k iters) | Argon2id (64 MiB, 3 iters, 4 lanes) |
| Memory hardness | None | 64 MiB per guess |
| Encryption | Fernet (AES-128-CBC + HMAC-SHA256) | AES-256-GCM or ChaCha20-Poly1305 |
| Key model | Single key = PBKDF2(master_password) | KEK = Argon2id(master_password), DEK = random, wrapped under KEK |
| Master password change | Not supported (full re-init required) | Re-wrap DEK (no credential re-encryption) |
| Associated data binding | None | vault_uuid, credential_uuid, field_name, version |
| Ciphertext swapping | Undetected | Detected (AEAD authentication failure) |
| Credential identity | `id` (AUTOINCREMENT, not cryptographically bound) | `credential_uuid` (UUID v4, used in AEAD associated data) |
| Metadata | Plaintext service, username, created_at | Same (with integrity binding under discussion, §8.1) |
| Migration | N/A (v1 is the baseline) | Single transaction, crash-safe, with backup |
| Unknown version handling | N/A | Rejected with clear error message |
| Key size | 128-bit (AES-128) | 256-bit (AES-256, DEK) |
