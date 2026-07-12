# Security Review: Generate-It (Post-Gemini Removal)

> **Date:** 2026-07-12 22:50 UTC
> **Reviewer:** Pip (Hermes Agent)
> **Scope:** System — full review of tracked application code, tests, packaging, CI/release workflows, and documentation after Gemini workflow removal
> **Standards:** OWASP ASVS 5.0 (V1, V2, V5, V6, V11, V13–V16), OWASP Top 10:2025, CWE Top 25:2025, NIST SP 800-115
> **Constraints:** Local, non-destructive dynamic validation only; no remote exploitation
> **Verification:** 357 tests passed · mypy clean · Bandit 7 Low (all false positives) · pip-audit (locked constraints) clean
> **Method:** 3 parallel deep-review subagents (storage/crypto, TUI, CI/CD+generator) + 11 adversarial probes + full local gate

---

## Executive Summary

Generate-It has a hardened default vault format (v2: Argon2id + AES-256-GCM AEAD + KEK/DEK), secure file/export handling (mkstemp, symlink rejection, 0600/0700 permissions), and cryptographically locked CI/release gates. All previous Round 1 and Round 2 findings remain fixed. The Gemini mutation workflows that were the sole latent critical risk have been **fully removed** from the repository — zero Gemini residue confirmed.

This review identified **10 findings** (2 Medium, 7 Low, 1 Info) from adversarial probes and deep code review by 3 parallel subagents. No Critical or High findings.

| Surface | Critical | High | Medium | Low | Informational |
|---|---:|---:|---:|---:|---:|
| Active tracked/runtime | 0 | 0 | 2 | 7 | 1 |
| Gemini workflow residue | 0 | 0 | 0 | 0 | 0 |

---

## System Overview

### Assets
- Stored passwords, notes, generated credentials, plaintext CSV exports
- Master password, derived KEK, unwrapped DEK, legacy Fernet key (v1)
- Service/username metadata
- Clipboard contents, terminal display
- PyPI release identity and published artifacts

### Entry points
- Curses TUI and keyboard input
- Explicit custom wordlist path / `GENERATE_IT_WORDLIST`
- CSV import/export and file picker paths
- SQLite vault file and migration backup
- Git tags and GitHub Actions events

### Trust boundaries
1. User input / imported CSV → generator, storage, curses rendering
2. Master password → KDF → KEK/DEK/Fernet state
3. SQLite file → config/KDF parameters/ciphertext → unlocked process memory
4. Process memory → terminal and system clipboard
5. Plaintext process data → export filesystem path
6. Git tag/repository source → CI build → PyPI OIDC publication

---

## Verification Results

| Check | Result |
|---|---|
| `pytest -p no:cacheprovider -q` | **357 passed** |
| `mypy generate_it/` | **Success** (18 source files) |
| `bandit -c pyproject.toml -r generate_it/ -q` | 7 Low (all false positives) |
| `pip-audit -r constraints/ci.txt --require-hashes` | **No known vulnerabilities** |
| `pip-audit --local` (dev env) | Dev-only advisories (pip, pytest, pygments, requests, urllib3); locked constraints select fixed versions |
| Gemini workflow residue | **None** — all files, .gitignore rules, .trufflehogignore, and code comments removed |
| Adversarial probes (11 probes) | 9 pass, 2 findings (F-015, F-016) |

---

## Adversarial Probe Results

| Probe | Result | Finding |
|---|---|---|
| Fresh vault version (v2) | ✅ `vault_version=2`, `kdf_algorithm=argon2id`, `credential_uuid` column present | — |
| Ciphertext-only swap (v2) | ✅ Both reject with `InvalidTag` | — |
| **UUID + ciphertext swap (v2)** | ❌ **Both swap successfully** — secrets are exchanged | **F-015** |
| Weak master password (v1+v2) | ✅ All rejected with `WeakMasterPasswordError` (short, 123, password, empty) | — |
| Log file permissions | ✅ Log dir `0o700`, log files `0o600`; no service/username in log content | — |
| Export symlink rejection | ✅ Rejected with `StorageError`; victim file untouched | — |
| Vault file permissions | ✅ Vault `0o600`, data dir `0o700` | — |
| KDF parameter validation (0, -1, huge) | ✅ All rejected with `StorageError` | — |
| Algorithm confusion (SM4-GCM, scrypt) | ✅ All rejected with `StorageError` | — |
| **CSV formula injection (generic export)** | ❌ **`=cmd` written raw** — not sanitized | **F-016** |
| Python `-O` (assert removal) | ✅ Vault unlock succeeds normally — no assert-based security checks | — |

---

## Findings

### F-015 — Fresh v2 vaults default to AAD v1, allowing UUID+ciphertext substitution

- **Severity:** Medium
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity)
- **OWASP:** A04:2025 (Cryptographic Failures)
- **ASVS:** V11.3.4 (L3)
- **Location:** `generate_it/storage.py:453` (`initialize_vault_v2`), `storage.py:721` (migration), `_crypto_v2.py:250` (`_make_aad_v1`)
- **Evidence:** `initialize_vault_v2()` writes `("aad_version", "1")` to config. AAD v1 only binds `vault_uuid + credential_uuid + field_name` — not service or username. Adversarial probe: swap both UUID and ciphertext between two credential rows → both decrypt successfully with swapped secrets (`uuid_ciphertext_swap_a = beta-secret`, `uuid_ciphertext_swap_b = alpha-secret`). `migrate_aad_v1_to_v2` exists but has zero call sites in TUI/CLI.
- **Impact:** An attacker with database write access can swap credential UUIDs alongside ciphertexts, causing the wrong secret to be returned for a given service/username label. Could lead to credential confusion or accidental use on wrong services.
- **Likelihood:** Medium — requires local DB write access (malware, backup compromise). Not remotely exploitable.
- **Remediation:** Set `aad_version=2` as default in `initialize_vault_v2` (line 453) and `migrate_v1_to_v2` (line 721). Add a TUI/CLI command to trigger AAD migration for existing vaults. Add test asserting `aad_version=2` for fresh vaults and that UUID+ciphertext swap fails.

### F-016 — CSV formula injection not sanitized on most export formats

- **Severity:** Medium
- **CWE:** CWE-1236 (Improper Neutralization of Special Characters in a Command)
- **OWASP:** A05:2025 (Injection)
- **ASVS:** V1.2.10 (L3)
- **Location:** `generate_it/csv_formats.py:234-235` (generic), `246-258` (bitwarden), `261-268` (apple), `271-294` (nordpass); `storage.py:1214` (default `export_format="generic"`)
- **Evidence:** `build_export_row()` only calls `_escape_formula()` for `spreadsheet-safe` format (line 237-244). All other formats pass raw values. Adversarial probe: store password `=cmd|'/c calc'!A0`, export with `generic` format → raw `=cmd` in CSV output.
- **Impact:** If user exports with any format other than `spreadsheet-safe` and opens in a spreadsheet app, formula injection payloads in stored credentials could execute.
- **Likelihood:** Low-Medium — requires user to select non-safe format AND open in spreadsheet app AND have a credential with formula-triggering first character.
- **Remediation:** Apply `_escape_formula()` to all export formats. The function is already defined and safe to use universally — no user-visible change for non-spreadsheet use.

### F-017 — Vault edit flow crashes with KeyError (cred["password"] not in metadata)

- **Severity:** Medium
- **CWE:** CWE-241 (Improper Handling of Unexpected Data)
- **Location:** `generate_it/tui.py:1351`
- **Evidence:** Edit flow uses `cred["password"]` as `initial_value` for the password modal. But `cred` comes from `list_credential_metadata()` which returns only `id`, `service`, `username`, `created_at` — no `password` key. This raises `KeyError`, which is not caught by the `except StorageError` at line 1397. The edit feature is completely broken.
- **Impact:** Edit credential flow crashes the application. Not a data exposure issue, but a functional security defect — the edit path never loads the decrypted credential via `get_credential_secret()`.
- **Remediation:** Before showing edit modals, call `state.storage.get_credential_secret(cred['id'])` to load the decrypted password and note (as `_run_details_modal` does at line 983). Use the returned secret's fields as initial values.

### F-018 — Unsanitized error text in details modal footer

- **Severity:** Low
- **CWE:** CWE-134 (Use of Externally-Controlled Format Character in Output)
- **Location:** `generate_it/tui.py:1059` (render), `tui.py:1129` (source)
- **Evidence:** The feedback footer is rendered with direct `win.addstr()` at line 1059. `footer_text` can be `feedback_text = f"     ERROR: {str(e)[:20]}    "` (line 1129), where `str(e)` comes from a `StorageError` that may contain user-supplied service/username values with embedded control characters. The string is truncated to 20 chars but NOT passed through `_sanitize_terminal_text()`.
- **Impact:** Control characters in error messages could inject terminal escape sequences (e.g., `\x1b[2J` to clear screen).
- **Remediation:** Route all `win.addstr()` calls in `_run_details_modal` through `R._addstr_safe()` or wrap `feedback_text` with `_sanitize_terminal_text()`.

### F-019 — Filesystem paths rendered without sanitization in file browser/fuzzy picker

- **Severity:** Low
- **CWE:** CWE-134
- **Location:** `generate_it/tui.py:160`, `205`, `272`, `335`
- **Evidence:** Multiple direct `win.addstr()` calls display filesystem-derived strings (directory paths, filenames) without sanitization. A maliciously named file containing terminal escape sequences in its filename could inject them when displayed.
- **Impact:** Low — user must browse to a directory containing such files.
- **Remediation:** Use `R._addstr_safe()` for all filesystem-derived display strings in `_run_fuzzy_file_picker`, `_run_file_browser_modal`, and `_run_path_modal`.

### F-020 — `_sanitize_terminal_text()` doesn't handle Unicode bidi/zero-width characters

- **Severity:** Low
- **CWE:** CWE-134 / CWE-451 (UI Misrepresentation of Information)
- **Location:** `generate_it/tui_helpers.py:12-38`
- **Evidence:** Sanitizer covers C0/C1 control characters but not U+200B-200F (zero-width), U+202A-202F (bidi controls), U+FEFF (BOM). These could be used for homograph/phishing attacks in credential service names.
- **Impact:** Low — in a curses terminal these may render as visible replacement chars or be invisible, but in a password manager context visual verification of service names matters.
- **Remediation:** Extend `_sanitize_terminal_text()` to also replace zero-width and bidi control characters with visible escape sequences, or strip them.

### F-021 — v1→v2 migration doesn't verify password against existing v1 vault

- **Severity:** Low
- **CWE:** CWE-287 (Improper Authentication)
- **Location:** `generate_it/storage.py:584-756` (`migrate_v1_to_v2`)
- **Evidence:** Migration validates password *strength* (line 601) but not *authenticity*. V1 decryption uses the already-in-memory Fernet key from prior `unlock_vault()`, not the `master_password` parameter. The parameter is only used to derive the new v2 KEK. If a caller passes a different password, the migration succeeds and re-keys the vault.
- **Impact:** A malicious actor with momentary access to an unlocked session could silently re-key the vault. Currently no TUI/CLI call site triggers this — only tests use `migrate_v1_to_v2`.
- **Remediation:** Before migration, derive the v1 key from `master_password` and verify the v1 verification token. Raise `InvalidPasswordError` if mismatch.

### F-022 — scrypt KDF accepted in config validation but never implemented

- **Severity:** Low
- **CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **Location:** `generate_it/_crypto_v2.py:56-57` (`KDF_SCRYPT` in `_VALID_KDF_ALGORITHMS`), `_crypto_v2.py:168-190` (`derive_kek` always uses Argon2id)
- **Evidence:** `_validate_kdf_config` accepts scrypt, but `derive_kek` always uses Argon2id. A vault with `kdf_algorithm=scrypt` would unlock successfully (using Argon2id silently), creating a misleading audit trail. When scrypt is in config, Argon2id-specific parameter bounds are skipped.
- **Impact:** Not directly exploitable — Argon2id is always used. But misleading config and future implementation risk.
- **Remediation:** Remove `KDF_SCRYPT` from `_VALID_KDF_ALGORITHMS` until scrypt is implemented in `derive_kek`.

### F-023 — ci-windows.txt is a placeholder — Windows CI will fail

- **Severity:** Low
- **CWE:** CWE-1188 (Insecure Default Initialization)
- **Location:** `constraints/ci-windows.txt:1-12`, referenced by `.github/workflows/security.yml:129`
- **Evidence:** File contains only comments: "This file is a placeholder. CI will fail on Windows until the real lock is generated." `security.yml` runs `pip install --require-hashes -r constraints/ci-windows.txt` on Windows runners — with no packages listed and `--require-hashes`, this will fail.
- **Impact:** Windows CI matrix entries are dead — they cannot pass. No security risk, but CI signal is unreliable.
- **Remediation:** Generate the lockfile on a Windows machine, or remove Windows from the CI matrix until the lock is ready.

### F-024 — Packaged wordlist below custom-wordlist entropy floor (Info)

- **Severity:** Informational
- **CWE:** CWE-330 (Use of Insufficiently Random Values)
- **Location:** `generate_it/generator.py:373-376, 388`
- **Evidence:** Packaged `wordlist.txt` has 1,005 unique words → ~40 bits for a 4-word passphrase. The 50-bit floor (`_MIN_PASSPHRASE_ENTROPY_BITS`) is only enforced for custom wordlists. The packaged wordlist is below the project's own stated minimum.
- **Impact:** Users who don't supply a custom wordlist get ~40 bits of entropy for passphrases. Acceptable for casual use, potentially insufficient for high-value targets.
- **Remediation:** Either expand the packaged wordlist to ≥5,800 words, or document that the default is suitable for casual use and recommend a custom wordlist for high-security scenarios.

---

## Coverage Map

| Area | Result | Notes |
|---|---|---|
| Authorization (V8/A01) | N/A | Local single-user app; symlink protection closes file boundary |
| Validation / business logic (V2) | ✅ Pass | Strong password policy, CSV bounds (10MB/10k rows/500B fields), migration validation |
| Encoding/sanitization (V1/A05) | ⚠️ Partial | Central sanitizer in render + modal primitives; CSV formula injection only in `spreadsheet-safe` (F-016); unsanitized error text in details modal (F-018); filesystem paths unsanitized (F-019); bidi chars not handled (F-020) |
| File handling (V5) | ✅ Pass | `mkstemp` temp, symlink rejection, atomic replace, private modes (0700/0600) |
| Authentication (V6/A07) | ✅ Pass | 12-char minimum, Argon2id 64MiB/3/4, offline oracle expected |
| Cryptography (V11/A04) | ⚠️ Partial | AAD v1 default doesn't bind service+username (F-015); scrypt accepted but not implemented (F-022); nonce random; KEK/DEK split; Argon2id |
| Config/supply chain (V13/V15/A02/A03) | ⚠️ Partial | Hash-locked constraints, platform locks, immutable action pins, OIDC publish all pass; ci-windows.txt is placeholder (F-023) |
| Data protection (V14) | ✅ Pass | On-demand decrypt, clipboard policy, log privacy, state cleanup |
| Logging/errors (V16/A09/A10) | ✅ Pass | No password logging; fail-closed validation; private modes |
| Web/API/session/OAuth | N/A | No network service surface |
| Gemini workflow residue | ✅ Clean | All Gemini files, .gitignore rules, .trufflehogignore, code comments removed |
| SQL injection (V1) | ✅ Pass | All 30+ queries parameterized — no f-strings, .format(), %, or + in any SQL |
| Dangerous sinks | ✅ Pass | No eval/exec/pickle/yaml.load/shell=True/os.system anywhere in generate_it/ |
| Hardcoded secrets | ✅ Pass | No hardcoded credentials, API keys, or tokens |
| CSPRNG | ✅ Pass | `secrets` module used exclusively; no `random` module |
| Assert-based security | ✅ Pass | Zero `assert` statements in storage.py or _crypto_v2.py; all checks use explicit if/raise |

---

## Positive Observations

- CSPRNG (`secrets`/`os.urandom`) used throughout; no `random` module
- v2 uses Argon2id (64 MiB / 3 / 4), AES-KW (RFC 3394), AES-256-GCM / ChaCha20-Poly1305, random 96-bit nonces
- Ciphertext-only swap correctly rejected via `InvalidTag` (AAD v1 binds vault UUID + credential UUID + field name)
- Master-password policy enforced at both v1 and v2 initialization; migration validates
- All 30+ SQL queries parameterized — no injection surface
- Zero `assert`-based security checks — all use explicit `if/raise` patterns surviving `python -O`
- Secure temp-file handling — `tempfile.mkstemp` with `os.chmod(0o600)`, symlink rejection, atomic `os.replace`
- KDF params strictly validated (0, negative, huge values all rejected)
- Algorithm confusion for unknown AEAD/KDF rejected (fail-closed)
- File/dir permissions `0700`/`0600` under umask `022`
- TUI vault lists use metadata-only queries; secrets decrypted on demand
- Password prompts masked; details modal masked by default; explicit `r` reveal
- `revealed_secret` cleared in `finally` block on modal close; `state.output` cleared on vault lock
- Clipboard auto-clear respects newer user content; revoked on lock/exit
- CSV import: 10 MB / 10k rows / 500 B field caps; transaction rollback; `total_rows` counted before parse guards
- Log dir `0700`, files `0600`; no service/username/PII in INFO logs
- All tracked GitHub Actions pinned to 40-char commit SHAs
- Hash-locked constraints with `--require-hashes`; `--no-isolation` build
- OIDC trusted publishing to protected `pypi` environment
- Pre-commit hooks pinned to verified commit SHAs
- `cryptography>=44.0.0` guarantees Argon2id availability
- Gemini workflows fully removed — no LLM mutation surface remains
- No dangerous sinks (eval/exec/pickle/yaml.load/shell=True) anywhere in generate_it/

---

## Residual Risk and Exclusions

- Python cannot reliably zero immutable `str`/`bytes`; review reduces lifetime but does not claim erasure
- Per-field AEAD does not prevent record deletion, rollback, or complete authenticated-record replay without a trusted manifest
- Same-user process with arbitrary code execution can read process memory/clipboard; app reduces exposure but cannot defend full host compromise
- Windows ACL behavior not dynamically measured; POSIX modes do not establish Windows confidentiality
- GitHub protected-environment settings and PyPI trusted-publisher configuration live outside repo; not remotely verified
- Dev-environment pip-audit shows advisories in pip, pytest, pygments, requests, urllib3 — dev-only; locked CI constraints select fixed versions

---

## Methodology

1. Scope locked: System review post-Gemini removal
2. Inventoried tracked files, entry points, assets, trust boundaries
3. Dispatched 3 parallel subagents for deep code review: storage/crypto (13 API calls, 324s), TUI modules (13 API calls, 267s), CI/CD+generator (12 API calls, 161s)
4. Ran full local gate: pytest (357 passed), mypy (clean), bandit (7 Low FP), pip-audit (locked constraints clean)
5. Ran 11 adversarial probes against real product code paths (vault init, ciphertext swap, UUID swap, weak password, log permissions, export symlink, vault permissions, KDF validation, algorithm confusion, CSV formula injection, python -O)
6. Triaged probe results: 9 pass, 2 findings (F-015, F-016)
7. Verified zero Gemini workflow residue (files, .gitignore, .trufflehogignore, code comments)
8. Consolidated subagent findings with probe results; verified each finding against source code

---

## Remediation Plan

Each task is scoped to be a single non-breaking commit on `development`. Tasks are ordered by security impact, with dependencies noted. Tests must be regression-sensitive (not empty shells) and the full local gate must pass after each task.

### Phase 1 — Crypto & Data Integrity (highest impact)

#### Task 1: F-015 — Make AAD v2 the default for fresh and migrated vaults

**Files:** `generate_it/storage.py`, `generate_it/_crypto_v2.py`, `tests/test_crypto_v2.py`, `tests/test_storage.py`, `tests/test_security_storage.py`

**Problem:** `initialize_vault_v2()` writes `aad_version=1` (line 453). `migrate_v1_to_v2()` also writes `aad_version=1` (line 721). AAD v1 doesn't bind service+username, so UUID+ciphertext swaps succeed.

**Steps:**
1. In `initialize_vault_v2()` (storage.py:453): change `("aad_version", "1")` → `("aad_version", "2")`
2. In `migrate_v1_to_v2()` (storage.py:721): change `("aad_version", "1")` → `("aad_version", "2")`. The migration already re-encrypts all credentials with service+username available, so AAD v2 is safe here.
3. Add a TUI-triggered AAD migration for existing v2 vaults still at `aad_version=1`: call `migrate_aad_v1_to_v2()` on unlock if `vault_version == 2` and `aad_version == 1`. Add a confirmation prompt. This auto-upgrades existing users.
4. Add test: fresh vault via `initialize_vault_v2()` has `aad_version=2` in config
5. Add test: UUID+ciphertext swap on fresh v2 vault (aad_version=2) → both reject with `InvalidTag`
6. Add test: v1→v2 migration produces `aad_version=2`
7. Add test: existing v2 vault with `aad_version=1` auto-migrates to `2` on unlock

**Pitfalls:**
- `migrate_aad_v1_to_v2()` must handle the case where there are zero credentials (empty vault) gracefully
- Auto-migration on unlock must not surprise users — add a log message and brief TUI message
- Existing tests that create v2 vaults with `aad_version=1` will need updating — grep for `aad_version` in test files

**Verify:** `pytest -k "aad or v2 or migrate"`, then full gate

---

#### Task 2: F-021 — Verify password authenticity in v1→v2 migration

**Files:** `generate_it/storage.py`, `tests/test_storage.py`

**Problem:** `migrate_v1_to_v2()` validates password strength but not authenticity. V1 decryption uses the in-memory Fernet key, not the provided password. A different password silently re-keys the vault.

**Steps:**
1. Before migration begins (after strength check at line 601), derive the v1 key from `master_password` using the stored v1 salt and PBKDF2 iterations
2. Attempt to decrypt the v1 verification token with the derived key
3. If decryption fails (`InvalidToken`), raise `StorageError("Password does not match existing v1 vault.")`
4. Only proceed with migration if the password authenticates against the existing vault
5. Add test: migration with wrong password raises `StorageError`
6. Add test: migration with correct password succeeds (existing test should still pass)

**Pitfalls:**
- Need access to the v1 salt and iteration count from config — read these before the migration overwrites config
- The v1 Fernet key derivation uses PBKDF2-HMAC-SHA256 — check `_derive_key` or equivalent in storage.py
- Don't break the existing test suite — verify the current migration tests pass the correct password

**Verify:** `pytest -k "migrate"`, then full gate

---

#### Task 3: F-022 — Remove scrypt from allowed KDF algorithms

**Files:** `generate_it/_crypto_v2.py`, `tests/test_crypto_v2.py`

**Problem:** `KDF_SCRYPT` is in `_VALID_KDF_ALGORITHMS` but `derive_kek` always uses Argon2id. scrypt config values skip Argon2id parameter bounds.

**Steps:**
1. Remove `KDF_SCRYPT` from `_VALID_KDF_ALGORITHMS` (line 57)
2. Keep the `KDF_SCRYPT` constant defined (line 56) for future reference, but remove it from the valid set
3. Add test: setting `kdf_algorithm=scrypt` in config → unlock raises `StorageError`
4. Verify existing algorithm confusion test still passes (it already tests `scrypt` → should now expect rejection earlier in the validation chain)

**Pitfalls:**
- The adversarial probe already showed `algo_kdf_algorithm_scrypt` is rejected with `StorageError` — this is because `derive_kek` fails, not because validation rejects it. After this fix, validation itself rejects it with a clearer error.

**Verify:** `pytest -k "kdf or algo or crypto_v2"`, then full gate

---

### Phase 2 — TUI Rendering & Input Safety

#### Task 4: F-017 — Fix vault edit flow (cred["password"] KeyError)

**Files:** `generate_it/tui.py`, `tests/test_security_tui.py`

**Problem:** Edit flow at `tui.py:1351` uses `cred["password"]` but `cred` comes from `list_credential_metadata()` which returns only `id`, `service`, `username`, `created_at`. The edit feature is completely broken.

**Steps:**
1. After the user presses 'E' to edit (line 1321-1323), before showing edit modals, call `state.storage.get_credential_secret(cred['id'])` to load the decrypted password and note
2. Use the returned secret's `password` field as `initial_value` for the password modal (line 1351)
3. Use the returned secret's `note` field as `initial_value` for the note modal (line 1366, replacing `cred.get("note", "")`)
4. Use the returned secret's `note_is_hidden` field (line 1365, replacing `cred.get("note_is_hidden", False)`)
5. Wrap the secret load + edit modal sequence in the existing `try/except StorageError` block
6. Add test: edit flow loads decrypted credential before showing modals
7. Add test: edit flow handles StorageError gracefully when vault is locked

**Pitfalls:**
- The `get_credential_secret()` call must happen while vault is unlocked — the edit handler already checks `state.vault_unlocked`
- Don't leave the decrypted secret in a local variable longer than necessary — it's scoped to the edit block and goes out of scope on continue/return
- The `filtered_credentials` list may be stale after edit — the existing code already refreshes `state.vault_credentials` after save (line 1124)

**Verify:** `pytest -k "edit or vault_modal"`, then full gate

---

#### Task 5: F-018 — Sanitize error text in details modal footer

**Files:** `generate_it/tui.py`

**Problem:** `feedback_text` at line 1129 contains `str(e)` from `StorageError` which may include user-supplied service/username with control characters. Rendered via direct `win.addstr()` at line 1059 — bypasses `_sanitize_terminal_text()`.

**Steps:**
1. At line 1129, wrap the error string: `feedback_text = f"     ERROR: {_sanitize_terminal_text(str(e))[:20]}    "`
   - Or better: replace `win.addstr(box_h - 2, 2, footer_text[:box_w-4], footer_attr)` at line 1059 with `R._addstr_safe(win, box_h - 2, 2, footer_text[:box_w-4], footer_attr)`
2. Audit all other `win.addstr()` calls in `_run_details_modal` (search lines 970-1140) — route any that display user-derived content through `_addstr_safe`
3. Add test: details modal with control chars in error feedback → sanitized in output

**Pitfalls:**
- Import `_sanitize_terminal_text` from `tui_helpers` if not already imported in this scope — check existing imports
- The `_addstr_safe` wrapper also handles curses edge cases (last column, invalid positions) — using it is strictly better than raw `addstr`

**Verify:** `pytest -k "details_modal or sanitize"`, then full gate

---

#### Task 6: F-019 — Sanitize filesystem paths in file browser/fuzzy picker

**Files:** `generate_it/tui.py`

**Problem:** Direct `win.addstr()` calls at lines 160, 205, 272, 335 display filesystem-derived strings (paths, filenames) without sanitization.

**Steps:**
1. Replace `win.addstr(1, 2, f"Root: {root_display}"[:inner_w], theme.dim)` at line 160 with `R._addstr_safe(win, 1, 2, f"Root: {root_display}"[:inner_w], theme.dim)`
2. Replace `win.addstr(content_y + i, 2, line[:inner_w], attr)` at line 205 with `R._addstr_safe(win, content_y + i, 2, line[:inner_w], attr)`
3. Replace `win.addstr(1, 2, _truncate_middle(str(current_dir), inner_w), theme.dim)` at line 272 with `R._addstr_safe(win, 1, 2, _truncate_middle(str(current_dir), inner_w), theme.dim)`
4. Replace `win.addstr(content_y + i, 2, _truncate_middle(label, inner_w), attr)` at line 335 with `R._addstr_safe(win, content_y + i, 2, _truncate_middle(label, inner_w), attr)`
5. Audit all other `win.addstr()` in `_run_fuzzy_file_picker`, `_run_file_browser_modal`, `_run_path_modal` for any displaying user/filesystem-derived content

**Pitfalls:**
- Check that `R` (the render module alias) is imported in scope — look at the imports at top of tui.py
- `_addstr_safe` signature may differ slightly from `win.addstr` — verify it accepts the same (win, y, x, string, attr) pattern

**Verify:** `pytest -k "file_browser or fuzzy or file_picker or tui_smoke"`, then full gate

---

#### Task 7: F-020 — Extend sanitizer for Unicode bidi/zero-width characters

**Files:** `generate_it/tui_helpers.py`, `tests/test_tui_helpers.py`

**Problem:** `_sanitize_terminal_text()` handles C0/C1 controls but not U+200B-200F (zero-width), U+202A-202F (bidi), U+FEFF (BOM).

**Steps:**
1. Add a new range to the sanitizer: U+200B-200F, U+202A-202F, U+FEFF → replace with `?` or strip entirely
2. Add a constant for these ranges at the top of `_sanitize_terminal_text`
3. Add tests: each of the above characters is replaced/stripped
4. Add test: mixed C0 + bidi chars in a single string are all handled
5. Add test: legitimate Unicode (CJK, Cyrillic, emoji) is preserved

**Pitfalls:**
- Stripping vs replacing: stripping is simpler and safer for a password manager (no visual spoofing). But replacing with `?` makes the user aware something was there. Choose strip for zero-width, replace with `?` for bidi overrides.
- Don't over-sanitize — only target the specific code point ranges, not all of Unicode

**Verify:** `pytest -k "sanitize or tui_helpers"`, then full gate

---

### Phase 3 — CSV & Export

#### Task 8: F-016 — Apply formula injection sanitization to all export formats

**Files:** `generate_it/csv_formats.py`, `tests/test_csv_formats.py`

**Problem:** `_escape_formula()` only called for `spreadsheet-safe` format. Generic, bitwarden, apple, nordpass all write raw values.

**Steps:**
1. In `build_export_row()`, apply `_escape_formula()` to every string field in every format branch:
   - `generic` (line 235): wrap service, username, password, note
   - `bitwarden` (lines 247-258): wrap service, username, password, note
   - `apple` (lines 262-268): wrap service, username, password, note
   - `nordpass` (lines 272-294): wrap service, username, password, note
2. The `spreadsheet-safe` branch already applies it — no change needed there
3. Add tests: each export format sanitizes `=cmd|'/c calc'!A0` → prefixed with `'`
4. Add test: formula characters `+`, `-`, `@` as leading chars are also prefixed in all formats
5. Add test: non-formula values are unchanged in all formats

**Pitfalls:**
- Some formats have numeric fields (bitwarden: "0", "1") — only apply to string fields from user data, not hardcoded constants
- The URL field in some formats may legitimately start with `=` — but URLs don't start with `=`, `+`, `-`, `@` in practice

**Verify:** `pytest -k "csv or formula or export"`, then full gate

---

### Phase 4 — CI & Supply Chain

#### Task 9: F-023 — Fix ci-windows.txt placeholder

**Files:** `constraints/ci-windows.txt`, `.github/workflows/security.yml`

**Problem:** `ci-windows.txt` is a placeholder with no packages. Windows CI runs `pip install --require-hashes` against it and will fail.

**Steps:**
1. Option A (preferred): Generate the lockfile properly — `pip-compile --generate-hashes --output-file=constraints/ci-windows.txt constraints/ci-windows.in`. This requires a Windows machine or cross-compilation approach. If not available now, use Option B.
2. Option B (interim): Remove `windows-latest` from the CI matrix in `security.yml` until the lockfile can be generated. Add a comment explaining why.
3. If Option B: add a tracking issue so this doesn't get forgotten

**Pitfalls:**
- If using Option B, ensure the `ci-windows.in` file is kept for future generation
- Don't remove the `ci-windows.in` file — it's the input spec

**Verify:** Full gate (no test impact; CI change only)

---

### Phase 5 — Documentation & Low-Priority

#### Task 10: F-024 — Document packaged wordlist entropy

**Files:** `README.md` or `AGENTS.md`

**Problem:** Packaged wordlist (1,005 words) provides ~40 bits for a 4-word passphrase, below the 50-bit floor enforced for custom wordlists.

**Steps:**
1. Add a note in README.md (passphrase section) or AGENTS.md: "The built-in wordlist provides ~40 bits of entropy for a 4-word passphrase. For high-security scenarios, supply a custom wordlist with at least 5,800 unique words via `GENERATE_IT_WORDLIST` to meet the 50-bit entropy floor."
2. Alternatively, expand the packaged wordlist — but this is a larger task and may not be worth the bloat. Documentation is the KISS approach.

**Verify:** Full gate (documentation only)

---

### Task Dependency Graph

```
Phase 1 (Crypto):
  Task 1 (F-015: AAD v2 default) ──┐
  Task 2 (F-021: migration auth)  ├── All independent, can parallelize
  Task 3 (F-022: remove scrypt)   ──┘

Phase 2 (TUI):
  Task 4 (F-017: edit flow fix) ──┐
  Task 5 (F-018: sanitize error) ├── All independent, can parallelize
  Task 6 (F-019: sanitize paths)  ├── (but all touch tui.py — serialize
  Task 7 (F-020: bidi sanitizer)  ──┘  to avoid merge conflicts)

Phase 3 (CSV):
  Task 8 (F-016: formula all formats) — independent

Phase 4 (CI):
  Task 9 (F-023: ci-windows.txt) — independent

Phase 5 (Docs):
  Task 10 (F-024: wordlist docs) — independent
```

### Parallelization Strategy

Tasks that touch different files can be done in parallel:
- **Group A** (storage/crypto): Tasks 1, 2, 3 — all touch `storage.py`/`_crypto_v2.py`, serialize
- **Group B** (tui.py): Tasks 4, 5, 6 — all touch `tui.py`, serialize. Task 7 touches `tui_helpers.py` only — can parallelize with Group B
- **Group C** (csv_formats.py): Task 8 — independent
- **Group D** (constraints/CI): Task 9 — independent
- **Group E** (docs): Task 10 — independent

Suggested order: A → B → C → D → E, with Task 7 parallel to Group B and Tasks 8/9/10 parallel to each other after Group B.

### Verification Protocol (after each task)

```bash
./.venv/bin/pytest -p no:cacheprovider -q
./.venv/bin/mypy generate_it/
./.venv/bin/bandit -c pyproject.toml -r generate_it/ -q
```

All three must pass before moving to the next task. No stale green — run fresh after every code change.

### Post-remediation probe replay

After all tasks complete, re-run the adversarial probe suite (11 probes). Expected results:
- UUID+ciphertext swap → `InvalidTag` (F-015 fixed)
- CSV formula export (generic) → sanitized (F-016 fixed)
- scrypt algorithm → rejected at validation (F-022 fixed)
- All other probes → unchanged (still pass)
