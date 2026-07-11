# Review → Commit Map

Each finding from both 2026-07 security reviews, paired with its fix commit.

## Round 1 Findings

### High

| ID | Finding | Fix | Commit |
|---|---|---|---|
| H1 | CWD wordlist substitution | Removed implicit `./wordlist.txt` discovery; only explicit path or `GENERATE_IT_WORDLIST` env var accepted | `568a14c` |
| H2 | Weak master passwords | 12-char minimum + common-password block enforced in `initialize_vault()`; migration also validates | `0a53302` `581722e` |
| H3 | Cleartext passwords in UI | All password entry masked; vault list shows no passwords; details modal masked by default with `r` toggle | `2211eeb` `602c244` |

### Medium

| ID | Finding | Fix | Commit |
|---|---|---|---|
| M1 | Full vault decrypted in memory | `list_credential_metadata()` metadata-only listing; `get_credential_secret(id)` decrypts one at a time; secret cache cleared in finally-block on modal close | `01d2ec9` `979f684` |
| M2 | Vault/export permissions | Data dir `0700`, vault `0600`, exports `0600`; symlink rejection; atomic temp-file replacement with secure `mkstemp`; predictable temp path attack closed | `df8da7d` `17bc82c` `03d857e` |
| M3 | Clipboard survives lock | `_revoke_clipboard()` clears on lock/exit if unchanged; respects newer user clipboard content | `fe58266` |
| M4 | Ciphertext not bound to row/field | Vault v2: AES-256-GCM AEAD with AAD v2.1 metadata binding (vault UUID + credential UUID + field name + service + username); credential UUID uniqueness enforced | `3e84970` `6031c59` |
| M5 | Security defaults fail-open | Defaults: 30s clipboard auto-clear, 5min auto-lock | `f0a2e4b` |
| M6 | Control chars reach curses | `_sanitize_terminal_text()` applied in `_addstr_safe` AND inside modal primitives (`_run_modal`, `_run_scrollable_modal`); no raw control char bypass | `6476343` `552583e` |
| M7 | CI controls insufficient | Actions pinned to full commit SHAs; blocking security gates; `persist-credentials: false`; TruffleHog pinned; hash-locked constraints enforced; immutable publish pins | `385afa4` `2697654` |
| M8 | Any `v*` tag publishes | Tag validated against `pyproject.toml`; test + security + SCA gates required; OIDC trusted publishing with protected environment; constraints consumed in publish job | `a058a56` `2697654` |

### Low

| ID | Finding | Fix | Commit |
|---|---|---|---|
| L1 | CSV formula injection | README warning; spreadsheet-safe export mode added (prefixes `=`, `+`, `-`, `@` with `'`) | `c67d981` `f75398c` |
| L2 | Export follows symlinks | `export_to_csv()` rejects symlinks and non-regular files; temp path uses `mkstemp` with random name | `17bc82c` `03d857e` |
| L3 | KDF params not validated | Malformed/zero/negative/excessive values rejected; v2 KDF/AEAD config strictly validated before crypto ops | `0415b16` `441949d` |
| L4 | Input resources unbounded | 10MB / 10k-row / 500-byte field limits; transaction rollback; `total_rows` counter before parse guards closes bypass | `a4d5af2` `26e7edc` |
| L5 | Small terminal → invalid windows | Geometry clamped; 20×5 modal minimum; 40×10 app minimum | `861214e` |
| L6 | Encryption docs inaccurate | README: Fernet/AES-128-CBC+HMAC → updated to AES-256-GCM/Argon2id (v2 default); WARP.md: 480k → Argon2id | `3a115d0` `602cc36` |
| L7 | Stale dev dependencies | `pyproject.toml` bounds updated; `cryptography>=44.0.0`; hash-locked constraint files; platform-aware locks including `windows-curses` | `5978793` `3a75570` `2697654` |

### Critical-risk workflow

| ID | Issue | Resolution | Commit |
|---|---|---|---|
| C1 | Gemini WIP gives LLM repo-write + mutation tools | Design doc created; read-only analysis workflow implemented; existing WIP files remain uncommitted | `a3711e4` |

---

## Round 2 Findings (2026-07-11 review)

| ID | Severity | Finding | Fix | Commit |
|---|---|---|---|---|
| F-001 | Medium | Default vaults remain v1, accept ciphertext substitution | Fresh TUI setup routed to `initialize_vault_v2()`; v2+AADv2.1 is now the default | `581722e` `6031c59` |
| F-002 | Medium | Predictable export temp symlink redirects plaintext | Temp files use `mkstemp` with random names; `os.replace` for atomic swap; symlink rejection | `03d857e` |
| F-003 | Medium | v2 UUID+ciphertext record substitution | AAD v2.1 binds service + username metadata; credential UUID uniqueness enforced | `6031c59` |
| F-004 | High | Mutable release tooling in OIDC boundary | Invalid action SHAs repaired; constraints consumed with `--require-hashes`; `--no-isolation` build; Bandit config fixed | `2697654` |
| F-005 | Low | v1→v2 migration accepts empty password | `_validate_master_password()` called in `migrate_v1_to_v2()` | `581722e` |
| F-006 | Low | Modal sanitation bypass | `_sanitize_terminal_text()` moved to `tui_helpers.py`; applied inside `_run_modal` and `_run_scrollable_modal` | `552583e` |
| F-007 | Low | cryptography <44 cannot import Argon2id | `cryptography>=44.0.0` in `pyproject.toml` | `2697654` |
| F-008 | Low | Log files world-readable, contain account metadata | Log dir `0700`, files `0600`; service/username removed from INFO logs | `ad91627` |
| F-009 | Low | v2 KDF/AEAD config not strictly validated | Min/max bounds for Argon2id params; algorithm allowlisting; assert→explicit checks | `441949d` |
| F-010 | Low | Plaintext caches outlive documented scope | `revealed_secret` cleared in finally-block; `state.output` cleared on lock | `979f684` |
| F-011 | Low | Malformed CSV rows bypass row count cap | `total_rows` counter incremented before parse guards; count enforced for all rows | `26e7edc` |
| F-012 | Low | CSV formula injection residual risk | Spreadsheet-safe export mode added; values prefixed with `'` when leading `=`, `+`, `-`, `@` | `f75398c` |
| F-013 | Medium | Windows dependency missing from hash-locked constraints | `windows-curses` added; platform-aware CI selects matching lock file | `2697654` |
| F-014 | Low | Pre-commit hooks use mutable version tags | All 6 hooks pinned to verified 40-char commit SHAs | `a7fa5a9` |

### Untracked risk

| ID | Severity | Issue | Status |
|---|---|---|---|
| U-001 | Critical | Gemini plan-execute gives LLM repo-write + mutation tools | Inactive/untracked; design doc exists (`GEMINI_WORKFLOW_SECURITY_DESIGN.md`); read-only placeholder workflow committed; WIP files must not be staged |

---

## Infrastructure

| Task | Description | Commit |
|---|---|---|
| Test structure | Security regression test modules + shared fixtures | `2a7db37` |
| Entropy floor | 50-bit minimum at 4 words for custom wordlists (~5,800 unique words) | `2e67127` |
| KDF validation | Strict `_read_optional_int_config` replacing silent fallback | `0415b16` |
| Vault v2 spec | 775-line design document: Argon2id, KEK/DEK, AEAD, migration | `d3f4724` |
| Vault v2 impl | `_crypto_v2.py` + storage integration + v1→v2 migration | `3e84970` |
| Vault v2 hardening | Config validation + AAD v2.1 metadata binding + v2 as default | `441949d` `6031c59` `581722e` |
| Gemini design | `GEMINI_WORKFLOW_SECURITY_DESIGN.md` + readonly workflow + validator | `a3711e4` |
| CI hardening | Immutable pins + locked deps + platform locks + pre-commit SHAs | `2697654` `a7fa5a9` |
| Export/import hardening | Secure temp files + row count fix + spreadsheet-safe mode | `03d857e` `26e7edc` `f75398c` |
| Rendering/state hardening | Modal sanitization + plaintext state cleanup + log privacy | `552583e` `979f684` `ad91627` |
| Documentation | Acceptance matrix + review-commit map + claims reconciliation | `85b3c80` `ef2634b` `602cc36` |

## Full commit log

```
602cc36 docs: reconcile security controls with implementation
f75398c feat: add spreadsheet-safe csv export
581722e feat: make hardened vault v2 the default
6031c59 feat: bind vault v2 secrets to credential metadata
441949d fix: validate vault v2 configuration strictly
26e7edc fix: bound all csv import rows
03d857e fix: secure export and migration file creation
a7fa5a9 build: pin contributor hooks immutably
2697654 ci: repair immutable publish action pins, enforce locked gates
979f684 fix: clear plaintext ui state promptly
552583e fix: sanitize all modal rendering
ad91627 fix: keep logs private and metadata free
ad6c2c4 docs: fix stale review-file references in vault v2 spec
ef2634b docs: add review-to-commit mapping, remove stale review files
3a75570 build: add hash-locked ci and release constraint files
a3711e4 docs: add gemini workflow security design and read-only analysis
3e84970 feat: implement vault v2 with Argon2id, KEK/DEK, and AEAD
85b3c80 docs: add security acceptance matrix
a058a56 ci: secure pypi publishing with oidc
3a115d0 docs: align security claims with implementation
5978793 build: constrain audited ci and release dependencies
385afa4 ci: enforce blocking security gates
01d2ec9 refactor: decrypt vault secrets only on demand
d3f4724 docs: specify versioned vault format migration
0415b16 fix: validate persisted kdf parameters strictly
861214e fix: guard modal geometry on small terminals
c67d981 docs: warn about spreadsheet handling of csv exports
a4d5af2 fix: bound and atomically import csv credentials
6476343 fix: sanitize untrusted text before curses rendering
f0a2e4b fix: use secure clipboard and auto-lock defaults
17bc82c fix: create csv exports atomically and privately
fe58266 fix: revoke copied secrets on vault lock
df8da7d fix: enforce private vault file permissions
602c244 fix: mask stored passwords in vault views
2e67127 fix: enforce custom wordlist entropy floor
0a53302 fix: enforce master password policy in storage
2211eeb fix: mask password entry in username save flow
568a14c fix: remove implicit cwd wordlist override
2a7db37 test: add security regression test structure
```
