# Review → Commit Map

Each finding from the 2026-07 security review, paired with its fix commit.

## High

| ID | Finding | Fix | Commit |
|---|---|---|---|
| H1 | CWD wordlist substitution | Removed implicit `./wordlist.txt` discovery; only explicit path or `GENERATE_IT_WORDLIST` env var accepted | `568a14c` |
| H2 | Weak master passwords | 12-char minimum + common-password block enforced in `initialize_vault()` | `0a53302` |
| H3 | Cleartext passwords in UI | All password entry masked; vault list shows no passwords; details modal masked by default with `r` toggle | `2211eeb` `602c244` |

## Medium

| ID | Finding | Fix | Commit |
|---|---|---|---|
| M1 | Full vault decrypted in memory | `list_credential_metadata()` metadata-only listing; `get_credential_secret(id)` decrypts one at a time | `01d2ec9` |
| M2 | Vault/export permissions | Data dir `0700`, vault `0600`, exports `0600`; symlink rejection; atomic temp-file replacement | `df8da7d` `17bc82c` |
| M3 | Clipboard survives lock | `_revoke_clipboard()` clears on lock/exit if unchanged; respects newer user clipboard content | `fe58266` |
| M4 | Ciphertext not bound to row/field | Vault v2: AES-256-GCM AEAD with AAD v2.1 metadata binding (vault UUID + credential UUID + field name + service + username) | `3e84970` `6031c59` |
| M5 | Security defaults fail-open | Defaults: 30s clipboard auto-clear, 5min auto-lock | `f0a2e4b` |
| M6 | Control chars reach curses | `_sanitize_terminal_text()` in `_addstr_safe` escapes C0/C1 controls before rendering | `6476343` |
| M7 | CI controls insufficient | Actions pinned to full commit SHAs; blocking security gates; `persist-credentials: false`; TruffleHog pinned; hash-locked constraints enforced; immutable publish pins | `385afa4` `2697654` |
| M8 | Any `v*` tag publishes | Tag validated against `pyproject.toml`; test + security gates required; OIDC trusted publishing with protected environment | `a058a56` |

## Low

| ID | Finding | Fix | Commit |
|---|---|---|---|
| L1 | CSV formula injection | README warning: don't open raw exports in spreadsheet software | `c67d981` |
| L2 | Export follows symlinks | `export_to_csv()` rejects symlinks and non-regular files | `17bc82c` |
| L3 | KDF params not validated | Malformed/zero/negative/excessive values rejected; min/max bounds enforced | `0415b16` |
| L4 | Input resources unbounded | 10MB file / 10k row / 500-byte field limits; transaction rollback on failure | `a4d5af2` |
| L5 | Small terminal → invalid windows | Geometry clamped; 20×5 modal minimum; 40×10 app minimum | `861214e` |
| L6 | Encryption docs inaccurate | README: Fernet/AES-128-CBC+HMAC; WARP.md: 480k iterations (new vaults) | `3a115d0` |
| L7 | Stale dev dependencies | `pyproject.toml` bounds updated; hash-locked constraint files added | `5978793` `3a75570` |

## Critical-risk workflow

| ID | Issue | Resolution | Commit |
|---|---|---|---|
| C1 | Gemini WIP gives LLM repo-write + mutation tools | Design doc created; read-only analysis workflow implemented; existing WIP files remain uncommitted | `a3711e4` |

## Infrastructure

| Task | Description | Commit |
|---|---|---|
| Test structure | Security regression test modules + shared fixtures | `2a7db37` |
| Entropy floor | 50-bit minimum at 4 words for custom wordlists (~5,800 unique words) | `2e67127` |
| KDF validation | Strict `_read_optional_int_config` replacing silent fallback | `0415b16` |
| Vault v2 spec | 775-line design document: Argon2id, KEK/DEK, AEAD, migration | `d3f4724` |
| Vault v2 impl | `_crypto_v2.py` + storage integration + v1→v2 migration + 50 tests | `3e84970` |
| Gemini design | `GEMINI_WORKFLOW_SECURITY_DESIGN.md` + readonly workflow + validator | `a3711e4` |
| Acceptance matrix | `SECURITY_ACCEPTANCE.md` mapping findings → tests → commits | `85b3c80` |

## Full commit log

```
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
2e1afb7 ci: enforce locked release security gates
b84e4be ci: repair immutable publish action pins
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
