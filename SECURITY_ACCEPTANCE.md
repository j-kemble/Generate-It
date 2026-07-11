# Security Acceptance Matrix

> Generated: 2026-07-11 · 343 tests · mypy clean · Bandit at baseline

Maps every finding from the security review to the implemented control and its regression test(s).
See `review-commit.md` for the commit-level mapping.

## High Severity

| ID | Finding | Control | Test | Commit |
|---|---|---|---|---|
| H1 | Implicit CWD wordlist substitution | Removed CWD discovery; explicit path or env var only | `test_cwd_wordlist_is_ignored` | `568a14c` |
| H2 | Weak master passwords accepted | 12-char minimum enforced in `initialize_vault()` via `_validate_master_password` | `TestInitializeRejectsWeakPasswords` (6 tests) | `0a53302` |
| H3 | Passwords rendered in cleartext | All password entry masked; vault list shows no passwords; details modal masked by default with `r` toggle | `test_username_save_flow_masks_password_prompt`, `test_vault_list_render_never_contains_password`, `test_details_modal_masks_password_by_default` | `2211eeb`, `602c244` |

## Medium Severity

| ID | Finding | Control | Test | Commit |
|---|---|---|---|---|
| M1 | Entire vault decrypted in memory | `list_credential_metadata()` returns metadata-only; `get_credential_secret(id)` decrypts on demand | `TestMetadataListing` (3 tests) | `01d2ec9` |
| M2 | Vault/export permissions not enforced | Data dir 0700, vault 0600, exports 0600; symlink rejection; atomic temp-file replacement | `TestVaultPermissions` (3 tests), `TestExportSecurity` (3 tests) | `df8da7d`, `17bc82c` |
| M3 | Clipboard not cleared on lock | `_revoke_clipboard()` called from `_lock_vault()` and exit paths; compares before clearing | `test_lock_vault_clears_unchanged_clipboard`, `test_lock_vault_does_not_clear_newer_clipboard`, `test_revoke_clipboard_handles_pyperclip_error` | `fe58266` |
| M4 | Ciphertext not bound to row/field | Vault v2: AES-256-GCM AEAD with AAD v2.1 metadata binding (vault UUID + credential UUID + field name + service + username) | `TestVaultV2AadV2Binding` (ciphertext-swap, UUID-swap, field-swap, cross-vault) | `3e84970`, `6031c59` |
| M5 | Security defaults fail-open | Defaults changed: 30s clipboard auto-clear, 5min auto-lock | `test_fresh_state_defaults_to_secure_clipboard_clear`, `test_fresh_state_defaults_to_secure_auto_lock` | `f0a2e4b` |
| M6 | Control characters reach curses unsanitized | `_sanitize_terminal_text()` in `_addstr_safe`; all direct `addstr` calls audited | `test_sanitize_replaces_control_characters`, `test_sanitize_preserves_printable_unicode`, `test_sanitize_applied_in_addstr_safe` | `6476343` |
| M7 | CI security controls insufficient | Actions pinned to full commit SHAs; blocking gates; `persist-credentials: false`; TruffleHog pinned; hash-locked constraints verified; publish workflow actions pinned to immutable commits | Structural assertions in CI YAML; `zizmor` informational-only (tracked workflows); `actionlint` clean | `385afa4`, `2697654` |
| M8 | Any `v*` tag publishes without gates | Tag validates against `pyproject.toml` version; test + security gates required; OIDC trusted publishing with protected environment | YAML validation; version-match logic in `validate` job | `a058a56` |

## Low / Informational

| ID | Finding | Control | Test | Commit |
|---|---|---|---|---|
| L1 | CSV formula injection | Warning in README: "do not open in spreadsheet software" | N/A (documentation) | `c67d981` |
| L2 | Export follows symlinks | `export_to_csv()` rejects symlinks and non-regular files | `test_export_rejects_symlink`, `test_export_rejects_non_regular_file` | `17bc82c` |
| L3 | KDF parameters not validated | `_read_optional_int_config()` rejects malformed values; min/max bounds enforced | `TestKdfValidation` (5 tests) | `0415b16` |
| L4 | Input resources weakly bounded | 10MB file limit, 10k row limit, 500-byte field limit; transaction rollback on failure | `test_import_rejects_oversized_file`, `test_import_rejects_oversized_fields`, `test_import_rolls_back_on_failure` | `a4d5af2` |
| L5 | Small terminal creates invalid windows | Geometry clamped; 20×5 minimum for modals; 40×10 minimum for app | `test_modal_refuses_tiny_terminal` | `861214e` |
| L6 | Encryption documentation inaccurate | README corrected (Fernet/AES-128-CBC+HMAC); WARP.md KDF updated | N/A (documentation) | `3a115d0` |
| L7 | Workspace dependencies need refreshing | pyproject.toml bounds updated | N/A (build) | `5978793` |

## Test-Quality Gaps Closed

| Gap | Control |
|---|---|
| No permission assertions | `TestVaultPermissions`, `TestExportSecurity` |
|| No ciphertext substitution test | `TestVaultV2AadV2Binding` (ciphertext-swap, UUID-swap, field-swap, cross-vault) |
| No lock clipboard revocation test | `test_lock_vault_*` (3 tests) |
| No raw-password-in-list test | `test_vault_list_render_never_contains_password` |
| No CWD wordlist hijack test | `test_cwd_wordlist_is_ignored` |
| No control-character render tests | `test_sanitize_*` (3 tests) |
| No malformed KDF parameter tests | `TestKdfValidation` (5 tests) |
| No small-terminal modal tests | `test_modal_refuses_tiny_terminal` |
| No CSV bounds/rollback tests | `test_import_*` (3 tests) |

## Follow-up Findings (F-001 — F-014)

Remediation-round findings from `SECURITY_REVIEW_2026-07-11.md`, each mapped to its fix.

| ID | Finding | Resolution | Test | Commit |
|---|---|---|---|---|
| F-001 | Default v1 vaults accept ciphertext substitution | v2 made the default (`initialize_vault_v2`); v1 only reachable via explicit migration path | `test_fresh_vault_is_v2` | `581722e` |
| F-002 | Export temp symlink redirects plaintext | Atomic temp-file creation with `mkstemp`; outcome written atomically to final path | `test_export_rejects_symlink`, `test_backup_rejects_symlink` | `03d857e` |
| F-003 | v2 blocks ciphertext-only swaps but not UUID+ciphertext substitution | AAD v2.1 binds service + username into AEAD associated data; metadata changes without re-encryption cause `InvalidTag` | `TestVaultV2AadV2Binding` | `6031c59` |
| F-004 | Mutable release tooling inside OIDC publishing boundary | All publish workflow actions pinned to immutable full-length commit SHAs; hash-locked constraints enforced | CI structural assertions | `2697654` |
| F-005 | v1→v2 migration accepts empty master password | Migration path validates new password against same 12-char policy as initialization | `test_migration_rejects_weak_password` | `581722e` |
| F-006 | Control-character sanitation bypassed by generic modals | All modal rendering paths (generic prompts, scrollable results, confirmation dialogs) routed through `_addstr_safe` | `test_modal_sanitization` | `552583e` |
| F-007 | Declared `cryptography` lower bound cannot import v2 implementation | `pyproject.toml` lower bound bumped to `>=40.0.0`; hash-locked constraints enforce it | N/A (build) | `b84e4be` |
| F-008 | Log files created world-readable with account metadata | Log directory set to `0700`; log files `0600`; rotation preserves private modes; metadata stripped from log output | `test_log_directory_permissions`, `test_log_file_permissions` | `ad91627` |
| F-009 | v2 KDF and algorithm configuration not strictly validated | `_crypto_v2.py` validates KDF parameters (memory, time, parallelism, algorithm) against allowed ranges before unlock | `test_v2_kdf_validation` | `441949d` |
| F-010 | Plaintext caches outlive documented UI scope | Detail-modal plaintext cleared on modal close; lock/exit path clears remaining state | `test_details_cleared_on_modal_close` | `979f684` |
| F-011 | Malformed CSV rows bypass nominal 10,000-row counter | Counter moved after field validation; empty/malformed rows counted before early-continue | `test_import_counts_malformed_rows` | `26e7edc` |
| F-012 | CSV formula injection remains accepted risk | Explicitly accepted residual; strong warning retained in README and documented as accepted risk | N/A (accepted risk) | `c67d981` |
| F-013 | Hash-locked constraints omit Windows-only runtime dependency | `windows-curses` added to `ci.in` and hash-pinned in `ci.txt`; CI matrix covers Windows | N/A (build) | `a7fa5a9` |
| F-014 | Pre-commit hooks execute mutable tags on contributor machines | `.pre-commit-config.yaml` hooks pinned to immutable full-length commit SHAs | N/A (config) | `a7fa5a9` |

## Untracked Risk

| ID | Finding | Status | Document |
|---|---|---|---|
| U-001 | Gemini plan execution gives LLM repo-write + mutation tools | Inactive/untracked; tracked read-only analysis workflow only; design documented | `GEMINI_WORKFLOW_SECURITY_DESIGN.md` |

## Deferred

| Item | Reason | Document |
|---|---|---|
| Gemini full write workflow activation | Requires deterministic privilege separation design and separate approval | `GEMINI_WORKFLOW_SECURITY_DESIGN.md` |

## Verification Commands

```bash
# Full test suite
./.venv/bin/pytest -p no:cacheprovider -q

# Type checking
./.venv/bin/mypy generate_it/

# Security lint
./.venv/bin/bandit -c pyproject.toml -r generate_it/ -q

# Dependency audit
env -u PYTHONPATH ./.venv/bin/pip-audit --local

# CI validation
actionlint .github/workflows/
zizmor .github/workflows/
```
