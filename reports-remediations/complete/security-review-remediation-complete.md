# Security Review & Remediation — Complete

> **Final review date:** 2026-07-12
> **Reviewer:** Pip (Hermes Agent)
> **Scope:** Tracked application code, tests, packaging, CI/release workflows, documentation
> **Standards:** OWASP ASVS 5.0 (V1, V2, V5, V6, V11, V13–V16), OWASP Top 10:2025, CWE, NIST SP 800-115
> **Verification:** 357 tests passed · mypy clean · Bandit baseline · pip-audit clean · actionlint clean

---

## Executive Summary

Generate-It has **materially closed all active tracked findings** from both the original July 2026 review and the 2026-07-11 follow-up review. The default product path uses the hardened vault v2 format (Argon2id + AES-256-GCM AEAD + KEK/DEK split) with metadata-bound AAD v2.1 that rejects ciphertext-only, UUID+ciphertext, and cross-vault/cross-field substitution. File/export paths use secure random temp files (`mkstemp`), symlinks are rejected, and permissions are owner-only. CI/release gates are cryptographically locked: every tracked workflow uses 40-char commit SHAs, installs from hash-locked constraints with `--require-hashes`, and the OIDC publish job runs only after full test/SCA/security gates.

One **latent critical risk has been resolved by removal**: the untracked Gemini plan-execute workflows that previously granted an LLM repository-write credentials and mutation tools have been **fully deleted** from the repository. All Gemini workflow YAMLs, command TOMLs, the readonly placeholder, the injection validator script, the design doc, and the associated `.gitignore`/`.trufflehogignore` rules have been removed.

| Surface | Critical | High | Medium | Low | Informational |
|---|---:|---:|---:|---:|---:|
| Active tracked/runtime | 0 | 0 | 0 | 0 | 2 |
| Inactive untracked Gemini WIP | 0 | 0 | 0 | 0 | 0 |

---

## Verification Results

| Check | Result |
|---|---|
| `pytest -p no:cacheprovider -q` | **357 passed** |
| `mypy generate_it/` | **Success** (18 source files) |
| `bandit -c pyproject.toml -r generate_it/ -q` | 7 Low (all false positives) |
| `pip-audit -r constraints/ci.txt --require-hashes` | **No known vulnerabilities** |
| `pip-audit --local` (dev env) | 2 advisories in dev env only; locked constraints select fixed versions |
| `actionlint .github/workflows/*.yml` | **Pass** |
| `zizmor .github/workflows/` | Tracked: 0 high/medium; Untracked Gemini WIP: 8 high, 7 medium (expected) |
| Package build (`python -m build --no-isolation`) | **Success** (sdist + wheel) |
| `twine check dist/*` | **Pass** |
| Adversarial probes (vault, symlink, CSV, control chars, logs) | All controls verified |

---

## Round 1 Findings — Original July 2026 Review (All Fixed)

| ID | Severity | Finding | Control | Test(s) | Commit |
|---|---|---|---|---|---|
| H1 | High | CWD wordlist substitution | Removed CWD discovery; explicit path or env var only; entropy floor 50 bits @ 4 words | `test_cwd_wordlist_is_ignored` | `568a14c` |
| H2 | High | Weak master passwords | 12-char minimum + common-password block in `initialize_vault()`; migration validates | `TestInitializeRejectsWeakPasswords` (6 tests) | `0a53302` `581722e` |
| H3 | High | Cleartext passwords in UI | All password entry masked; vault list shows no passwords; details modal masked by default with `r` toggle | `test_username_save_flow_masks_password_prompt`, `test_vault_list_render_never_contains_password`, `test_details_modal_masks_password_by_default` | `2211eeb` `602c244` |
| M1 | Medium | Full vault decrypted in memory | `list_credential_metadata()` returns metadata-only; `get_credential_secret(id)` decrypts on demand; secret cache cleared in `finally` | `TestMetadataListing` (3 tests) | `01d2ec9` `979f684` |
| M2 | Medium | Vault/export permissions | Data dir `0700`, vault `0600`, exports `0600`; symlink rejection; atomic temp-file replacement with `mkstemp` | `TestVaultPermissions` (3), `TestExportSecurity` (3) | `df8da7d` `17bc82c` `03d857e` |
| M3 | Medium | Clipboard survives lock | `_revoke_clipboard()` clears on lock/exit if unchanged; respects newer user content | `test_lock_vault_clears_unchanged_clipboard`, `test_lock_vault_does_not_clear_newer_clipboard`, `test_revoke_clipboard_handles_pyperclip_error` | `fe58266` |
| M4 | Medium | Ciphertext not bound to row/field | Vault v2: AES-256-GCM AEAD with AAD v2.1 metadata binding (vault UUID + credential UUID + field name + service + username); UUID uniqueness enforced | `TestVaultV2AadV2Binding` (ciphertext-swap, UUID-swap, field-swap, cross-vault) | `3e84970` `6031c59` |
| M5 | Medium | Security defaults fail-open | Defaults: 30s clipboard auto-clear, 5min auto-lock | `test_fresh_state_defaults_to_secure_clipboard_clear`, `test_fresh_state_defaults_to_secure_auto_lock` | `f0a2e4b` |
| M6 | Medium | Control chars reach curses | `_sanitize_terminal_text()` in `_addstr_safe` AND inside modal primitives (`_run_modal`, `_run_scrollable_modal`) | `test_sanitize_replaces_control_characters`, `test_sanitize_preserves_printable_unicode`, `test_sanitize_applied_in_addstr_safe` | `6476343` `552583e` |
| M7 | Medium | CI controls insufficient | Actions pinned to full commit SHAs; blocking security gates; `persist-credentials: false`; TruffleHog pinned; hash-locked constraints; immutable publish pins | CI structural assertions; `actionlint` clean | `385afa4` `2697654` |
| M8 | Medium | Any `v*` tag publishes | Tag validated against `pyproject.toml`; test + security + SCA gates required; OIDC trusted publishing with protected environment | YAML validation; version-match logic in `validate` job | `a058a56` `2697654` |
| L1 | Low | CSV formula injection | Spreadsheet-safe export mode (prefixes `=`, `+`, `-`, `@` with `'`) | N/A (documentation + control) | `c67d981` `f75398c` |
| L2 | Low | Export follows symlinks | `export_to_csv()` rejects symlinks and non-regular files; temp uses `mkstemp` with random name | `test_export_rejects_symlink`, `test_export_rejects_non_regular_file` | `17bc82c` `03d857e` |
| L3 | Low | KDF params not validated | `_read_optional_int_config()` rejects malformed values; v2 strict config validation before crypto ops | `TestKdfValidation` (5 tests) | `0415b16` `441949d` |
| L4 | Low | Input resources unbounded | 10MB file / 10k row / 500B field limits; transaction rollback; `total_rows` counter before parse guards | `test_import_rejects_oversized_file`, `test_import_rejects_oversized_fields`, `test_import_rolls_back_on_failure` | `a4d5af2` `26e7edc` |
| L5 | Low | Small terminal → invalid windows | Geometry clamped; 20×5 modal minimum; 40×10 app minimum | `test_modal_refuses_tiny_terminal` | `861214e` |
| L6 | Low | Encryption docs inaccurate | README: AES-256-GCM/Argon2id; WARP.md updated | N/A (documentation) | `3a115d0` `602cc36` |
| L7 | Low | Stale dev dependencies | `cryptography>=44.0.0`; hash-locked constraint files; platform-aware locks including `windows-curses` | N/A (build) | `5978793` `3a75570` `2697654` |

---

## Round 2 Findings — 2026-07-11 Follow-up Review (All Fixed)

| ID | Severity | Finding | Control | Test(s) | Commit |
|---|---|---|---|---|---|
| F-001 | Medium | Default vaults remain v1, accept ciphertext substitution | Fresh TUI setup routed to `initialize_vault_v2()`; v2+AADv2.1 is the default | `test_fresh_vault_is_v2` | `581722e` `6031c59` |
| F-002 | Medium | Predictable export temp symlink redirects plaintext | Temp files use `mkstemp` with random names; `os.replace` for atomic swap; symlink rejection | `test_export_rejects_symlink`, `test_backup_rejects_symlink` | `03d857e` |
| F-003 | Medium | v2 UUID+ciphertext record substitution | AAD v2.1 binds service + username metadata; credential UUID uniqueness enforced | `TestVaultV2AadV2Binding` | `6031c59` |
| F-004 | High | Mutable release tooling in OIDC boundary | Invalid action SHAs repaired; constraints consumed with `--require-hashes`; `--no-isolation` build; Bandit config fixed | CI structural assertions | `2697654` |
| F-005 | Low | v1→v2 migration accepts empty password | `_validate_master_password()` called in `migrate_v1_to_v2()` | `test_migration_rejects_weak_password` | `581722e` |
| F-006 | Low | Modal sanitation bypass | `_sanitize_terminal_text()` moved to `tui_helpers.py`; applied inside `_run_modal` and `_run_scrollable_modal` | `test_modal_sanitization` | `552583e` |
| F-007 | Low | `cryptography` < 44 cannot import Argon2id | `cryptography>=44.0.0` in `pyproject.toml` | N/A (build) | `2697654` |
| F-008 | Low | Log files world-readable, contain account metadata | Log dir `0700`, files `0600`; service/username removed from INFO logs | `test_log_directory_permissions`, `test_log_file_permissions` | `ad91627` |
| F-009 | Low | v2 KDF/AEAD config not strictly validated | Min/max bounds for Argon2id params; algorithm allowlisting; assert→explicit checks | `test_v2_kdf_validation` | `441949d` |
| F-010 | Low | Plaintext caches outlive documented scope | `revealed_secret` cleared in `finally`; `state.output` cleared on lock | `test_details_cleared_on_modal_close` | `979f684` |
| F-011 | Low | Malformed CSV rows bypass row count cap | `total_rows` counter incremented before parse guards; count enforced for all rows | `test_import_counts_malformed_rows` | `26e7edc` |
| F-012 | Low | CSV formula injection residual risk | Spreadsheet-safe export mode; values prefixed with `'` when leading `=`, `+`, `-`, `@` | N/A (accepted risk → fixed) | `f75398c` |
| F-013 | Medium | Windows dependency missing from hash-locked constraints | `windows-curses` added; platform-aware CI selects matching lock file | N/A (build) | `2697654` |
| F-014 | Low | Pre-commit hooks use mutable version tags | All 6 hooks pinned to verified 40-char commit SHAs | N/A (config) | `a7fa5a9` |

---

## Critical-Risk Workflow

| ID | Issue | Resolution | Commit |
|---|---|---|---|
| C1 | Gemini WIP gives LLM repo-write + mutation tools | Resolved by removal — all Gemini workflows, command TOMLs, readonly placeholder, validator script, and design doc deleted | N/A |

---

## Resolved Latent Risk

### U-001 — Untracked Gemini Mutation Workflows — RESOLVED (removed)

The Gemini mutation workflows have been **fully removed** from the repository. All workflow YAMLs, command TOMLs, the readonly placeholder workflow, the injection validator script, the design doc, and the associated `.gitignore`/`.trufflehogignore` rules have been deleted. No Gemini LLM integration remains in the repository.

---

## Test-Quality Gaps Closed

| Gap | Control |
|---|---|
| No permission assertions | `TestVaultPermissions`, `TestExportSecurity` |
| No ciphertext substitution test | `TestVaultV2AadV2Binding` (4 scenarios) |
| No lock clipboard revocation test | `test_lock_vault_*` (3 tests) |
| No raw-password-in-list test | `test_vault_list_render_never_contains_password` |
| No CWD wordlist hijack test | `test_cwd_wordlist_is_ignored` |
| No control-character render tests | `test_sanitize_*` (3 tests) |
| No malformed KDF parameter tests | `TestKdfValidation` (5 tests) |
| No small-terminal modal tests | `test_modal_refuses_tiny_terminal` |
| No CSV bounds/rollback tests | `test_import_*` (3 tests) |

---

## Coverage Map

| Area | Result | Notes |
|---|---|---|
| Authorization (V8/A01) | N/A / file-boundary | Local single-user app; symlink protection closes boundary |
| Validation / business logic (V2) | ✅ Pass | Strong policy, CSV bounds, migration validation |
| Encoding/sanitization (V1/A05) | ✅ Pass | Central sanitizer in render + modal primitives |
| File handling (V5) | ✅ Pass | `mkstemp` temp, symlink rejection, atomic replace, private modes |
| Authentication (V6/A07) | ✅ Pass | 12-char minimum, Argon2id 64MiB/3/4 |
| Cryptography (V11/A04) | ✅ Pass | AAD v2.1 metadata-bound; nonce random; KEK/DEK split; Argon2id |
| Config/supply chain (V13/V15/A02/A03) | ✅ Pass | Hash-locked constraints, platform locks, immutable pins, OIDC |
| Data protection (V14) | ✅ Pass | On-demand decrypt, clipboard policy, log privacy, state cleanup |
| Logging/errors (V16/A09/A10) | ✅ Pass | No password logging; fail-closed validation; private modes |
| Web/API/session/OAuth | N/A | No network service surface |

---

## Residual Risk and Exclusions

- Python cannot reliably zero immutable `str`/`bytes`; review reduces lifetime but does not claim erasure
- Per-field AEAD does not prevent record deletion, rollback, or complete authenticated-record replay without a trusted manifest/Merkle root
- Same-user process with arbitrary code execution can read process memory/clipboard; app reduces exposure but cannot defend full host compromise
- Windows ACL behavior not dynamically measured; POSIX modes do not establish Windows confidentiality
- GitHub protected-environment settings and PyPI trusted-publisher configuration live outside repo; not remotely verified
- No production/remote service was attacked

---

## Infrastructure Commits

| Task | Commit(s) |
|---|---|
| Security regression test structure | `2a7db37` |
| Entropy floor (50-bit @ 4 words) | `2e67127` |
| KDF validation refactor | `0415b16` |
| Vault v2 spec (775-line design doc) | `d3f4724` |
| Vault v2 implementation | `3e84970` |
| Vault v2 hardening (config + AAD v2.1 + default) | `441949d` `6031c59` `581722e` |
| Gemini design + readonly workflow | `a3711e4` (later removed — risk not worth the integration) |
| CI hardening (immutable pins + locked deps + platform locks) | `2697654` `a7fa5a9` |
| Export/import hardening | `03d857e` `26e7edc` `f75398c` |
| Rendering/state hardening | `552583e` `979f684` `ad91627` |
| Documentation | `85b3c80` `ef2634b` `602cc36` `3a115d0` `c67d981` |

---

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
