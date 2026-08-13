# Developer Submission: crypto_boundaries

* **Status:** SUBMITTED_FOR_REVIEW
* **Target Module:** Cryptographic field and storage write boundaries
* **Worktree Branch:** `feature/generate-it-crypto-boundaries` in `wt-generate-it-crypto-boundaries`
* **Timestamp:** 2026-08-13 18:16 -0500

## 1. Summary of Changes

Enforced declared UTF-8 plaintext limits for password and note fields across direct v1/v2 storage save/update paths and the v2 encryption primitive. Hardened `decrypt_field()` to reject non-byte and truncated ciphertext before invoking the AEAD backend, with coverage for AES-GCM and ChaCha20-Poly1305.

## 2. Impacted Files & Created Modules

* **Modified:** `generate_it/_crypto_v2.py`
* **Modified:** `generate_it/storage/core.py`
* **Created:** `tests/test_crypto_boundaries.py`
* **Created:** `tests/test_storage_field_limits.py`

## 3. Pull Request Description Draft (High Signal, No Bloat)

### Overview

The declared 1,024-byte password and 64 KiB note limits are now enforced at encryption and storage boundaries using UTF-8 byte counts. Malformed ciphertext now follows a documented, deterministic validation path before the cryptography backend is called.

### Key Changes

- Added configurable plaintext byte-limit validation to `encrypt_field()`.
- Applied password and note limits to v1 and v2 credential encryption plus save/update entry points.
- Added defensive ciphertext type and nonce-plus-tag minimum validation to `decrypt_field()`.
- Added boundary tests for ASCII, multibyte Unicode, both supported AEAD algorithms, malformed input, and both vault versions.

### Testing & Verification

- [x] Boundary tests: `10 passed`
- [x] Crypto/AAD regression tests: `92 passed`
- [x] Full test suite: `427 passed`
- [x] Mypy: `Success: no issues found in 26 source files`
- [x] Bandit: no issues identified
- [x] Pip-audit: no known vulnerabilities found
- [x] `git diff --check` passed
- [x] No error-silencing or hacky typing suppressions were added
- [x] Changes were made in the dedicated `feature/generate-it-crypto-boundaries` worktree

## 4. Remaining Scope

This submission covers the crypto/plaintext-boundary finding. Identity normalization, password-pattern policy, logging hardening, legacy migration authentication, generator behavior, lockout/startup handling, and remaining TUI findings remain separate worktree tasks.
