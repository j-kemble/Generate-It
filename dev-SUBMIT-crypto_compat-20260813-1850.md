# Developer Submission: crypto_compat

* **Status:** SUBMITTED_FOR_REVIEW
* **Target Module:** Crypto migration compatibility and malformed storage records
* **Worktree Branch:** `feature/generate-it-crypto-compat` in `wt-generate-it-crypto-compat`
* **Timestamp:** 2026-08-13 18:50 -0500

## 1. Summary of Changes

Addressed the independent review findings against the earlier crypto-boundaries fix. Legacy v1-to-v2 and AAD migrations now explicitly use the note byte limit for note re-encryption, malformed v2 ciphertext is converted to the existing decryption-error/skip behavior at storage presentation boundaries, and update limit rollback is covered for both vault versions.

## 2. Impacted Files & Created Modules

* **Modified:** `generate_it/storage/core.py`
* **Created:** `tests/test_crypto_compatibility_regressions.py`

## 3. Testing & Verification

- [x] Focused compatibility tests: `5 passed`
- [x] Full test suite: `460 passed`
- [x] Mypy: `Success: no issues found in 26 source files`
- [x] Bandit: no issues identified
- [x] Pip-audit: no known vulnerabilities found
- [x] `git diff --check` passed
- [x] No error-silencing or hacky typing suppressions were added
- [x] Changes were made in the dedicated `feature/generate-it-crypto-compat` worktree

## 4. Findings Addressed

- Existing notes larger than 1,024 bytes but within the 64 KiB note limit can migrate through both v1-to-v2 and AAD migrations.
- Malformed/truncated v2 ciphertext no longer escapes `list_credentials()` or `export_to_csv()` as an unexpected `ValueError`.
- Oversized update attempts for password and note fields leave the existing credential unchanged in both vault versions.
