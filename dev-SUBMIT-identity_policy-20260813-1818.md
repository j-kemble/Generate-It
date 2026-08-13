# Developer Submission: identity_policy

* **Status:** SUBMITTED_FOR_REVIEW
* **Target Module:** Canonical identity normalization and master-password predictability policy
* **Worktree Branch:** `feature/generate-it-identity-policy` in `wt-generate-it-identity-policy`
* **Timestamp:** 2026-08-13 18:18 -0500

## 1. Summary of Changes

Canonical identity keys now remove Unicode format characters before storage/indexing/AAD use, so validation and returned keys share one policy. The master-password entropy estimator now rejects exact short-pattern repetition before applying the character-set estimate, preventing long repeated values from passing solely due to length.

## 2. Impacted Files & Created Modules

* **Modified:** `generate_it/identity.py`
* **Modified:** `generate_it/storage/core.py`
* **Created:** `tests/test_identity_policy_regressions.py`

## 3. Pull Request Description Draft (High Signal, No Bloat)

### Overview

The identity canonicalization path now performs one cleanup operation and returns the cleaned keys used for duplicate detection and persistence. Predictable repeated passwords such as 64 copies of `A` and repeated `Ab1!` chunks no longer receive inflated entropy estimates.

### Key Changes

- Remove all Unicode `Cf` format characters from canonical service/username keys.
- Make `validate_identity()` test the canonical returned keys directly.
- Detect exact repeated password patterns before charset-based entropy estimation.
- Add regression tests for embedded zero-width/bidi characters, format-only identities, repeated passwords, and strong password compatibility.

### Testing & Verification

- [x] Focused identity/policy tests: `31 passed`
- [x] Full test suite: `432 passed`
- [x] Mypy: `Success: no issues found in 26 source files`
- [x] Bandit: no issues identified
- [x] Pip-audit: no known vulnerabilities found
- [x] `git diff --check` passed
- [x] No error-silencing or hacky typing suppressions were added
- [x] Changes were made in the dedicated `feature/generate-it-identity-policy` worktree

## 4. Remaining Scope

This submission covers identity normalization and repeated-password policy. Logging hardening, legacy migration authentication, generator behavior, lockout/startup handling, and remaining TUI findings remain separate worktree tasks.
