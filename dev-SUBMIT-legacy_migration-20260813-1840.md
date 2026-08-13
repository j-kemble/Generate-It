# Developer Submission: legacy_migration

* **Status:** SUBMITTED_FOR_REVIEW
* **Target Module:** Authenticated v1-to-v2 migration and validated re-key
* **Worktree Branch:** `feature/generate-it-legacy-migration` in `wt-generate-it-legacy-migration`
* **Timestamp:** 2026-08-13 18:40 -0500

## 1. Summary of Changes

Legacy v1 migration now verifies the existing password first, then validates the v2 target password. Weak-but-authenticated legacy passwords remain unlockable and require an explicit validated `new_master_password` for migration instead of being stranded or silently re-keyed.

## 2. Impacted Files & Created Modules

* **Modified:** `generate_it/storage/core.py`
* **Created:** `tests/test_legacy_migration_policy.py`

## 3. Pull Request Description Draft (High Signal, No Bloat)

### Overview

The migration path separates legacy authentication from new-password policy validation. Existing callers using a strong password remain compatible; callers migrating a weak legacy password must explicitly provide a strong replacement password.

### Key Changes

- Authenticate legacy v1 credentials using persisted salt/iteration parameters before applying the new password policy.
- Add keyword-only `new_master_password` for explicit re-key migration.
- Derive the v2 KEK from the validated target password.
- Preserve v1 state when authentication or target-password validation fails.
- Add tests for weak legacy unlock, required explicit re-key, successful re-key, and wrong-password rejection.

### Testing & Verification

- [x] Legacy migration regression tests: `3 passed`
- [x] Existing migration tests: `11 passed`
- [x] Full test suite: `455 passed`
- [x] Mypy: `Success: no issues found in 26 source files`
- [x] Pip-audit: no known vulnerabilities found
- [x] `git diff --check` passed
- [x] No error-silencing or hacky typing suppressions were added
- [x] Changes were made in the dedicated `feature/generate-it-legacy-migration` worktree

## 4. Remaining Scope

This submission covers legacy migration authentication/re-key behavior. Documentation reconciliation, storage extraction depth, final package smoke validation, and complete release handoff remain.
