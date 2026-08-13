# Developer Submission: packaging_migration

* **Status:** SUBMITTED_FOR_REVIEW
* **Target Module:** Packaging boundary and storage migration exception ownership
* **Worktree Branch:** `feature/generate-it-packaging-migration` in `wt-generate-it-packaging-migration`
* **Timestamp:** 2026-08-13 18:12 -0500

## 1. Summary of Changes

Completed the first isolated remediation group from the rejected and security-flagged reviews. The storage package is now discovered and included in built wheels, migration conflict handling uses one canonical exception definition, direct migration-module coverage was added, and CI no longer masks typecheck, whitespace, or primary test failures.

## 2. Impacted Files & Created Modules

* **Created:** `generate_it/constants.py`
* **Created:** `generate_it/exceptions.py`
* **Created:** `generate_it/storage/__init__.py`
* **Created:** `generate_it/storage/core.py` (renamed from `generate_it/storage.py`)
* **Created:** `generate_it/storage/csv.py`
* **Created:** `generate_it/storage/migration.py`
* **Created:** `generate_it/storage/v1.py`
* **Created:** `generate_it/storage/v2.py`
* **Created:** `tests/test_storage_migration_module.py`
* **Modified:** `pyproject.toml`
* **Modified:** `.github/workflows/security.yml`

## 3. Pull Request Description Draft (High Signal, No Bloat)

### Overview

The package boundary now includes all `generate_it.*` runtime packages, including `generate_it.storage`, so clean wheel installations can import the TUI and storage layer. Storage and migration share a canonical `StorageError`/`CredentialIdentityConflictError` owner without introducing a second exception class.

### Key Changes

- Replaced the single-package setuptools list with package discovery for `generate_it*`.
- Moved the storage implementation into the discovered `generate_it.storage.core` package while retaining compatibility re-exports.
- Moved storage domain exceptions into `generate_it.exceptions` and removed the invalid migration import path.
- Added direct migration-module tests for conflict construction and exported helpers.
- Made mypy and trailing-whitespace checks blocking in CI.
- Removed the CI test fallback that could conceal coverage/test-command failures.

### Testing & Verification

- [x] Focused regression tests: `14 passed`
- [x] Full test suite: `417 passed`
- [x] Mypy: `Success: no issues found in 26 source files`
- [x] Bandit: no issues identified
- [x] Pip-audit: no known vulnerabilities found
- [x] `git diff --check` passed
- [x] Wheel inspection confirmed `generate_it/storage/` files are present
- [x] Clean wheel environment imported `generate_it.storage` and `generate_it.tui`
- [x] No error-silencing or hacky typing suppressions were added
- [x] Changes were made in the dedicated `feature/generate-it-packaging-migration` worktree

## 4. Remaining Scope

This submission covers only the packaging/exception/CI gate group. The remaining security and behavioral findings—storage extraction depth, crypto limits, identity policy, logging hardening, legacy migration policy, generator behavior, lockout/startup handling, and TUI safety—remain separate worktree tasks per the remediation plan.
