# Developer Submission: logging

* **Status:** SUBMITTED_FOR_REVIEW
* **Target Module:** Logging and sensitive storage-file permissions
* **Worktree Branch:** `feature/generate-it-logging` in `wt-generate-it-logging`
* **Timestamp:** 2026-08-13 18:20 -0500

## 1. Summary of Changes

Hardened log initialization against caller-supplied symlinks and non-regular targets using `lstat`, no-follow opens, and regular-file verification. Logging now retries after failed setup because initialization is latched only after successful handler installation. Required POSIX storage permission failures now raise a `StorageError` instead of being silently logged and ignored.

## 2. Impacted Files & Created Modules

* **Modified:** `generate_it/logging.py`
* **Modified:** `generate_it/storage/core.py`
* **Created:** `tests/test_logging_security_regressions.py`
* **Created:** `tests/test_storage_permissions_regression.py`

## 3. Pull Request Description Draft (High Signal, No Bloat)

### Overview

The logging boundary now rejects existing symlinks/directories, creates/opens only regular files with owner-only permissions, and leaves initialization retryable after an error. Storage permission setup fails closed on POSIX rather than continuing with potentially weaker protection.

### Key Changes

- Added `LoggingError` for secure logging setup failures.
- Added `lstat`, `O_NOFOLLOW` where supported, `open`, and `fstat` checks.
- Delayed `_initialised = True` until handler setup succeeds and cleaned up partial handlers on failure.
- Raised `StorageError` when required POSIX `chmod` operations fail.
- Added regression tests for symlink overwrite prevention, directory targets, retry behavior, permission failures, and existing rotation/mode behavior.

### Testing & Verification

- [x] Focused logging/storage security tests: `24 passed`
- [x] Full test suite: `437 passed`
- [x] Mypy: `Success: no issues found in 26 source files`
- [x] Pip-audit: no known vulnerabilities found
- [x] `git diff --check` passed
- [x] No error-silencing or hacky typing suppressions were added
- [x] Changes were made in the dedicated `feature/generate-it-logging` worktree

## 4. Remaining Scope

This submission covers logging and local permission handling. Legacy migration authentication, generator behavior, lockout/startup handling, and remaining TUI findings remain separate worktree tasks.
