# Developer Submission: tui_security

* **Status:** SUBMITTED_FOR_REVIEW
* **Target Module:** TUI unlock, lockout, clipboard, search, and CSV status handling
* **Worktree Branch:** `feature/generate-it-tui-security` in `wt-generate-it-tui-security`
* **Timestamp:** 2026-08-13 18:28 -0500

## 1. Summary of Changes

Unified startup unlock with the guarded unlock helper, added process-local failed-attempt tracking with documented threshold semantics, made AAD migration confirmation affirmative-only, preserved clipboard retry state on backend failure, stopped search input action fall-through, and reported missing CSV imports explicitly.

## 2. Impacted Files & Created Modules

* **Modified:** `generate_it/tui.py`
* **Modified:** `generate_it/tui_csv.py`
* **Modified:** `generate_it/tui_security.py`
* **Modified:** `generate_it/tui_state.py`
* **Modified:** `tests/test_security_tui.py`
* **Created:** `tests/test_tui_lockout_regressions.py`
* **Created:** `tests/test_tui_security_regressions.py`

## 3. Pull Request Description Draft (High Signal, No Bloat)

### Overview

All startup unlock attempts now use the same security policy as post-lock unlocks. Persistent AAD migration requires explicit `y`/`yes`; clipboard cleanup is retryable and truthful; search-mode printable keys cannot invoke destructive/copy actions; and missing import files no longer leave stale success status.

### Key Changes

- Routed startup login through `tui_security._try_unlock_vault()`.
- Added process-local failure count/timestamp tracking and first/second/third/fourth threshold tests.
- Required affirmative AAD confirmation and treated Esc, blank, `n`, and invalid input as cancellation.
- Preserved clipboard tracking through backend failures and cleared tracking only after clear or confirmed user replacement.
- Added `continue` after printable search input.
- Set explicit failure status for missing CSV import paths.

### Testing & Verification

- [x] Focused TUI regression tests: `15 passed`
- [x] Full test suite: `449 passed`
- [x] Mypy: `Success: no issues found in 26 source files`
- [x] Bandit: no issues identified
- [x] Pip-audit: no known vulnerabilities found
- [x] `git diff --check` passed
- [x] No error-silencing or hacky typing suppressions were added
- [x] Changes were made in the dedicated `feature/generate-it-tui-security` worktree

## 4. Remaining Scope

This submission covers the related TUI security/input group. Details-modal geometry/decryption handling, renderer coupling, username-specific settings, and deeper storage extraction remain separate worktree tasks.
