# Developer Submission: lockout_persistence

* **Status:** SUBMITTED_FOR_REVIEW
* **Target Module:** Failed-unlock throttling (CWE-307) persistence
* **Worktree Branch:** `feature/generate-it-lockout-persistence` in `wt-generate-it-lockout-persistence`
* **Timestamp:** 2026-08-14 01:50 -0500

## Summary

Failed-unlock throttling is no longer process-local: the attempt counter and wall-clock timestamp are persisted in the vault `config` table, so restarting the application can no longer reset the escalating lockout delays.

## Changes

- `generate_it/storage/core.py`:
  - `get_failed_unlock_state()` → `(attempts, last_failed_at_epoch)` from the `config` table; malformed persisted values raise `StorageError` (fail closed, no silent throttle-disable).
  - `record_failed_unlock(attempts, last_failed_at)` → persists counter + epoch timestamp.
  - `clear_failed_unlock_state()` → removes both keys after successful unlock.
- `generate_it/tui_security.py`:
  - `_now()` — epoch-based clock (was `time.monotonic()`, meaningless across processes).
  - `_load_lockout_state()` — merges persisted state into `AppState` at every unlock attempt (max-of semantics so restart can't lower the counter).
  - `_record_unlock_failure()` persists through `state.storage`; successful unlock clears persisted state.
  - Threshold semantics unchanged and asserted: `[0, 30, 300, 1800, 1800]` (1st immediate, 2nd 30s, 3rd 5min, 4th+ 30min).
- `generate_it/tui_state.py`: updated the stale "process-local" comment.
- Tests: new `tests/test_lockout_persistence.py` (roundtrip across reopen, persist-on-failure/clear-on-success, load-applies-delay, no-vault no-op, epoch timing). Existing mock-based tests updated to configure the new storage API.

## Verification

- Focused lockout/TUI tests: `11 passed`
- Full pytest suite: `514 passed` (was 509)
- Mypy: clean
- Bandit: no issues identified
- Pip-audit: no known vulnerabilities
- `git diff --check`: clean

## Notes

- Persisted values live in the vault's plaintext `config` table (same store as KDF params and app settings), so they are readable pre-unlock — required, since throttling must apply before authentication. A local attacker with write access to the vault file could reset them, which is inherent to any pre-auth throttle; documented behavior.

## Remaining Release-Review Scope

- Pre-existing `type: ignore` annotations remain unchanged (not introduced by remediation).

*End of handoff.*
