# Developer Submission: migration_consolidation

* **Status:** SUBMITTED_FOR_REVIEW
* **Target Module:** Identity-schema migration implementation
* **Worktree Branch:** `feature/generate-it-migration-consolidation` in `wt-generate-it-migration-consolidation`
* **Timestamp:** 2026-08-14 01:35 -0500

## Summary

Eliminated the duplicated identity-schema migration implementation: `StorageManager` now delegates all identity-migration paths to the public `generate_it/storage/migration.py` module, which is the single canonical implementation.

## Changes

- `generate_it/storage/core.py` (net −209 lines):
  - `_create_identity_indexes`, `_identity_columns_present`, `_identity_unique_index_present`, `_detect_identity_conflicts`, `_ensure_identity_schema`, `_retry_identity_unique_index`, `_set_identity_conflict`, `_run_identity_migration` are now thin delegation wrappers over `migration.py` functions.
  - Removed the private duplicate implementations of conflict detection, backfill, and index creation.
- `generate_it/storage/migration.py` (canonical home, +28 lines):
  - `retry_identity_unique_index` now recomputes stale canonical keys before checking conflicts (previously only `core.py` did this — drift risk).
  - `run_identity_migration` now cleans up its temporary backup if the final `os.replace` fails (previously only `core.py` had this hardening — drift risk).

## Regression Tests (new)

`tests/test_migration_consolidation.py`:
- `core._ensure_identity_schema` delegates to `migration.ensure_identity_schema` (monkeypatch-proven).
- `migration.retry_identity_unique_index` recomputes stale keys before creating the index.
- `migration.run_identity_migration` cleans the temporary backup when `os.replace` fails.

## Verification

- Focused storage/identity/legacy tests: `18 passed`
- Full pytest suite: `509 passed` (was 506)
- Mypy: clean (26 source files)
- Bandit: no issues identified
- Pip-audit: no known vulnerabilities
- `git diff --check`: clean
- Net diff: 130 insertions / 209 deletions

## Remaining Release-Review Scope

- `storage/v1.py`, `storage/v2.py`, `storage/csv.py` remain compatibility/grouping shells (storage-extraction decision still open).
- Lockout persistence is still process-local (decision pending).
- `type: ignore` annotations pre-exist and are unchanged.

*End of handoff.*
