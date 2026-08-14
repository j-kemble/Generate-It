# Developer Submission: docs

* **Status:** SUBMITTED_FOR_REVIEW
* **Target Module:** Repository guidance and format documentation
* **Worktree Branch:** `feature/generate-it-docs` in `wt-generate-it-docs`
* **Timestamp:** 2026-08-14 01:25 -0500

## Summary

Corrected stale references to the removed monolithic `generate_it/storage.py` module in repository guidance and format documentation, matching the current `generate_it/storage/` package layout.

## Changes

- `AGENTS.md`: "Core logic lives in `generate_it/generator.py` and `generate_it/storage.py`" now points to the `generate_it/storage/` package with its implementation in `generate_it/storage/core.py`.
- `VAULT_FORMAT_V2.md`: the related-documents entry referencing `generate_it/storage.py` now references `generate_it/storage/core.py` and the re-exporting package.

## Remaining Docs Item (Requires User Approval)

The `AGENTS.md` "Storage & Security" section still contains the stale `generate_it/storage.py` reference and the old PBKDF2 wording. The edit was blocked by the protected-file approval prompt (timed out). The intended replacement describes the actual per-vault persisted iteration semantics (480,000 default, 100,000 legacy fallback), the v1/v2 format split, and migration confirmation behavior. No alternative edit path was used.

## Verification

- `git diff --check` passed.
- No production code changed.

*End of handoff.*
