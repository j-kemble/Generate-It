# Developer Submission: docs

* **Status:** SUBMITTED_FOR_REVIEW
* **Target Module:** Repository guidance and format documentation
* **Worktree Branch:** `feature/generate-it-docs` in `wt-generate-it-docs`
* **Timestamp:** 2026-08-14 01:30 -0500

## Summary

Corrected stale references to the removed monolithic `generate_it/storage.py` module in repository guidance and format documentation, matching the current `generate_it/storage/` package layout, and documented actual vault/KDF semantics.

## Changes

- `AGENTS.md`: "Core logic lives in `generate_it/generator.py` and `generate_it/storage.py`" now points to the `generate_it/storage/` package with its implementation in `generate_it/storage/core.py`.
- `AGENTS.md` "Storage & Security" section (user-approved):
  - Replaces the `generate_it/storage.py` reference with the `generate_it/storage/core.py` package layout.
  - Documents v1 (Fernet + PBKDF2HMAC, 480,000 iterations persisted per-vault with 100,000 legacy fallback) and v2 (Argon2id + AES-256-GCM AEAD, AAD v3) accurately.
  - Documents migration semantics: authenticated v1→v2 with explicit validated re-key, affirmative-confirmation AAD upgrades, and private backups before rewriting.
- `VAULT_FORMAT_V2.md`: the related-documents entry referencing `generate_it/storage.py` now references `generate_it/storage/core.py` and the re-exporting package.

## Verification

- `git diff --check` passed.
- No production code changed.

## Commits

- `24ffa07` docs: update storage package references
- `1769f49` docs: add documentation handoff
- `7c92914` docs: correct storage and KDF semantics in AGENTS.md

*End of handoff.*
