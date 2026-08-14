# Developer Submission: identity_hardening

* **Status:** SUBMITTED_FOR_REVIEW
* **Target Module:** Identity normalization and master-password predictability policy
* **Worktree Branch:** `feature/generate-it-identity-hardening` in `wt-generate-it-identity-hardening`
* **Timestamp:** 2026-08-13 19:15 -0500

## 1. Review Findings Addressed

An independent review identified three defects in the previous identity/password policy change:

- Removing format characters after `strip()` was non-idempotent and could bypass duplicate detection at whitespace boundaries.
- Blanket removal of Unicode `Cf` characters could break existing AAD v3 ciphertext and collapse meaningful joiner characters.
- Exact-only repeated-pattern detection allowed a repeated pattern with a suffix and falsely rejected long high-entropy repeated units.

## 2. Corrective Changes

- Restored `canonical_identity()` compatibility with existing AAD v3 identity bytes and made it idempotent.
- Rejected only a narrowly scoped set of dangerous invisible format characters at write validation boundaries; meaningful ZWJ/ZWNJ sequences remain representable.
- Added compatibility coverage for AAD v3 records containing format characters.
- Limited repeated-pattern analysis to short patterns, required at least three repetitions, allowed only a bounded suffix, and avoided classifying long high-entropy units as zero entropy.
- Added regression tests for boundary whitespace, meaningful joiners, near-repeat suffixes, long repeated units, and strong-password compatibility.

## 3. Verification

- [x] Focused identity/AAD tests: `24 passed`
- [x] Full pytest suite: `470 passed`
- [x] Mypy: `Success: no issues found in 26 source files`
- [x] Pip-audit: `No known vulnerabilities found`
- [x] Git diff check: passed
- [x] No error-silencing or typing workarounds added

## 4. Scope Notes

Existing storage architecture follow-ups and the explicitly process-local lockout limitation remain documented separately. This worktree contains only the identity/password hardening changes and regression tests.

## 5. Integrity Statement

All verification results came from commands executed in `/Users/josh/Code/wt-generate-it-identity-hardening`. No fabricated results were used.

## 6. Handoff

Ready for independent review and final cumulative verification.

*End of handoff.*

