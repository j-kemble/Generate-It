"""Test that every constant duplicated across modules matches its counterpart.

This test currently guards a single duplication surface:

**``constants.py`` ↔ ``generator.py``** — generator-level constants
(length bounds, character sets, wordlists, entropy minimums).  This is the
original drift surface; ``USERNAME_ALPHANUMERIC`` was caught diverging here
(``review-REJECTED-consolidated-remediation-20260816-2305.md`` §3).

If a test here fails, the two modules are out of sync.  Fix the source of
truth (first decide which one it is, then update the other) and add the
correction to this test so future drift is caught.

--------------------------------------------------------------------
Known architectural debt — not yet guarded by this test suite
--------------------------------------------------------------------

**Policy-tuple duplication** — ``constants.py`` ↔ ``tui.py``
  ``CLIPBOARD_AUTO_CLEAR_OPTIONS`` and ``AUTO_LOCK_OPTIONS`` are defined
  independently in both modules (``tui.py`` at lines 52, 62 is the runtime
  authority; ``constants.py`` at lines 10, 20 is imported by
  ``tui_render.py``).  These are verified byte-identical at the time of
  PR #3 remediation but are *not* guarded by a sync test — they could
  silently diverge.

**Constants single-source-of-truth migration**
  Making ``generator.py`` and ``tui.py`` import from ``constants.py``
  (rather than defining independent copies) is the intended resolution for
  *all* duplication surfaces above.  The sync test is a pragmatic interim
  guard; the full migration is deferred for scope-risk reasons.  When the
  migration lands, this file should be updated to verify the *remaining*
  guards rather than the duplication surfaces.
"""

from __future__ import annotations

import string

from generate_it import constants
from generate_it import generator


def _as_str(value: object) -> str:
    """Normalise a constant to a string for comparison.

    Both modules may express string constants as plain ``str``, via
    ``string.ascii_letters``, or as ``frozenset``.  Normalise everything
    to a plain ``str`` for unambiguous comparison.
    """
    if isinstance(value, frozenset):
        return str(sorted(value))
    return str(value)


class TestConstantsSync:
    """Verify every shared constant matches between ``constants`` and ``generator``."""

    # --- Integer/bool constants -----------------------------------------

    def test_min_password_chars(self) -> None:
        assert constants.MIN_PASSWORD_CHARS == generator.MIN_PASSWORD_CHARS

    def test_max_password_chars(self) -> None:
        assert constants.MAX_PASSWORD_CHARS == generator.MAX_PASSWORD_CHARS

    def test_min_passphrase_words(self) -> None:
        assert constants.MIN_PASSPHRASE_WORDS == generator.MIN_PASSPHRASE_WORDS

    def test_max_passphrase_words(self) -> None:
        assert constants.MAX_PASSPHRASE_WORDS == generator.MAX_PASSPHRASE_WORDS

    def test_min_username_length(self) -> None:
        assert constants.MIN_USERNAME_LENGTH == generator.MIN_USERNAME_LENGTH

    def test_max_username_length(self) -> None:
        assert constants.MAX_USERNAME_LENGTH == generator.MAX_USERNAME_LENGTH

    def test_min_username_words(self) -> None:
        assert constants.MIN_USERNAME_WORDS == generator.MIN_USERNAME_WORDS

    def test_max_username_words(self) -> None:
        assert constants.MAX_USERNAME_WORDS == generator.MAX_USERNAME_WORDS

    def test_min_passphrase_entropy_bits(self) -> None:
        assert constants._MIN_PASSPHRASE_ENTROPY_BITS == generator._MIN_PASSPHRASE_ENTROPY_BITS

    # --- Character-set string constants ----------------------------------

    def test_letters(self) -> None:
        assert _as_str(constants.LETTERS) == _as_str(generator.LETTERS)

    def test_numbers(self) -> None:
        assert _as_str(constants.NUMBERS) == _as_str(generator.NUMBERS)

    def test_special_characters(self) -> None:
        assert _as_str(constants.SPECIAL_CHARACTERS) == _as_str(generator.SPECIAL_CHARACTERS)

    def test_username_alphanumeric(self) -> None:
        """This was the constant that diverged — PR #3 review caught it."""
        assert (
            _as_str(constants.USERNAME_ALPHANUMERIC)
            == _as_str(generator.USERNAME_ALPHANUMERIC)
        )
        # The canonical value — both must be lowercase-only
        expected = string.ascii_lowercase + string.digits
        assert _as_str(constants.USERNAME_ALPHANUMERIC) == expected

    def test_username_separators(self) -> None:
        assert _as_str(constants.USERNAME_SEPARATORS) == _as_str(generator.USERNAME_SEPARATORS)

    def test_passphrase_specials(self) -> None:
        assert _as_str(constants.PASSPHRASE_SPECIALS) == _as_str(generator.PASSPHRASE_SPECIALS)

    # --- Constant collections (lists / frozensets) -----------------------

    def test_default_wordlist(self) -> None:
        assert constants.DEFAULT_WORDLIST == generator.DEFAULT_WORDLIST
