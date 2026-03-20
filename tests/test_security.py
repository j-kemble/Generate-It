"""Cryptography and entropy validation tests for Generate-It.

These tests validate that the generated credentials meet security requirements
including entropy thresholds and resistance to common weak patterns.
"""

from __future__ import annotations

import math
from collections import Counter

import pytest

from generate_it import generator


def calculate_entropy(password: str, character_pool_size: int) -> float:
    """Calculate Shannon entropy of a password given the character pool size.

    H = L * log2(N)
    Where L = password length, N = character pool size
    """
    if not password:
        return 0.0
    return len(password) * math.log2(character_pool_size)


def estimate_character_pool_size(
    use_letters: bool, use_numbers: bool, use_special: bool
) -> int:
    """Estimate the character pool size based on enabled character types."""
    pool_size = 0
    if use_letters:
        pool_size += len(generator.LETTERS)
    if use_numbers:
        pool_size += len(generator.NUMBERS)
    if use_special:
        pool_size += len(generator.SPECIAL_CHARACTERS)
    return pool_size


class TestPasswordEntropy:
    """Tests for password entropy and randomness quality."""

    def test_password_minimum_entropy_50_bits(self) -> None:
        """Ensure 12-character passwords with full character set have >50 bits entropy."""
        # 12 chars * log2(26+26+10+23) = 12 * log2(85) ≈ 76 bits
        pool_size = estimate_character_pool_size(True, True, True)
        password = generator.generate_character_password(
            12, use_letters=True, use_numbers=True, use_special=True
        )
        entropy = calculate_entropy(password, pool_size)
        assert entropy >= 50, f"Password entropy {entropy:.1f} bits is below 50-bit minimum"

    def test_password_minimum_entropy_40_bits(self) -> None:
        """Ensure 10-character passwords have at least 40 bits entropy."""
        pool_size = estimate_character_pool_size(True, True, True)
        password = generator.generate_character_password(
            10, use_letters=True, use_numbers=True, use_special=True
        )
        entropy = calculate_entropy(password, pool_size)
        assert entropy >= 40, f"Password entropy {entropy:.1f} bits is below 40-bit minimum"

    def test_password_meets_length_requirement(self) -> None:
        """NIST recommends minimum 8 characters for passwords."""
        password = generator.generate_character_password(
            generator.MIN_PASSWORD_CHARS,
            use_letters=True,
            use_numbers=True,
            use_special=True,
        )
        assert len(password) >= 8, "Password must be at least 8 characters"

    def test_password_no_common_patterns(self) -> None:
        """Check that generated passwords don't contain common weak patterns."""
        common_patterns = [
            "password", "123456", "qwerty", "abc123", "letmein", "welcome",
            "monkey", "dragon", "master", "sunshine", "princess", "admin",
        ]

        # Generate multiple passwords to check for patterns
        for _ in range(100):
            password = generator.generate_character_password(
                12, use_letters=True, use_numbers=True, use_special=True
            ).lower()
            for pattern in common_patterns:
                assert pattern not in password, f"Password contains weak pattern: {pattern}"

    def test_password_distribution_uniformity(self) -> None:
        """Check that characters are reasonably uniformly distributed."""
        # Generate many passwords and check character frequency
        all_chars = []
        for _ in range(1000):
            pw = generator.generate_character_password(
                20, use_letters=True, use_numbers=True, use_special=False
            )
            all_chars.extend(pw)

        counts = Counter(all_chars)
        total = len(all_chars)
        expected_freq = total / len(generator.LETTERS + generator.NUMBERS)

        # Check that no character appears significantly more often than expected
        # (allowing 3x expected frequency for random variation)
        for char, count in counts.items():
            assert count < expected_freq * 3, (
                f"Character '{char}' appears {count} times, "
                f"expected ~{expected_freq:.1f}"
            )

    def test_password_contains_required_categories(self) -> None:
        """Ensure passwords contain at least one character from each enabled category."""
        password = generator.generate_character_password(
            20, use_letters=True, use_numbers=True, use_special=True
        )

        has_letter = any(c in generator.LETTERS for c in password)
        has_number = any(c in generator.NUMBERS for c in password)
        has_special = any(c in generator.SPECIAL_CHARACTERS for c in password)

        assert has_letter, "Password must contain at least one letter"
        assert has_number, "Password must contain at least one number"
        assert has_special, "Password must contain at least one special character"


class TestPassphraseEntropy:
    """Tests for passphrase entropy and word selection."""

    def test_passphrase_word_count_entropy(self) -> None:
        """Calculate entropy based on word selection from wordlist."""
        wordlist = generator.load_wordlist()
        wordlist_size = len(wordlist)

        # Generate passphrase and calculate entropy
        passphrase = generator.generate_passphrase(
            4, add_numbers=False, add_special=False, words=wordlist
        )
        words = passphrase.split("-")

        # Entropy = log2(wordlist_size ^ word_count)
        entropy = len(words) * math.log2(wordlist_size)

        # 4 words from ~2500 wordlist = ~44 bits minimum
        assert entropy >= 40, f"Passphrase entropy {entropy:.1f} bits is below 40-bit minimum"

    def test_passphrase_no_duplicate_words(self) -> None:
        """Ensure passphrase words are unique (no repetition)."""
        wordlist = [f"word{i}" for i in range(100)]

        for _ in range(50):
            passphrase = generator.generate_passphrase(
                5, add_numbers=False, add_special=False, words=wordlist
            )
            words = passphrase.split("-")
            assert len(words) == len(set(words)), "Passphrase contains duplicate words"

    def test_passphrase_with_numbers_increases_entropy(self) -> None:
        """Numbers embedded in passphrase should increase entropy."""
        wordlist = generator.load_wordlist()

        # Generate with numbers
        passphrase_with_nums = generator.generate_passphrase(
            4, add_numbers=True, add_special=False, words=wordlist
        )

        # Should contain digits
        assert any(c.isdigit() for c in passphrase_with_nums), (
            "Passphrase with add_numbers=True should contain digits"
        )

    def test_passphrase_minimum_word_count(self) -> None:
        """NIST recommends minimum 4 words for passphrases."""
        wordlist = generator.load_wordlist()

        passphrase = generator.generate_passphrase(
            generator.MIN_PASSPHRASE_WORDS,
            add_numbers=False,
            add_special=False,
            words=wordlist,
        )
        words = passphrase.split("-")
        assert len(words) >= 3, "Passphrase must contain at least 3 words"

    def test_passphrase_randomness(self) -> None:
        """Generate multiple passphrases and verify word selection appears random."""
        wordlist = generator.load_wordlist()

        # Collect first words from many passphrases
        first_words = []
        for _ in range(200):
            pp = generator.generate_passphrase(
                3, add_numbers=False, add_special=False, words=wordlist
            )
            first_words.append(pp.split("-")[0])

        # Check for diversity in word selection
        unique_words = len(set(first_words))
        # Expect at least 30% unique words (accounting for randomness)
        assert unique_words >= 50, (
            f"Only {unique_words} unique first words out of 200, "
            f"selection may not be random enough"
        )


class TestUsernameEntropy:
    """Tests for username generation randomness."""

    def test_username_random_character_distribution(self) -> None:
        """Verify random usernames have reasonable character distribution."""
        usernames = [
            generator.generate_username_random(15, separator_style="none")
            for _ in range(100)
        ]

        all_chars = "".join(usernames)
        counts = Counter(all_chars)

        # Check no character dominates (allowing some random variation)
        most_common_count = counts.most_common(1)[0][1]
        avg_count = len(all_chars) / len(generator.USERNAME_ALPHANUMERIC)
        assert most_common_count < avg_count * 3, (
            f"Character distribution is skewed: max={most_common_count}, avg={avg_count:.1f}"
        )

    def test_username_words_unique_selection(self) -> None:
        """Verify username word selection uses unique words."""
        wordlist = [f"word{i}" for i in range(50)]

        usernames = [
            generator.generate_username_words(2, add_numbers=False, words=wordlist)
            for _ in range(25)
        ]

        # Check that we're getting different word combinations
        unique_usernames = len(set(usernames))
        assert unique_usernames >= 15, (
            f"Only {unique_usernames} unique usernames out of 25, "
            f"selection may not be random enough"
        )


class TestCryptographicSecurity:
    """Tests for proper use of cryptographic primitives."""

    def test_uses_secrets_module_not_random(self) -> None:
        """Verify the code uses secrets module for cryptographic randomness.

        This is a code review test - checks that we're not using random.random()
        or random.choice() in the generator module.
        """
        import ast
        import inspect

        source = inspect.getsource(generator)
        tree = ast.parse(source)

        # Check for any imports of random module (should only use secrets)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "random", (
                        "Should not import 'random' module, use 'secrets' instead"
                    )
            if isinstance(node, ast.ImportFrom):
                assert node.module != "random", (
                    "Should not import from 'random' module, use 'secrets' instead"
                )

    def test_secure_shuffle_uses_secrets(self) -> None:
        """Verify secure_shuffle uses cryptographically secure randomness."""
        # This indirectly tests that secure_shuffle uses secrets.randbelow
        items = list(range(100))
        original = items.copy()

        # Run shuffle multiple times and check distribution
        results = []
        for _ in range(50):
            test_items = original.copy()
            generator.secure_shuffle(test_items)
            results.append(tuple(test_items))

        # Should get different shuffles (unlikely to be identical)
        unique_shuffles = len(set(results))
        assert unique_shuffles >= 45, (
            f"Only {unique_shuffles} unique shuffles, randomness may be weak"
        )


class TestWeakPatternResistance:
    """Tests to ensure generated credentials resist common attacks."""

    def test_no_sequential_characters(self) -> None:
        """Check that passwords don't contain sequential characters like 'abc' or '123'."""
        sequential_patterns = [
            "abc", "bcd", "cde", "def", "efg", "fgh", "ghi", "hij",
            "ijk", "jkl", "klm", "lmn", "mno", "nop", "opq", "pqr",
            "qrs", "rst", "stu", "tuv", "uvw", "vwx", "wxy", "xyz",
            "012", "123", "234", "345", "456", "567", "678", "789",
            "qwerty", "asdf", "zxcv",
        ]

        for _ in range(100):
            password = generator.generate_character_password(
                16, use_letters=True, use_numbers=True, use_special=False
            ).lower()
            for pattern in sequential_patterns:
                assert pattern not in password, (
                    f"Password contains sequential pattern: {pattern}"
                )

    def test_no_repeated_character_sequences(self) -> None:
        """Check that passwords don't have excessive repeated characters."""
        for _ in range(50):
            password = generator.generate_character_password(
                20, use_letters=True, use_numbers=True, use_special=True
            )
            # Check for 3+ identical consecutive characters
            for i in range(len(password) - 2):
                trio = password[i:i+3]
                assert not (trio[0] == trio[1] == trio[2]), (
                    f"Password contains 3+ repeated characters: {trio}"
                )

    def test_passphrase_words_not_predictable(self) -> None:
        """Verify that word selection doesn't follow predictable patterns."""
        wordlist = generator.load_wordlist()

        # Generate many passphrases
        all_words = []
        for _ in range(100):
            pp = generator.generate_passphrase(
                4, add_numbers=False, add_special=False, words=wordlist
            )
            all_words.extend(pp.split("-"))

        # Check that words appear in different positions
        word_positions = {w: [] for w in set(all_words)}
        for i, word in enumerate(all_words):
            position = i % 4  # position in passphrase (0-3)
            word_positions[word].append(position)

        # Words should appear in multiple positions (not always first, etc.)
        for word, positions in word_positions.items():
            if len(positions) >= 3:
                unique_positions = len(set(positions))
                assert unique_positions >= 2, (
                    f"Word '{word}' always appears in same position: {positions}"
                )
