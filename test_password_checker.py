"""
Tests for password_checker.py

Run:
    python -m unittest -v

These tests turn off the online breach check so they work without
internet access.
"""

import unittest

from password_checker import (
    check_common_patterns,
    check_context,
    check_number_sequence,
    check_password,
    check_repeated,
    check_sequence,
    get_context_words,
)


class TestLength(unittest.TestCase):

    def test_short_password_fails(self):
        result = check_password("abc", check_breach=False)

        self.assertFalse(result["standards"]["minimum_8"])
        self.assertEqual(result["standards"]["status"], "FAIL")

    def test_eight_characters_pass_length(self):
        result = check_password("abcdefgh", check_breach=False)

        self.assertTrue(result["standards"]["minimum_8"])

    def test_long_password_is_allowed(self):
        password = "a" * 100
        result = check_password(password, check_breach=False)

        self.assertTrue(result["standards"]["minimum_8"])


class TestSequences(unittest.TestCase):

    def test_letters(self):
        self.assertEqual(check_sequence("helloabcd"), "abcd")

    def test_numbers(self):
        self.assertEqual(check_sequence("hello1234"), "1234")

    def test_reverse_letters(self):
        self.assertEqual(check_sequence("hellodcba"), "dcba")

    def test_keyboard_pattern(self):
        self.assertEqual(check_sequence("xxqwerxx"), "qwer")


class TestRepeatedCharacters(unittest.TestCase):

    def test_repeated_characters(self):
        self.assertEqual(check_repeated("helloaaaa"), "aaaa")

    def test_no_repeated_characters(self):
        self.assertIsNone(check_repeated("hello1234"))


class TestNumberSequences(unittest.TestCase):

    def test_increasing_numbers(self):
        self.assertEqual(
            check_number_sequence("hello1234"),
            "1234",
        )

    def test_decreasing_numbers(self):
        self.assertEqual(
            check_number_sequence("hello9876"),
            "9876",
        )


class TestContext(unittest.TestCase):

    def test_email_is_split_into_words(self):
        words = get_context_words("john.doe@example.com")

        self.assertIn("john", words)
        self.assertIn("doe", words)
        self.assertIn("example", words)

    def test_context_is_detected(self):
        found = check_context(
            "JohnPassword123!",
            "john@example.com",
        )

        self.assertIn("john", found)
        self.assertIn("password", found)


class TestCommonPatterns(unittest.TestCase):

    def test_number_at_end(self):
        issues = check_common_patterns("hello123")

        self.assertTrue(
            any("number is added" in issue for issue in issues)
        )

    def test_year(self):
        issues = check_common_patterns("hello2026")

        self.assertTrue(
            any("Year pattern" in issue for issue in issues)
        )


class TestFullChecker(unittest.TestCase):

    def test_breach_check_can_be_unknown(self):
        result = check_password(
            "A reasonably long password",
            check_breach=False,
        )

        self.assertEqual(result["breach"]["status"], "unknown")

    def test_password_is_not_returned(self):
        password = "This is a private password"

        result = check_password(
            password,
            check_breach=False,
        )

        self.assertNotIn("password", result)

    def test_result_has_main_sections(self):
        result = check_password(
            "A reasonably long password",
            check_breach=False,
        )

        self.assertIn("standards", result)
        self.assertIn("breach", result)
        self.assertIn("checks", result)
        self.assertIn("score", result)
        self.assertIn("rating", result)
        self.assertIn("issues", result)


if __name__ == "__main__":
    unittest.main()
