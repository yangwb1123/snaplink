#!/usr/bin/env python3
"""Tests for complexity check."""
import unittest
from checks.complexity import is_exempt, EXEMPT_FUNCS, MAX_CYCLO, MAX_COGNIT


class TestIsExempt(unittest.TestCase):
    def test_exact_exempt_functions(self):
        for func in EXEMPT_FUNCS:
            self.assertTrue(is_exempt(func),
                            f"{func} should be exempt")

    def test_partial_match(self):
        self.assertTrue(is_exempt("handleLoginWithContext"))
        self.assertTrue(is_exempt("handleTokenExchange"))

    def test_no_false_positive(self):
        self.assertFalse(is_exempt("someUnknownFunction"))
        self.assertFalse(is_exempt("randomHelper"))

    def test_case_sensitivity(self):
        self.assertFalse(is_exempt("handlelogin"))
        self.assertFalse(is_exempt("HANDLETOKEN"))


class TestConstants(unittest.TestCase):
    def test_max_cyclo_reasonable(self):
        self.assertEqual(MAX_CYCLO, 15)

    def test_max_cognit_reasonable(self):
        self.assertEqual(MAX_COGNIT, 20)

    def test_exemption_list_non_empty(self):
        self.assertGreater(len(EXEMPT_FUNCS), 0)

    def test_no_duplicates(self):
        self.assertEqual(len(EXEMPT_FUNCS), len(set(EXEMPT_FUNCS)))


if __name__ == "__main__":
    unittest.main()
