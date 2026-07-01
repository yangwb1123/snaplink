#!/usr/bin/env python3
"""Tests for oracle-leak review skill."""
import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from run import review


class TestOracleLeakReview(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def test_review_missing_file(self):
        result = review(self.tmpdir / "nonexistent.go")
        self.assertEqual(result, 1)

    def test_clean_file_passes(self):
        f = self.tmpdir / "clean.go"
        f.write_text("package main\n\nfunc main() { println(\"hello\") }\n")
        result = review(f)
        self.assertEqual(result, 0)

    def test_token_no_store_headers_detected(self):
        f = self.tmpdir / "handler.go"
        f.write_text(
            'package main\n\n'
            'import "net/http"\n\n'
            'func handleToken(w http.ResponseWriter) {\n'
            '    tokenNoStoreHeaders(w)\n'
            '    setBearerChallenge(w, "invalid_token")\n'
            '}\n'
        )
        result = review(f)
        self.assertEqual(result, 0)  # These are GOOD patterns

    def test_oracle_leak_detected(self):
        f = self.tmpdir / "leak.go"
        f.write_text(
            'package main\n\n'
            'import "errors"\n\n'
            'func findUser() error {\n'
            '    return errors.New("unknown user")\n'
            '}\n'
        )
        result = review(f)
        self.assertEqual(result, 1)  # LEAK detected

    def test_invalid_grant_is_safe(self):
        f = self.tmpdir / "token.go"
        f.write_text(
            'package main\n\n'
            'func handleToken() string {\n'
            '    return "invalid_grant"\n'
            '}\n'
        )
        result = review(f)
        self.assertEqual(result, 0)  # Oracle-safe pattern


if __name__ == "__main__":
    unittest.main()
