#!/usr/bin/env python3
"""Tests for filesize check."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import checks.filesize as filesize
from checks.filesize import check_file, is_exempt, run, EXEMPTIONS, IGNORE_PATTERNS, MAX_LINES


class TestIsExempt(unittest.TestCase):
    def test_exact_match(self):
        root = Path("/repo")
        rel = "interfaces/sso/accessors.go"
        self.assertTrue(is_exempt(root / rel, rel, exemptions=[rel]))

    def test_wildcard_match(self):
        root = Path("/repo")
        exempt = "generated/*"
        rel = "generated/some_file.go"
        self.assertTrue(is_exempt(root / rel, rel, exemptions=[exempt]))

    def test_no_false_positive(self):
        root = Path("/repo")
        self.assertFalse(is_exempt(root / "some/random/path.go",
                                    "some/random/path.go"))

    def test_exempt_file_listed_via_suffix(self):
        root = Path("/repo")
        rel = "cmd/sso-server/main.go"
        self.assertTrue(is_exempt(root / rel, rel, exemptions=["main.go"]))


class TestCheckFile(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())

    def test_non_go_file_passes(self):
        f = self.root / "readme.md"
        f.write_text("hello\n")
        self.assertTrue(check_file(f, self.root))

    def test_short_go_file_passes(self):
        f = self.root / "main.go"
        f.write_text("\n".join(f"line {i}" for i in range(10)))
        self.assertTrue(check_file(f, self.root))

    def test_oversized_go_file_fails(self):
        f = self.root / "main.go"
        f.write_text("\n".join(f"line {i}" for i in range(MAX_LINES + 10)))
        self.assertFalse(check_file(f, self.root))

    def test_oversized_file_outside_root_still_fails(self):
        """A path outside `root` (e.g. a CLI arg pointing elsewhere, as
        checks/self_test.py's probe does) must not raise -- it should still
        be size-checked, just without exemption/ignore-pattern matching."""
        f = self.root / "main.go"
        f.write_text("\n".join(f"line {i}" for i in range(MAX_LINES + 10)))
        other_root = Path(tempfile.mkdtemp())
        self.assertFalse(check_file(f, other_root))

    def test_relative_path_arg_resolves_correctly(self):
        """A relative Path (as produced by the CLI's `[Path(a) for a in
        sys.argv[1:]]`) must resolve against cwd before comparing to root,
        not raise ValueError."""
        import os
        f = self.root / "sub" / "main.go"
        f.parent.mkdir()
        f.write_text("short file\n")
        old_cwd = os.getcwd()
        try:
            os.chdir(self.root)
            self.assertTrue(check_file(Path("sub/main.go"), self.root))
        finally:
            os.chdir(old_cwd)

    def test_ignored_pattern_skipped(self):
        for pat in IGNORE_PATTERNS:
            f = self.root / pat.strip("/") / "ignored.go"
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("\n".join(f"line {i}" for i in range(MAX_LINES + 10)))
            self.assertTrue(check_file(f, self.root),
                            f"Pattern {pat} should be ignored")

    def test_exempt_file_skipped(self):
        rel = "legacy/oversized.go"
        f = self.root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("\n".join(f"line {i}" for i in range(MAX_LINES + 10)))
        with patch.object(filesize, "EXEMPTIONS", [rel]):
            self.assertTrue(check_file(f, self.root))


class TestExemptionsList(unittest.TestCase):
    def test_all_exemptions_are_go_files_or_wildcards(self):
        for e in EXEMPTIONS:
            if e.endswith("/*"):
                self.assertTrue(e.count("/") >= 1,
                                f"Wildcard {e} should have a directory prefix")
            else:
                self.assertTrue(e.endswith(".go") or e.endswith("/*"),
                                f"Exemption {e} should end with .go or /*")

    def test_no_duplicate_exemptions(self):
        self.assertEqual(len(EXEMPTIONS), len(set(EXEMPTIONS)),
                         "Duplicate exemptions found")


class TestIgnorePatterns(unittest.TestCase):
    def test_patterns_cover_nested_modules(self):
        """All nested module dirs should be in IGNORE_PATTERNS."""
        nested = {"kms/", "redis/", "saml/", "ldap/", "kerberos/",
                  "radius/", "extauthz/"}
        for n in nested:
            found = any(n in p for p in IGNORE_PATTERNS)
            self.assertTrue(found, f"Nested module {n} not in IGNORE_PATTERNS")


if __name__ == "__main__":
    unittest.main()
