#!/usr/bin/env python3
"""Tests for project-reorganization skill."""
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shared.fs import count_lines, list_exported_functions


class TestSharedFs(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(__file__).resolve().parent

    def test_count_lines_known_file(self):
        """Test count_lines on itself."""
        path = Path(__file__)
        count = count_lines(path)
        self.assertGreater(count, 0)

    def test_count_lines_empty(self):
        """Count lines on empty file-like input."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as t:
            t.write("\n\n")
            tmp = Path(t.name)
        count = count_lines(tmp)
        tmp.unlink()
        self.assertEqual(count, 2)

    def test_list_exported_functions_on_go_file(self):
        """list_exported_functions on a Go file (the format it expects)."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".go", delete=False) as t:
            t.write("package main\n\nfunc Hello() {}\n\nfunc private() {}\n")
            tmp = Path(t.name)
        funcs = list_exported_functions(tmp)
        tmp.unlink()
        names = [f[0] for f in funcs]
        self.assertIn("Hello", names,
                       "Exported func Hello() should be detected")
        self.assertNotIn("private", names,
                         "Unexported func private() should NOT be listed")


if __name__ == "__main__":
    unittest.main()
