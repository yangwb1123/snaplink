#!/usr/bin/env python3
"""Regression tests for the self-diagnosis report.

The file-health section parses `wc -l` output, and `wc -l {} +` closes with a
`total` line whose shape is indistinguishable from a file entry. Treating it as
a finding made the report name "total" as the repository's largest file and fail
the Codebase Health job on a tree with no oversized file at all.
"""

from __future__ import annotations

import io
import contextlib
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import diagnose  # noqa: E402 — path is prepared above


def _completed(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


def _file_health(listing: str) -> tuple[int, str]:
    """Run the report over a stubbed `wc -l` listing and return (criticals, output).

    Every later subprocess call is answered with empty output, so the only
    findings that can appear are the ones the listing produces.
    """
    def fake_run(cmd, *args, **kwargs):
        text = cmd if isinstance(cmd, str) else " ".join(cmd)
        if "wc -l" in text:
            return _completed(listing)
        if isinstance(cmd, list) and "-rq" in cmd:
            return _completed("", returncode=1)  # no architecture violation
        return _completed("")

    buffer = io.StringIO()
    with mock.patch.object(diagnose.subprocess, "run", side_effect=fake_run), \
            contextlib.redirect_stdout(buffer):
        critical = diagnose.run()
    return critical, buffer.getvalue()


class FileHealthParsingTests(unittest.TestCase):
    def test_the_wc_total_line_is_not_a_finding(self):
        critical, out = _file_health("  498 shared/core/router.go\n2100 total\n")
        self.assertEqual(0, critical, out)
        self.assertNotIn("Files >2000", out)

    def test_a_genuinely_oversized_file_is_still_reported(self):
        critical, out = _file_health(
            "  498 shared/core/router.go\n2500 interfaces/sso/handler.go\n2600 total\n"
        )
        self.assertEqual(1, critical, out)
        self.assertIn("interfaces/sso/handler.go", out)
        self.assertNotIn("Files >2000 lines: total", out)

    def test_a_file_at_the_threshold_is_not_reported(self):
        critical, out = _file_health("  2000 shared/core/router.go\n2000 total\n")
        self.assertEqual(0, critical, out)

    def test_a_file_over_the_threshold_is_reported_exactly_once(self):
        critical, out = _file_health("  2001 a.go\n2001 total\n")
        self.assertEqual(1, critical, out)
        self.assertEqual(1, out.count("[CRITICAL]"), out)

    def test_non_go_lines_from_the_listing_are_ignored(self):
        """A two-column numeric line that is not a .go path is not file health."""
        critical, out = _file_health("  5000 total\n  4321 some/other/file.txt\n")
        self.assertEqual(0, critical, out)


if __name__ == "__main__":
    unittest.main()
