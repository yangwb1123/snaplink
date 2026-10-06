"""Offline regressions for isolated SwiftPM consumption and immutable candidates."""

from __future__ import annotations

import copy
import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import swift_sdk_smoke as smoke
from swift_sdk_release import SwiftReleaseError


SHA = "a" * 40
VERSION = "0.3.0-beta.1"


def _git(root: Path, *arguments: str) -> str:
    environment = smoke._environment()
    environment.update(GIT_AUTHOR_NAME="SDK smoke fixture", GIT_AUTHOR_EMAIL="sdk@example.invalid",
                       GIT_COMMITTER_NAME="SDK smoke fixture", GIT_COMMITTER_EMAIL="sdk@example.invalid")
    return subprocess.check_output(["git", *arguments], cwd=root, env=environment,
                                   text=True, stderr=subprocess.PIPE).strip()


def _commit(root: Path) -> str:
    _git(root, "add", ".")
    tree = _git(root, "write-tree")
    commit = _git(root, "commit-tree", tree, "-m", "SDK smoke fixture")
    _git(root, "update-ref", "refs/heads/main", commit)
    _git(root, "symbolic-ref", "HEAD", "refs/heads/main")
    return commit


def _repository(root: Path) -> str:
    _git(root, "init", "--quiet")
    version = root / smoke.VERSION_PATH
    version.parent.mkdir(parents=True)
    version.write_text(VERSION + "\n", encoding="ascii")
    (root / "Package.swift").write_text("committed package fixture", encoding="utf-8")
    return _commit(root)


def _lock(url: str = smoke.PACKAGE_URL) -> dict:
    return {
        "version": 3,
        "pins": [{"identity": "snaplink", "kind": "remoteSourceControl", "location": url,
                  "state": {"revision": SHA, "version": VERSION}}],
    }


class SwiftSmokeMetadataTests(unittest.TestCase):
    def test_inputs_require_prerelease_and_full_sha(self) -> None:
        smoke.validate_inputs(VERSION, SHA)
        smoke.validate_inputs(VERSION, "b" * 64)
        for version, sha in (("0.3.0", SHA), (VERSION + "+build", SHA),
                             (VERSION, "HEAD"), (VERSION, SHA + "\n"), (VERSION, SHA.upper())):
            with self.subTest(version=version, sha=sha):
                with self.assertRaises(SwiftReleaseError):
                    smoke.validate_inputs(version, sha)

    def test_resolution_versions_two_and_three_require_the_exact_pin(self) -> None:
        for format_version in (2, 3):
            lock = _lock()
            lock["version"] = format_version
            smoke.validate_resolution(lock, smoke.PACKAGE_URL, VERSION, SHA)

    def test_local_git_url_pins_use_the_exact_decoded_path_and_local_kind(self) -> None:
        url = "file:///private/tmp/with%20spaces/snaplink.git"
        lock = _lock(url)
        lock["pins"][0].update(kind="localSourceControl", location="/private/tmp/with spaces/snaplink.git")
        smoke.validate_resolution(lock, url, VERSION, SHA)
        for key, value in (("kind", "remoteSourceControl"), ("location", url),
                           ("location", "/private/tmp/other/snaplink.git")):
            wrong = copy.deepcopy(lock)
            wrong["pins"][0][key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaises(SwiftReleaseError):
                    smoke.validate_resolution(wrong, url, VERSION, SHA)

    def test_wrong_or_malformed_resolution_is_rejected(self) -> None:
        invalid = [[], {}, {"version": 1}, {"version": 3, "pins": []},
                   {"version": 3, "pins": [None]}, {"version": 3, "pins": "invalid"}]
        for key, value in (("identity", "other"), ("location", "https://attacker.example/snaplink.git"),
                           ("kind", "registry"), ("state", None)):
            lock = _lock()
            lock["pins"][0][key] = value
            invalid.append(lock)
        for key, value in (("revision", "b" * 40), ("version", "0.3.0-beta.2"), ("branch", "main")):
            lock = _lock()
            lock["pins"][0]["state"][key] = value
            invalid.append(lock)
        lock = _lock()
        lock["pins"].append(copy.deepcopy(lock["pins"][0]))
        invalid.append(lock)
        for lock in invalid:
            with self.subTest(lock=lock):
                with self.assertRaises(SwiftReleaseError):
                    smoke.validate_resolution(lock, smoke.PACKAGE_URL, VERSION, SHA)

    def test_consumer_uses_semver_git_dependency_and_public_product(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            consumer = smoke.write_consumer(Path(directory), smoke.PACKAGE_URL, VERSION)
            manifest = (consumer / "Package.swift").read_text()
            source = (consumer / "Sources/main.swift").read_text()
            self.assertIn(f'.package(url: "{smoke.PACKAGE_URL}", exact: "{VERSION}")', manifest)
            self.assertIn('.product(name: "SnaplinkSSO", package: "snaplink")', manifest)
            self.assertIn("import SnaplinkSSO", source)
            self.assertIn("SnaplinkAuthClient(configuration:", source)
            self.assertNotIn("@testable", source)
            self.assertNotIn(".package(path:", manifest)


class SwiftSmokeCandidateTests(unittest.TestCase):
    def test_candidate_preserves_commit_and_never_tags_or_changes_the_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "source"
            root.mkdir()
            sha = _repository(root)
            # Git-backed consumption must exclude dirty and untracked files.
            (root / "Package.swift").write_text("uncommitted change")
            (root / "not-shipped.txt").write_text("untracked")
            status = _git(root, "status", "--porcelain")
            workspace = parent / "workspace"
            workspace.mkdir()
            candidate = smoke.candidate_repository(root, workspace, VERSION, sha)
            self.assertEqual(candidate.name, "snaplink.git")
            self.assertEqual(_git(candidate, "rev-parse", f"refs/tags/{VERSION}"), sha)
            self.assertEqual(_git(candidate, "show", f"{sha}:Package.swift"), "committed package fixture")
            self.assertEqual(_git(root, "tag", "--list"), "")
            self.assertEqual(_git(root, "status", "--porcelain"), status)

    def test_mismatched_sha_or_committed_version_is_rejected_before_cloning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "source"
            root.mkdir()
            sha = _repository(root)
            for version, expected in ((VERSION, SHA), ("0.3.0-beta.2", sha)):
                with self.subTest(version=version, expected=expected):
                    with self.assertRaises(SwiftReleaseError):
                        smoke.candidate_repository(root, parent, version, expected)
                    self.assertFalse((parent / "snaplink.git").exists())

    def test_existing_tag_on_the_same_commit_is_accepted_without_moving_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sha = _repository(root)
            _git(root, "update-ref", f"refs/tags/{VERSION}", sha, "")
            workspace = root / "scratch"
            workspace.mkdir()
            candidate = smoke.candidate_repository(root, workspace, VERSION, sha)
            self.assertEqual(_git(candidate, "rev-parse", f"refs/tags/{VERSION}"), sha)
            self.assertEqual(_git(root, "rev-parse", f"refs/tags/{VERSION}"), sha)

    def test_conflicting_tag_is_rejected_without_rewriting_the_source_tag(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = _repository(root)
            _git(root, "update-ref", f"refs/tags/{VERSION}", first, "")
            (root / "new-file.txt").write_text("second commit")
            second = _commit(root)
            workspace = root / "scratch"
            workspace.mkdir()
            with self.assertRaisesRegex(SwiftReleaseError, "another commit"):
                smoke.candidate_repository(root, workspace, VERSION, second)
            self.assertEqual(_git(root, "rev-parse", f"refs/tags/{VERSION}"), first)


class SwiftSmokeExecutionTests(unittest.TestCase):
    def test_environment_drops_tokens_git_overrides_and_global_rewrites(self) -> None:
        with patch.dict(smoke.os.environ, {"GH_TOKEN": "secret", "GITHUB_TOKEN": "secret",
                                          "GIT_DIR": "/other", "GIT_WORK_TREE": "/other",
                                          "GIT_CONFIG_COUNT": "1", "PATH": "/tools"}, clear=True):
            environment = smoke._environment()
        self.assertNotIn("GH_TOKEN", environment)
        self.assertNotIn("GITHUB_TOKEN", environment)
        self.assertNotIn("GIT_DIR", environment)
        self.assertNotIn("GIT_WORK_TREE", environment)
        self.assertNotIn("GIT_CONFIG_COUNT", environment)
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], smoke.os.devnull)
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(environment["PATH"], "/tools")

    def test_subprocess_is_bounded_and_build_errors_are_not_ignored(self) -> None:
        with patch.object(smoke.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "ok")) as run:
            smoke._run(["swift", "build"], Path("/tmp"))
        self.assertEqual(run.call_args.kwargs["timeout"], 600)
        self.assertNotIn("shell", run.call_args.kwargs)
        failure = subprocess.CompletedProcess([], 1, "build failed")
        with patch.object(smoke.subprocess, "run", return_value=failure), redirect_stderr(io.StringIO()):
            with self.assertRaises(SwiftReleaseError):
                smoke._run(["swift", "build"], Path("/tmp"))
        for error in (OSError("test-secret"), subprocess.TimeoutExpired("test-secret", 600)):
            with patch.object(smoke.subprocess, "run", side_effect=error):
                with self.assertRaises(SwiftReleaseError) as raised:
                    smoke._run(["swift", "build"], Path("/tmp"))
                self.assertNotIn("test-secret", str(raised.exception))

    def test_consumer_runs_resolution_strict_release_build_and_public_api(self) -> None:
        commands = []
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)

            def run(command, cwd):
                commands.append(command)
                if command[1] == "package":
                    (cwd / "Package.resolved").write_text(json.dumps(_lock()))
                return subprocess.CompletedProcess(command, 0, "PASS: SnaplinkSSO consumer\n")

            with patch.object(smoke, "_run", side_effect=run):
                smoke.verify_consumer(workspace, smoke.PACKAGE_URL, VERSION, SHA)
        self.assertEqual([command[1] for command in commands], ["package", "build", "run"])
        self.assertIn("-strict-concurrency=complete", commands[1])
        self.assertIn("-warnings-as-errors", commands[1])
        self.assertIn("release", commands[1])
        for command in commands[1:]:
            self.assertIn("--force-resolved-versions", command)
        for command in commands:
            for flag in ("--scratch-path", "--cache-path", "--config-path", "--security-path",
                         "--disable-dependency-cache", "--disable-keychain", "--disable-netrc"):
                self.assertIn(flag, command)

    def test_wrong_resolution_stops_before_compilation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)

            def resolve(command, cwd):
                lock = _lock()
                lock["pins"][0]["state"]["revision"] = "b" * 40
                (cwd / "Package.resolved").write_text(json.dumps(lock))

            with patch.object(smoke, "_run", side_effect=resolve) as run:
                with self.assertRaises(SwiftReleaseError):
                    smoke.verify_consumer(workspace, smoke.PACKAGE_URL, VERSION, SHA)
                self.assertEqual(run.call_count, 1)

    def test_published_mode_uses_only_the_public_github_url_and_cleans_up(self) -> None:
        with patch.object(smoke, "verify_consumer") as verify, patch.object(smoke, "candidate_repository") as candidate:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(smoke.main(["published", "--version", VERSION, "--source-sha", SHA]), 0)
            candidate.assert_not_called()
            workspace, url, version, sha = verify.call_args.args
            self.assertEqual((url, version, sha), (smoke.PACKAGE_URL, VERSION, SHA))
            self.assertFalse(workspace.exists())

    def test_failed_consumer_cleans_up_and_returns_failure(self) -> None:
        with patch.object(smoke, "verify_consumer", side_effect=SwiftReleaseError("failed")) as verify:
            with redirect_stderr(io.StringIO()):
                self.assertEqual(smoke.main(["published", "--version", VERSION, "--source-sha", SHA]), 2)
            self.assertFalse(verify.call_args.args[0].exists())


if __name__ == "__main__":
    unittest.main()
