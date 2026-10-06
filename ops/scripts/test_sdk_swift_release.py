"""Offline regression tests for SwiftPM release policy and publication retries."""

from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import MagicMock, patch

import swift_sdk_release as release


SHA = "a" * 40
OTHER_SHA = "b" * 40
VERSION = "0.3.0-beta.1"
PLAN = release.ReleasePlan(VERSION, SHA)


def _source_environment() -> dict[str, str]:
    return {
        "GITHUB_REPOSITORY": release.REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REF_PROTECTED": "true",
        "GITHUB_SHA": SHA,
    }


def _package() -> dict:
    return {
        "name": "SnaplinkSSO",
        "products": [{
            "name": "SnaplinkSSO", "type": {"library": ["automatic"]},
            "targets": ["SnaplinkSSO"],
        }],
        "targets": [{
            "name": "SnaplinkSSO", "type": "regular", "path": "sdks/swift/Sources",
        }],
    }


class FakeGitHub:
    def __init__(self) -> None:
        self.references: dict[str, dict] = {}
        self.releases: dict[str, dict] = {}
        self.annotations: dict[str, dict] = {}
        self.calls: list[tuple[str, dict | None]] = []

    def add_tag(self, sha: str = SHA) -> None:
        self.references[VERSION] = {
            "ref": f"refs/tags/{VERSION}", "object": {"type": "commit", "sha": sha},
        }

    def add_release(self) -> dict:
        value = {
            "tag_name": VERSION, "prerelease": True, "draft": False,
            "html_url": f"https://github.com/{release.REPOSITORY}/releases/tag/{VERSION}",
        }
        self.releases[VERSION] = value
        return value

    def request(self, path: str, payload: dict | None = None) -> dict | None:
        self.calls.append((path, copy.deepcopy(payload)))
        if payload is None:
            if path.startswith("/git/ref/tags/"):
                return copy.deepcopy(self.references.get(path.removeprefix("/git/ref/tags/")))
            if path.startswith("/git/tags/"):
                return copy.deepcopy(self.annotations.get(path.removeprefix("/git/tags/")))
            if path.startswith("/releases/tags/"):
                return copy.deepcopy(self.releases.get(path.removeprefix("/releases/tags/")))
        elif path == "/git/refs":
            if VERSION in self.references:
                raise release.GitHubError(422)
            self.add_tag(payload["sha"])
            return copy.deepcopy(self.references[VERSION])
        elif path == "/releases":
            if VERSION in self.releases:
                raise release.GitHubError(422)
            return copy.deepcopy(self.add_release())
        raise AssertionError(f"unexpected API call: {path}")

    def writes(self) -> list[tuple[str, dict]]:
        return [(path, payload) for path, payload in self.calls if payload is not None]


class SwiftReleaseMetadataTests(unittest.TestCase):
    def test_committed_release_version_is_a_valid_prerelease(self) -> None:
        self.assertIn("-", release.load_version())

    def test_version_requires_plain_prerelease_semver(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / release.VERSION_PATH
            path.parent.mkdir(parents=True)
            for text in (VERSION, VERSION + "\n", "0.3.0-rc.2"):
                with self.subTest(valid=text):
                    path.write_text(text, encoding="ascii")
                    self.assertEqual(release.load_version(root), text.rstrip("\n"))
            for text in (
                "0.3.0", "v0.3.0-beta.1", "sdk-swift-v0.3.0-beta.1", "01.3.0-beta.1",
                "0.3.0-beta.01", "0.3.0-beta.1+build", "", " " + VERSION,
                VERSION + "\n\n", VERSION + "\nversion=evil", VERSION + "\x00",
            ):
                with self.subTest(invalid=text):
                    path.write_text(text, encoding="ascii")
                    with self.assertRaises(release.SwiftReleaseError):
                        release.load_version(root)

    def test_missing_or_non_ascii_version_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(release.SwiftReleaseError):
                release.load_version(root)
            path = root / release.VERSION_PATH
            path.parent.mkdir(parents=True)
            path.write_bytes(b"\xff")
            with self.assertRaises(release.SwiftReleaseError):
                release.load_version(root)

    def test_source_requires_the_protected_repository_main_and_exact_sha(self) -> None:
        release.validate_source(_source_environment(), SHA)
        for key, value in (
            ("GITHUB_REPOSITORY", "attacker/snaplink"),
            ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_REF", f"refs/tags/{VERSION}"),
            ("GITHUB_REF_PROTECTED", "false"),
            ("GITHUB_REF_PROTECTED", ""),
            ("GITHUB_SHA", "HEAD"),
            ("GITHUB_SHA", OTHER_SHA),
            ("GITHUB_SHA", SHA + "\n"),
        ):
            with self.subTest(key=key, value=value):
                environment = _source_environment()
                environment[key] = value
                with self.assertRaises(release.SwiftReleaseError):
                    release.validate_source(environment, SHA)

    def test_prepare_plan_checks_the_actual_git_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / release.VERSION_PATH
            path.parent.mkdir(parents=True)
            path.write_text(VERSION)
            with patch.object(release.subprocess, "check_output", return_value=SHA + "\n") as git:
                self.assertEqual(release.prepare_plan(root, _source_environment()), PLAN)
                self.assertEqual(git.call_args.args[0], ["git", "rev-parse", "HEAD"])
            with patch.object(release.subprocess, "check_output", return_value=OTHER_SHA):
                with self.assertRaises(release.SwiftReleaseError):
                    release.prepare_plan(root, _source_environment())

    def test_manifest_requires_the_real_root_library_and_source_path(self) -> None:
        release.validate_package(_package())
        invalid = [[], {}, {"name": "SnaplinkSSO", "products": "invalid"}]
        for key, value in (("name", "Other"), ("type", "executable"), ("path", "wrong")):
            manifest = _package()
            manifest["targets"][0][key] = value
            invalid.append(manifest)
        manifest = _package()
        manifest["products"][0]["type"] = {"executable": None}
        invalid.append(manifest)
        manifest = _package()
        manifest["products"][0]["targets"] = ["Other"]
        invalid.append(manifest)
        manifest = _package()
        manifest["name"] = "Other"
        invalid.append(manifest)
        for manifest in invalid:
            with self.subTest(manifest=manifest):
                with self.assertRaises(release.SwiftReleaseError):
                    release.validate_package(manifest)

    def test_changed_version_cannot_reach_the_publication_client(self) -> None:
        with patch.object(release, "prepare_plan", return_value=PLAN):
            with patch.object(release, "GitHubAPI") as client, redirect_stderr(io.StringIO()):
                self.assertEqual(release.main(["publish", "--expected-version", "0.3.0-beta.2"]), 2)
                client.assert_not_called()


class SwiftReleasePublicationTests(unittest.TestCase):
    def test_new_publication_creates_only_a_plain_tag_and_prerelease(self) -> None:
        api = FakeGitHub()
        self.assertEqual(release.publish(api, PLAN), api.releases[VERSION]["html_url"])
        tag, publication = api.writes()
        self.assertEqual(tag, ("/git/refs", {"ref": f"refs/tags/{VERSION}", "sha": SHA}))
        self.assertEqual(publication[1]["target_commitish"], SHA)
        self.assertEqual(publication[1]["prerelease"], True)
        self.assertEqual(publication[1]["make_latest"], "false")
        self.assertIn(f'exact: "{VERSION}"', publication[1]["body"])
        self.assertIn("not approved for production", publication[1]["body"])

    def test_retry_of_the_same_publication_performs_no_writes(self) -> None:
        api = FakeGitHub()
        release.publish(api, PLAN)
        api.calls.clear()
        release.publish(api, PLAN)
        self.assertEqual(api.writes(), [])

    def test_retry_after_tag_creation_resumes_only_the_release(self) -> None:
        api = FakeGitHub()
        api.add_tag()
        release.publish(api, PLAN)
        self.assertEqual([path for path, _ in api.writes()], ["/releases"])

    def test_failed_release_creation_retains_the_tag_and_can_resume(self) -> None:
        api = FakeGitHub()
        original = api.request

        def outage(path, payload=None):
            if path == "/releases":
                raise release.GitHubError(503)
            return original(path, payload)

        with patch.object(api, "request", side_effect=outage):
            with self.assertRaises(release.GitHubError):
                release.publish(api, PLAN)
        self.assertEqual(api.references[VERSION]["object"]["sha"], SHA)
        self.assertEqual(api.releases, {})
        api.calls.clear()
        release.publish(api, PLAN)
        self.assertEqual([path for path, _ in api.writes()], ["/releases"])

    def test_existing_tag_at_another_commit_is_never_overwritten(self) -> None:
        api = FakeGitHub()
        api.add_tag(OTHER_SHA)
        with self.assertRaisesRegex(release.SwiftReleaseError, "another commit"):
            release.publish(api, PLAN)
        self.assertEqual(api.writes(), [])

    def test_existing_annotated_tag_is_peeled_without_changing_it(self) -> None:
        api = FakeGitHub()
        api.references[VERSION] = {
            "ref": f"refs/tags/{VERSION}", "object": {"type": "tag", "sha": OTHER_SHA},
        }
        api.annotations[OTHER_SHA] = {"sha": OTHER_SHA, "object": {"type": "commit", "sha": SHA}}
        release.publish(api, PLAN)
        self.assertEqual([path for path, _ in api.writes()], ["/releases"])

    def test_malformed_or_cyclic_tags_fail_closed(self) -> None:
        for obj in (None, {"type": "commit", "sha": "HEAD"}, {"type": "tree", "sha": SHA},
                    {"type": "tag", "sha": OTHER_SHA}):
            with self.subTest(obj=obj):
                api = FakeGitHub()
                api.references[VERSION] = {"ref": f"refs/tags/{VERSION}", "object": obj}
                api.annotations[OTHER_SHA] = {"sha": OTHER_SHA, "object": obj}
                with self.assertRaises(release.SwiftReleaseError):
                    release.publish(api, PLAN)
                self.assertEqual(api.writes(), [])

    def test_concurrent_tag_creation_must_match_the_verified_commit(self) -> None:
        for sha in (SHA, OTHER_SHA):
            with self.subTest(sha=sha):
                api = FakeGitHub()
                original = api.request

                def race(path, payload=None):
                    if path == "/git/refs":
                        api.add_tag(sha)
                        raise release.GitHubError(422)
                    return original(path, payload)

                with patch.object(api, "request", side_effect=race):
                    if sha == SHA:
                        release.publish(api, PLAN)
                    else:
                        with self.assertRaises(release.SwiftReleaseError):
                            release.publish(api, PLAN)
                        self.assertEqual(api.writes(), [])

    def test_duplicate_release_creation_can_resume_without_editing(self) -> None:
        api = FakeGitHub()
        api.add_tag()
        original = api.request

        def race(path, payload=None):
            if path == "/releases":
                api.add_release()
                raise release.GitHubError(422)
            return original(path, payload)

        with patch.object(api, "request", side_effect=race):
            release.publish(api, PLAN)
        self.assertEqual(api.writes(), [])

    def test_existing_draft_or_stable_release_is_not_rewritten(self) -> None:
        for key, value in (("draft", True), ("prerelease", False), ("tag_name", "other"),
                           ("html_url", "https://attacker.example/release")):
            with self.subTest(key=key):
                api = FakeGitHub()
                api.add_tag()
                api.add_release()[key] = value
                with self.assertRaises(release.SwiftReleaseError):
                    release.publish(api, PLAN)
                self.assertEqual(api.writes(), [])

    def test_api_authorization_failures_never_become_missing_tags(self) -> None:
        api = FakeGitHub()
        with patch.object(api, "request", side_effect=release.GitHubError(403)):
            with self.assertRaises(release.GitHubError):
                release.publish(api, PLAN)
        self.assertEqual(api.writes(), [])

    def test_tag_change_during_release_is_detected_not_repaired(self) -> None:
        api = FakeGitHub()
        original = api.request

        def race(path, payload=None):
            result = original(path, payload)
            if path == "/releases":
                api.add_tag(OTHER_SHA)
            return result

        with patch.object(api, "request", side_effect=race):
            with self.assertRaises(release.SwiftReleaseError):
                release.publish(api, PLAN)
        self.assertEqual([path for path, _ in api.writes()], ["/git/refs", "/releases"])


class SwiftReleaseAPITests(unittest.TestCase):
    def test_empty_token_is_rejected(self) -> None:
        with self.assertRaisesRegex(release.SwiftReleaseError, "GH_TOKEN"):
            release.GitHubAPI("")

    def test_fixed_endpoint_header_and_post_method(self) -> None:
        api = release.GitHubAPI("test-secret")
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'{"ok": true}'
        with patch.object(api.opener, "open", return_value=response) as opener:
            self.assertEqual(api.request("/git/refs", {"ref": "test"}), {"ok": True})
        request = opener.call_args.args[0]
        self.assertEqual(request.full_url, f"https://api.github.com/repos/{release.REPOSITORY}/git/refs")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Authorization"), "Bearer test-secret")
        self.assertEqual(json.loads(request.data), {"ref": "test"})
        self.assertEqual(opener.call_args.kwargs["timeout"], 30)

    def test_only_a_get_404_is_treated_as_missing(self) -> None:
        api = release.GitHubAPI("test-secret")
        for code in (301, 403, 404, 422, 500):
            with self.subTest(code=code):
                error = urllib.error.HTTPError("https://api.github.com", code, "test-secret", {}, None)
                with patch.object(api.opener, "open", side_effect=error):
                    if code == 404:
                        self.assertIsNone(api.request("/git/ref/tags/test"))
                    else:
                        with self.assertRaises(release.GitHubError) as raised:
                            api.request("/git/ref/tags/test")
                        self.assertNotIn("test-secret", str(raised.exception))
                    with self.assertRaises(release.GitHubError):
                        api.request("/git/refs", {})

    def test_redirects_are_refused(self) -> None:
        handler = release._NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, "redirect", {}, "https://attacker.example"))

    def test_invalid_oversized_or_non_object_responses_fail_closed(self) -> None:
        api = release.GitHubAPI("test-secret")
        for raw in (b"invalid", b"[]", b"null", b"\xff", b"x" * (release._RESPONSE_LIMIT + 1)):
            with self.subTest(raw=raw[:12]):
                response = MagicMock()
                response.__enter__.return_value.read.return_value = raw
                with patch.object(api.opener, "open", return_value=response):
                    with self.assertRaises(release.SwiftReleaseError):
                        api.request("/git/ref/tags/test")


class SwiftReleaseWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        import yaml
        path = release.ROOT / ".github/workflows/sdk-swift-release.yml"
        self.workflow = yaml.safe_load(path.read_text(encoding="utf-8"))

    def test_trigger_and_write_permissions_are_bounded(self) -> None:
        # PyYAML's YAML 1.1 parser treats the Actions key `on` as a boolean.
        triggers = self.workflow.get("on", self.workflow.get(True))
        self.assertEqual(triggers["push"]["branches"], ["main"])
        self.assertEqual(triggers["push"]["paths"], ["sdks/swift/VERSION"])
        self.assertIn("workflow_dispatch", triggers)
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        jobs = self.workflow["jobs"]
        self.assertEqual(jobs["publish"]["permissions"], {"contents": "write"})
        self.assertEqual(set(jobs["publish"]["needs"]), {"plan", "verify-root", "verify-swift"})
        for name, job in jobs.items():
            if name != "publish":
                self.assertNotIn("write", job.get("permissions", {}).values())
            self.assertIn({"ref": "${{ github.sha }}", "fetch-depth": 0, "persist-credentials": False},
                          [step.get("with") for step in job["steps"] if step.get("uses") == "actions/checkout@v4"])

    def test_root_and_swift_checks_cannot_be_skipped_before_publication(self) -> None:
        jobs = self.workflow["jobs"]
        root_commands = [step.get("run", "") for step in jobs["verify-root"]["steps"]]
        self.assertIn("make ci", root_commands)
        swift_commands = "\n".join(step.get("run", "") for step in jobs["verify-swift"]["steps"])
        for required in ("swift test", "-strict-concurrency=complete", "-warnings-as-errors",
                         "-c release", "arm64-apple-ios17.0", "arm64-apple-ios17.0-simulator",
                         "--scratch-path", "--sdk", "dump-package", "swift_sdk_release.py package",
                         "swift_sdk_smoke.py candidate", "--source-sha"):
            self.assertIn(required, swift_commands)
        self.assertNotIn("SDKROOT=", swift_commands)
        self.assertIn('"$GITHUB_ENV"', swift_commands)
        candidate = next(step for step in jobs["verify-swift"]["steps"]
                         if "swift_sdk_smoke.py candidate" in step.get("run", ""))
        self.assertEqual(candidate["env"], {
            "RELEASE_VERSION": "${{ needs.plan.outputs.version }}",
            "SOURCE_SHA": "${{ github.sha }}",
        })
        for name in ("verify-root", "verify-swift"):
            self.assertNotIn("if", jobs[name])
            for step in jobs[name]["steps"]:
                self.assertFalse(step.get("continue-on-error", False))
        publisher = jobs["publish"]["steps"][-1]
        self.assertEqual(publisher["env"]["GH_TOKEN"], "${{ github.token }}")
        self.assertIn("--expected-version", publisher["run"])

    def test_published_installation_is_a_required_read_only_github_check(self) -> None:
        job = self.workflow["jobs"]["verify-install"]
        self.assertEqual(set(job["needs"]), {"plan", "publish"})
        self.assertEqual(job["permissions"], {"contents": "read"})
        self.assertNotIn("if", job)
        for step in job["steps"]:
            self.assertFalse(step.get("continue-on-error", False))
            self.assertNotIn("GH_TOKEN", step.get("env", {}))
        check = job["steps"][-1]
        self.assertIn("swift_sdk_smoke.py published", check["run"])
        self.assertEqual(check["env"], {
            "RELEASE_VERSION": "${{ needs.plan.outputs.version }}",
            "SOURCE_SHA": "${{ github.sha }}",
        })

    def test_pull_request_ci_includes_release_safeguards(self) -> None:
        import yaml
        path = release.ROOT / ".github/workflows/sdk-ci.yml"
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        triggers = workflow.get("on", workflow.get(True))
        for event in ("push", "pull_request"):
            for required in (".github/workflows/sdk-swift-release.yml",
                             "ops/scripts/swift_sdk_release.py",
                             "ops/scripts/test_sdk_swift_release.py",
                             "ops/scripts/swift_sdk_smoke.py", "ops/scripts/test_sdk_swift_smoke.py"):
                self.assertIn(required, triggers[event]["paths"])
        commands = "\n".join(step.get("run", "") for step in workflow["jobs"]["surface"]["steps"])
        self.assertIn("swift_sdk_release.py version", commands)
        self.assertIn("test_sdk_*.py", commands)
        swift_commands = "\n".join(step.get("run", "") for step in workflow["jobs"]["swift"]["steps"])
        self.assertIn("swift_sdk_smoke.py candidate", swift_commands)
        self.assertIn("--source-sha", swift_commands)
        checkout = workflow["jobs"]["swift"]["steps"][0]
        self.assertEqual(checkout["with"], {"ref": "${{ github.sha }}", "persist-credentials": False})


if __name__ == "__main__":
    unittest.main()
