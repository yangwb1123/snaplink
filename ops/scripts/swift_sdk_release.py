#!/usr/bin/env python3
"""Validate and publish the experimental SwiftPM SDK without moving release tags."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from sdk_versions import SDKVersionError, validate_semver


ROOT = Path(__file__).resolve().parents[2]
VERSION_PATH = Path("sdks/swift/VERSION")
REPOSITORY = "yangwb1123/snaplink"
PACKAGE_NAME = "SnaplinkSSO"
_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z", re.ASCII)
_RESPONSE_LIMIT = 1024 * 1024


class SwiftReleaseError(ValueError):
    """Raised when release metadata, source, or an existing publication is unsafe."""


class GitHubError(SwiftReleaseError):
    def __init__(self, status: int) -> None:
        super().__init__(f"GitHub API failed with HTTP {status}")
        self.status = status


@dataclass(frozen=True)
class ReleasePlan:
    version: str
    source_sha: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # A redirect must never forward the publication token to another host.
        return None


class GitHubAPI:
    def __init__(self, token: str) -> None:
        if not token:
            raise SwiftReleaseError("GH_TOKEN is required for publication")
        self.token = token
        self.opener = urllib.request.build_opener(_NoRedirect())

    def request(self, path: str, payload: dict | None = None) -> dict | None:
        request = urllib.request.Request(
            f"https://api.github.com/repos/{REPOSITORY}{path}",
            data=json.dumps(payload).encode("utf-8") if payload is not None else None,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "SnaplinkSSO-release",
            },
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read(_RESPONSE_LIMIT + 1)
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            if status == 404 and payload is None:
                return None
            raise GitHubError(status) from None
        except (OSError, urllib.error.URLError):
            raise SwiftReleaseError("GitHub API request failed") from None
        if len(raw) > _RESPONSE_LIMIT:
            raise SwiftReleaseError("GitHub API response is too large")
        try:
            result = json.loads(raw)
        except (UnicodeError, ValueError):
            raise SwiftReleaseError("GitHub API returned invalid JSON") from None
        if not isinstance(result, dict):
            raise SwiftReleaseError("GitHub API response must be an object")
        return result


def load_version(root: Path = ROOT) -> str:
    try:
        text = (root / VERSION_PATH).read_text(encoding="ascii")
    except (OSError, UnicodeError):
        raise SwiftReleaseError(f"{VERSION_PATH}: cannot read release version") from None
    version = text.removesuffix("\n")
    validate_prerelease(version)
    return version


def validate_prerelease(version: str) -> None:
    try:
        validate_semver(version, str(VERSION_PATH))
    except SDKVersionError as exc:
        raise SwiftReleaseError(str(exc)) from None
    if "+" in version or "-" not in version:
        raise SwiftReleaseError("experimental Swift releases require a prerelease without build metadata")


def validate_source(environ: dict[str, str], actual_sha: str) -> None:
    if environ.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise SwiftReleaseError(f"release repository must be {REPOSITORY}")
    if environ.get("GITHUB_REF") != "refs/heads/main":
        raise SwiftReleaseError("Swift releases must originate from main")
    if environ.get("GITHUB_REF_PROTECTED") != "true":
        raise SwiftReleaseError("main must be protected by a GitHub branch rule or ruleset")
    source_sha = environ.get("GITHUB_SHA", "")
    if not _SHA.fullmatch(source_sha) or source_sha != actual_sha:
        raise SwiftReleaseError("checked-out commit must match the full workflow source SHA")


def prepare_plan(root: Path, environ: dict[str, str]) -> ReleasePlan:
    try:
        actual_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        raise SwiftReleaseError("cannot resolve checked-out source commit") from None
    validate_source(environ, actual_sha)
    return ReleasePlan(load_version(root), actual_sha)


def validate_package(manifest: dict) -> None:
    if not isinstance(manifest, dict) or manifest.get("name") != PACKAGE_NAME:
        raise SwiftReleaseError("root SwiftPM package must be SnaplinkSSO")
    products = manifest.get("products", [])
    targets = manifest.get("targets", [])
    if not isinstance(products, list) or not isinstance(targets, list):
        raise SwiftReleaseError("SwiftPM products and targets must be arrays")
    product_ok = any(
        isinstance(item, dict) and item.get("name") == PACKAGE_NAME
        and isinstance(item.get("type"), dict) and "library" in item["type"]
        and item.get("targets") == [PACKAGE_NAME]
        for item in products
    )
    target_ok = any(
        isinstance(item, dict) and item.get("name") == PACKAGE_NAME
        and item.get("type") == "regular" and item.get("path") == "sdks/swift/Sources"
        for item in targets
    )
    if not product_ok or not target_ok:
        raise SwiftReleaseError("SnaplinkSSO must export the library from sdks/swift/Sources")


def _tag_commit(api: GitHubAPI, reference: dict, version: str) -> str:
    if reference.get("ref") != f"refs/tags/{version}":
        raise SwiftReleaseError("GitHub returned an unexpected release tag")
    obj = reference.get("object")
    for _ in range(5):
        if not isinstance(obj, dict) or not _SHA.fullmatch(str(obj.get("sha", ""))):
            raise SwiftReleaseError("release tag object is invalid")
        if obj.get("type") == "commit":
            return obj["sha"]
        if obj.get("type") != "tag":
            raise SwiftReleaseError("release tag does not point to a commit")
        tag = api.request(f"/git/tags/{obj['sha']}")
        if tag is None or tag.get("sha") != obj["sha"]:
            raise SwiftReleaseError("annotated release tag is missing or mismatched")
        obj = tag.get("object")
    raise SwiftReleaseError("release tag annotation chain is too deep")


def ensure_tag(api: GitHubAPI, plan: ReleasePlan) -> None:
    path = f"/git/ref/tags/{plan.version}"
    reference = api.request(path)
    if reference is None:
        try:
            api.request("/git/refs", {
                "ref": f"refs/tags/{plan.version}", "sha": plan.source_sha,
            })
        except GitHubError as exc:
            if exc.status not in (409, 422):
                raise
            # A concurrent creator is safe only if it created exactly our tag.
        reference = api.request(path)
    if reference is None or _tag_commit(api, reference, plan.version) != plan.source_sha:
        raise SwiftReleaseError("version tag is missing or belongs to another commit; choose a new version")


def _release_payload(plan: ReleasePlan) -> dict:
    return {
        "tag_name": plan.version,
        "target_commitish": plan.source_sha,
        "name": f"{PACKAGE_NAME} {plan.version}",
        "prerelease": True,
        "draft": False,
        "make_latest": "false",
        "body": (
            "Experimental SwiftPM SDK; not approved for production use.\n\n"
            "Requires iOS/iPadOS 17+ or macOS 14+, and Swift 5.9+.\n\n"
            "```swift\n"
            f'.package(url: "https://github.com/{REPOSITORY}.git", '
            f'exact: "{plan.version}")\n'
            "```\n\n"
            f"Select the `{PACKAGE_NAME}` product. No binary upload is required.\n\n"
            f"Verified source commit: `{plan.source_sha}`.\n"
            "Browser UI and real-device Keychain acceptance remain outstanding.\n"
        ),
    }


def ensure_release(api: GitHubAPI, plan: ReleasePlan) -> str:
    path = f"/releases/tags/{plan.version}"
    release = api.request(path)
    if release is None:
        try:
            release = api.request("/releases", _release_payload(plan))
        except GitHubError as exc:
            if exc.status not in (409, 422):
                raise
            release = api.request(path)
    expected_url = f"https://github.com/{REPOSITORY}/releases/tag/{plan.version}"
    if release is None or (
        release.get("tag_name") != plan.version
        or release.get("prerelease") is not True
        or release.get("draft") is not False
        or release.get("html_url") != expected_url
    ):
        raise SwiftReleaseError("existing or created Release is not the expected published prerelease")
    return expected_url


def publish(api: GitHubAPI, plan: ReleasePlan) -> str:
    ensure_tag(api, plan)
    url = ensure_release(api, plan)
    # Detect a concurrent tag change as a failure, never repair it by force.
    ensure_tag(api, plan)
    return url


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("version", help="validate the committed prerelease version")
    commands.add_parser("plan", help="validate protected main and report the version")
    package = commands.add_parser("package", help="validate swift package dump-package output")
    package.add_argument("--manifest-json", type=Path, required=True)
    publication = commands.add_parser("publish", help="create or resume an immutable prerelease")
    publication.add_argument("--expected-version", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "version":
            print(load_version())
        elif args.command == "package":
            validate_package(json.loads(args.manifest_json.read_text(encoding="utf-8")))
            print("PASS: root SwiftPM library manifest")
        else:
            plan = prepare_plan(ROOT, dict(os.environ))
            if args.command == "plan":
                print(plan.version)
            else:
                if args.expected_version != plan.version:
                    raise SwiftReleaseError("release version changed after verification")
                url = publish(GitHubAPI(os.environ.get("GH_TOKEN", "")), plan)
                print(url)
                summary = os.environ.get("GITHUB_STEP_SUMMARY")
                if summary:
                    with open(summary, "a", encoding="utf-8") as output:
                        output.write(f"SwiftPM prerelease: [{plan.version}]({url})\n")
        return 0
    except (SwiftReleaseError, OSError, UnicodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
