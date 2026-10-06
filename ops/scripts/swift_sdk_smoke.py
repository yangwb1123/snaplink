#!/usr/bin/env python3
"""Install an exact Swift prerelease in an isolated, executable SwiftPM consumer."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlsplit

from swift_sdk_release import ROOT, REPOSITORY, VERSION_PATH, SwiftReleaseError, validate_prerelease


PACKAGE_URL = f"https://github.com/{REPOSITORY}.git"
_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z", re.ASCII)
_CONSUMER_SOURCE = '''import Foundation
import SnaplinkSSO

let configuration = try SnaplinkConfiguration(
    issuerBaseURL: URL(string: "https://sso.example.invalid")!,
    clientID: "swift-package-smoke",
    redirectURI: URL(string: "snaplink-smoke://oauth/callback")!
)
let client = SnaplinkAuthClient(configuration: configuration)
let error = SnaplinkAuthError(code: "invalid_grant", message: "smoke", statusCode: 400)
precondition(configuration.clientID == "swift-package-smoke")
precondition(error.code == "invalid_grant" && error.status == 400)
print("PASS: SnaplinkSSO consumer")
'''


def _environment() -> dict[str, str]:
    # Public GitHub consumption must not need publisher credentials or inherit
    # Git directory overrides, credential helpers, or URL rewrite configuration.
    result = {key: value for key, value in os.environ.items()
              if not key.startswith("GIT_") and key not in ("GH_TOKEN", "GITHUB_TOKEN")}
    result.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")
    return result


def _run(command: list[str], cwd: Path, *, check: bool = True) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(command, cwd=cwd, env=_environment(), text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
    except (OSError, subprocess.TimeoutExpired):
        raise SwiftReleaseError(f"{command[0]} consumer check could not complete") from None
    if check and result.returncode:
        # Arguments never contain credentials; emit build diagnostics, not the
        # inherited environment or subprocess exception representation.
        print(result.stdout, file=sys.stderr)
        raise SwiftReleaseError(f"{command[0]} consumer check failed")
    return result


def validate_inputs(version: str, source_sha: str) -> None:
    validate_prerelease(version)
    if not _SHA.fullmatch(source_sha):
        raise SwiftReleaseError("consumer verification requires the full source commit SHA")


def candidate_repository(root: Path, workspace: Path, version: str, source_sha: str) -> Path:
    validate_inputs(version, source_sha)
    actual = _run(["git", "rev-parse", "HEAD"], root).stdout.strip()
    if actual != source_sha:
        raise SwiftReleaseError("candidate checkout does not match the expected source commit")
    committed = _run(["git", "show", f"{source_sha}:{VERSION_PATH}"], root).stdout.removesuffix("\n")
    if committed != version:
        raise SwiftReleaseError("candidate version must match the committed VERSION file")
    repository = workspace / "snaplink.git"
    _run(["git", "clone", "--bare", "--no-local", root.resolve().as_uri(), str(repository)], workspace)
    reference = f"refs/tags/{version}"
    tag = _run(["git", "rev-parse", "--verify", "--quiet", f"{reference}^{{commit}}"], repository, check=False)
    if tag.returncode == 0:
        if tag.stdout.strip() != source_sha:
            raise SwiftReleaseError("candidate version tag belongs to another commit")
    else:
        # Compare against an absent ref: never replace even a malformed tag.
        _run(["git", "update-ref", reference, source_sha, ""], repository)
    return repository


def write_consumer(workspace: Path, url: str, version: str) -> Path:
    consumer = workspace / "consumer"
    consumer.mkdir()
    manifest = f'''// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SnaplinkConsumer",
    platforms: [.macOS(.v14), .iOS(.v17)],
    dependencies: [.package(url: {json.dumps(url)}, exact: {json.dumps(version)})],
    targets: [.executableTarget(
        name: "SnaplinkConsumer",
        dependencies: [.product(name: "SnaplinkSSO", package: "snaplink")],
        path: "Sources"
    )]
)
'''
    (consumer / "Package.swift").write_text(manifest, encoding="utf-8")
    source = consumer / "Sources"
    source.mkdir()
    (source / "main.swift").write_text(_CONSUMER_SOURCE, encoding="utf-8")
    return consumer


def validate_resolution(lock: dict, url: str, version: str, source_sha: str) -> None:
    if not isinstance(lock, dict) or lock.get("version") not in (2, 3):
        raise SwiftReleaseError("unsupported SwiftPM resolution file")
    pins = lock.get("pins")
    if not isinstance(pins, list) or len(pins) != 1 or not isinstance(pins[0], dict):
        raise SwiftReleaseError("consumer must resolve exactly the Snaplink package")
    pin = pins[0]
    state = pin.get("state")
    parsed = urlsplit(url)
    local = parsed.scheme == "file"
    # SwiftPM records file-URL Git dependencies as an absolute filesystem path.
    location = unquote(parsed.path) if local else url
    kind = "localSourceControl" if local else "remoteSourceControl"
    if (pin.get("identity") != "snaplink" or pin.get("location") != location
            or pin.get("kind") != kind
            or not isinstance(state, dict) or state.get("version") != version
            or state.get("revision") != source_sha or state.get("branch") is not None):
        raise SwiftReleaseError("resolved Swift package does not match the version, repository, and source commit")


def verify_consumer(workspace: Path, url: str, version: str, source_sha: str) -> None:
    validate_inputs(version, source_sha)
    consumer = write_consumer(workspace, url, version)
    options = ["--package-path", str(consumer), "--scratch-path", str(workspace / "build"),
               "--cache-path", str(workspace / "cache"), "--config-path", str(workspace / "config"),
               "--security-path", str(workspace / "security"), "--disable-dependency-cache",
               "--disable-keychain", "--disable-netrc"]
    _run(["swift", "package", *options, "resolve"], consumer)
    try:
        lock = json.loads((consumer / "Package.resolved").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise SwiftReleaseError("cannot read the consumer's SwiftPM resolution file") from None
    validate_resolution(lock, url, version, source_sha)
    flags = ["-c", "release", "-Xswiftc", "-strict-concurrency=complete", "-Xswiftc", "-warnings-as-errors"]
    _run(["swift", "build", *options, "--force-resolved-versions", *flags], consumer)
    result = _run(["swift", "run", *options, "--force-resolved-versions", "-c", "release",
                   "--skip-build", "SnaplinkConsumer"], consumer)
    if "PASS: SnaplinkSSO consumer" not in result.stdout.splitlines():
        raise SwiftReleaseError("installed Swift consumer did not complete its public API smoke check")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("candidate", "published"):
        command = commands.add_parser(name)
        command.add_argument("--version", required=True)
        command.add_argument("--source-sha", required=True)
        if name == "candidate":
            command.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        validate_inputs(args.version, args.source_sha)
        with tempfile.TemporaryDirectory(prefix="snaplink-swift-consumer-") as directory:
            workspace = Path(directory).resolve()
            url = PACKAGE_URL
            if args.command == "candidate":
                url = candidate_repository(args.root, workspace, args.version, args.source_sha).as_uri()
            verify_consumer(workspace, url, args.version, args.source_sha)
        print(f"PASS: {args.command} SwiftPM install {args.version} at {args.source_sha}")
        return 0
    except (SwiftReleaseError, OSError, UnicodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
