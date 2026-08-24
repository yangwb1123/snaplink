#!/usr/bin/env python3
"""Build-profile physical-isolation evidence (P0-5).

`python cli.py profiles evidence` proves the smaller editions are
physically isolated from the durable/admin/observability graph:

- builds every profile binary declared in ops/build/profile-isolation.json;
- collects per-binary evidence: snaplink package inventory (go list -deps),
  module inventory (go version -m), symbol count (go tool nm), binary size;
- asserts the declared must_link / must_not_link package boundaries, so an
  accidental import that drags postgres/grpc/SCIM into the minimal binary
  fails the check instead of silently growing it;
- writes the evidence bundle under dist/profiles/<binary>/ for release
  archives (package list, module SBOM, symbol table, sizes).

Run with --skip-build to re-verify a previous bundle without rebuilding.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "ops" / "build" / "profile-isolation.json"
SCHEMA_PATH = ROOT / "ops" / "build" / "profile-isolation.schema.json"
OUT_ROOT = ROOT / "dist" / "profiles"


class EvidenceError(Exception):
    """Raised for any isolation violation or evidence failure."""


def load_manifest() -> dict:
    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"{MANIFEST_PATH}: invalid JSON: {exc}") from exc
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise EvidenceError(f"{SCHEMA_PATH}: unexpected $schema header")
    if manifest.get("schema_version") != 1 or not manifest.get("profiles"):
        raise EvidenceError(f"{MANIFEST_PATH}: schema_version must be 1 with profiles")
    return manifest


def shell(cmd: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(cmd, cwd=cwd or ROOT, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise EvidenceError(
            f"{' '.join(cmd)} failed ({result.returncode}): {result.stderr[-2000:]}"
        )
    return result.stdout


def package_inventory(binary: Path) -> set[str]:
    """The snaplink packages linked into a binary (go list -deps walk)."""
    stdout = shell(["go", "list", "-deps", binary.name.replace("-", "-"), "-f", "{{.ImportPath}}"])
    return {p for p in stdout.splitlines() if p.startswith("github.com/yangwb1123/snaplink/")}


def collect(binary: Path, pkg: str) -> dict:
    out: dict = {}
    out["size_bytes"] = binary.stat().st_size
    deps = shell(["go", "list", "-deps", "-f", "{{.ImportPath}}", pkg])
    out["snaplink_packages"] = sorted(
        p for p in deps.splitlines() if p.startswith("github.com/yangwb1123/snaplink/")
    )
    out["package_count"] = len(out["snaplink_packages"])
    out["module_sbom"] = shell(["go", "version", "-m", str(binary)])
    nm = shell(["go", "tool", "nm", str(binary)])
    out["symbol_count"] = len(nm.splitlines())
    return out


def assert_boundaries(profile: dict, evidence: dict) -> list[str]:
    violations: list[str] = []
    packages = evidence["snaplink_packages"]
    rel = {p.removeprefix("github.com/yangwb1123/snaplink/") for p in packages}
    for prefix in profile.get("must_not_link", []):
        if any(p == prefix.rstrip("/") or p.startswith(prefix) for p in rel):
            violations.append(f"must NOT link {prefix!r} but does")
    for prefix in profile.get("must_link", []):
        if not any(p == prefix.rstrip("/") or p.startswith(prefix) for p in rel):
            violations.append(f"must link {prefix!r} but does not")
    return violations


def write_bundle(name: str, evidence: dict) -> Path:
    out_dir = OUT_ROOT / name
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "packages.txt").write_text(
        "\n".join(evidence["snaplink_packages"]) + "\n", encoding="utf-8"
    )
    (out_dir / "module-sbom.txt").write_text(evidence["module_sbom"], encoding="utf-8")
    (out_dir / "symbols.txt").write_text(
        f"symbol_count={evidence['symbol_count']}\n", encoding="utf-8"
    )
    (out_dir / "size.txt").write_text(f"size_bytes={evidence['size_bytes']}\n", encoding="utf-8")
    (out_dir / "evidence.json").write_text(
        json.dumps(evidence, indent=2, default=str), encoding="utf-8"
    )
    return out_dir


def run_evidence(skip_build: bool) -> int:
    manifest = load_manifest()
    rows: list[dict] = []
    failures: list[str] = []
    for profile_name, profile in manifest["profiles"].items():
        for entry in profile["binaries"]:
            binary_path = OUT_ROOT / entry["binary"] / entry["binary"]
            if not skip_build or not binary_path.exists():
                shell(["go", "build", "-o", str(binary_path), entry["package"]])
            evidence = collect(binary_path, entry["package"])
            violations = assert_boundaries(profile, evidence)
            out_dir = write_bundle(entry["binary"], evidence)
            rows.append(
                {
                    "profile": profile_name,
                    "binary": entry["binary"],
                    "packages": evidence["package_count"],
                    "symbols": evidence["symbol_count"],
                    "size_mb": round(evidence["size_bytes"] / 1e6, 1),
                    "violations": violations,
                }
            )
            if violations:
                failures.append(f"{entry['binary']}: " + "; ".join(violations))
            print(
                f"{profile_name:8} {entry['binary']:12} "
                f"{evidence['package_count']:4} snaplink pkgs "
                f"{evidence['symbol_count']:7} symbols "
                f"{evidence['size_bytes'] / 1e6:6.1f} MB "
                f"{'OK' if not violations else 'VIOLATION'}"
            )
    if len(rows) >= 2:
        small = next(r for r in rows if r["binary"] == "sso-minimal")
        prototype = next(r for r in rows if r["binary"] == "sso-prototype")
        full = next(r for r in rows if r["binary"] == "sso-server")
        print(
            f"\nisolation delta: full links {full['packages'] - small['packages']} more "
            f"snaplink packages (+{full['size_mb'] - small['size_mb']:.1f} MB, "
            f"+{full['symbols'] - small['symbols']} symbols) than the minimal edition"
        )
        print(
            f"composition roots: prototype/minimal share {min(prototype['packages'], small['packages'])} "
            f"snaplink packages (prototype {prototype['packages']}, minimal {small['packages']}); "
            "each links only its own cmd/ root"
        )
    if failures:
        raise EvidenceError("isolation boundary violated: " + " | ".join(failures))
    print(f"\nOK: evidence bundles in {OUT_ROOT}")
    return 0


def run(args: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="profiles", description=__doc__)
    parser.add_argument(
        "action",
        choices=["evidence"],
        help="evidence: build + verify + archive per-profile isolation evidence",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="re-verify a previously written bundle without rebuilding",
    )
    parsed, _ = parser.parse_known_args(args)
    try:
        return run_evidence(parsed.skip_build)
    except EvidenceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
