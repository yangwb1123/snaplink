#!/usr/bin/env python3
"""Pin the public SKU release artifact and evidence contracts."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ops" / "scripts"))

import profile_release


def _release_config() -> dict:
    return yaml.safe_load((ROOT / ".goreleaser.yaml").read_text(encoding="utf-8"))


def _by_id(items: list[dict]) -> dict[str, dict]:
    return {item["id"]: item for item in items}


@pytest.mark.parametrize("profile", profile_release.PROFILES)
def test_profile_build_uses_configured_target_inputs_and_verifier(profile: str):
    build = _by_id(_release_config()["builds"])[f"snaplink-{profile}"]
    expected = {
        "prototype": ("./cmd/sso-minimal", "snaplink"),
        "minimal": ("./cmd/sso-minimal", "snaplink"),
        "full": ("./cmd/sso-server", "snaplink"),
        "billing": ("./cmd/snaplink-billing", "snaplink-billing"),
    }
    targets = {
        tuple(target.split("/")) for target in profile_release.PROFILE_TARGETS[profile]
    }

    assert (build["main"], build["binary"]) == expected[profile]
    assert build["tags"] == ["snaplink_configured"]
    assert set(build["goos"]) == {target[0] for target in targets}
    assert set(build["goarch"]) == {target[1] for target in targets}
    flags = "\n".join(build["flags"])
    assert f"/{profile}/{{{{ .Os }}}}_{{{{ .Arch }}}}/modules.mod" in flags
    assert f"/{profile}/{{{{ .Os }}}}_{{{{ .Arch }}}}/overlay.json" in flags
    hook = build["hooks"]["post"][0]["cmd"]
    assert "profile_release.py verify-binary" in hook
    assert f"--profile {profile}" in hook

    overrides = {
        (item["goos"], item["goarch"]): "\n".join(item["ldflags"])
        for item in build["overrides"]
    }
    assert set(overrides) == targets
    for (goos, goarch), ldflags in overrides.items():
        prefix = f"SNAPLINK_RELEASE_{profile.upper()}"
        assert f"BuildProfile={profile}" in ldflags
        assert f"{prefix}_{goos.upper()}_{goarch.upper()}_LOCK_DIGEST" in ldflags
        assert f"{prefix}_MODULES" in ldflags
        assert f"{prefix}_CAPABILITIES" in ldflags


@pytest.mark.parametrize("profile", profile_release.PROFILES)
def test_profile_archive_contains_target_evidence(profile: str):
    config = _release_config()
    archive = _by_id(config["archives"])[f"snaplink-{profile}"]

    assert archive["ids"] == [f"snaplink-{profile}"]
    external = [item for item in archive["files"] if isinstance(item, dict)]
    assert {Path(item["src"]).name for item in external} == {
        "modules.lock.json",
        "profile-inventory.json",
        "binary-evidence.json",
    }
    assert {item["dst"] for item in external} == {
        "evidence/modules.lock.json",
        "evidence/profile-inventory.json",
        "evidence/binary-evidence.json",
    }
    assert all(f"/{profile}/" in item["src"] for item in external)
    assert config["sboms"] == [{"artifacts": "archive"}]


def test_default_archive_does_not_absorb_profile_builds():
    default = _by_id(_release_config()["archives"])["default"]

    for profile in profile_release.PROFILES:
        assert f"snaplink-{profile}" not in default["ids"]
    assert default["allow_different_binary_count"] is True


def test_nested_sso_mcp_build_runs_from_its_module_root():
    build = _by_id(_release_config()["builds"])["sso-mcp"]

    assert build["dir"] == "./cmd/sso-mcp"
    assert build["main"] == "."


def test_stock_server_does_not_advertise_unsupported_windows_binary():
    build = _by_id(_release_config()["builds"])["sso-server"]

    assert set(build["goos"]) == {"linux", "darwin"}


def test_release_workflow_prepares_evidence_before_goreleaser():
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    prepare = workflow.index("profile_release.py prepare")
    release = workflow.index("goreleaser/goreleaser-action")

    assert prepare < release
    assert "${GITHUB_REF_NAME}" in workflow
    assert '>> "${GITHUB_ENV}"' in workflow


def test_inventory_is_the_public_modules_command_shape():
    lock = {
        "profile": "prototype",
        "lock_digest": "sha256:abc",
        "target": {"program": "snaplink"},
        "modules": [
            {"id": "core-runtime", "provides": ["z", "a"]},
            {"id": "sso-prototype-runtime", "provides": ["a", "m"]},
        ],
    }

    assert profile_release._inventory(lock) == {
        "program": "snaplink",
        "profile": "prototype",
        "lock_digest": "sha256:abc",
        "modules": ["core-runtime", "sso-prototype-runtime"],
        "capabilities": ["a", "m", "z"],
    }


def test_prepare_refuses_evidence_that_clean_would_delete(tmp_path: Path):
    with pytest.raises(profile_release.ProfileReleaseError, match="outside repository"):
        profile_release.prepare(
            "v1.2.3",
            ROOT / "dist" / "release-evidence",
            tmp_path / "release.env",
            ("prototype",),
            ("linux/amd64",),
        )


def test_prepare_rejects_a_target_outside_the_profile_matrix(tmp_path: Path):
    with pytest.raises(profile_release.ProfileReleaseError, match="unsupported"):
        profile_release.prepare(
            "v1.2.3",
            tmp_path / "evidence",
            tmp_path / "release.env",
            ("billing",),
            ("darwin/amd64",),
        )


def test_binary_evidence_never_claims_physical_profile_isolation():
    source = (ROOT / "ops/scripts/profile_release.py").read_text(encoding="utf-8")
    assert json.dumps("complete_package_level_physical_dependency_isolation") in source
