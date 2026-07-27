import argparse
import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ops" / "scripts"))

import configure_modules as module_builder
import module_catalog
from configure_modules import (
    BuildModulesError,
    _binary_module_paths,
    _local_source_ref,
    _normalize_go_module,
    _validate_output_dir,
    _validate_owned_output,
    render_registration,
)
from module_catalog import (
    ModuleConfigError,
    buildable_profile_ids,
    load_profile,
    resolve_plan,
    supported_profile_ids,
    validate_repository,
)


def test_repository_catalog_and_profiles_validate():
    checked = validate_repository()
    assert checked[0] == "catalog (32 modules)"
    assert any(item.startswith("profile prototype") for item in checked)
    assert any(item.startswith("profile minimal") for item in checked)
    assert any(item.startswith("profile production") for item in checked)
    catalog_schema = json.loads(
        (ROOT / "ops" / "build" / "catalog.schema.json").read_text()
    )
    module_schema = json.loads(
        (ROOT / "ops" / "build" / "module.schema.json").read_text()
    )
    module_ref = catalog_schema["properties"]["modules"]["items"]["oneOf"][0]["$ref"]
    assert module_ref == module_schema["$id"]


def test_smoke_matrix_includes_supported_and_buildable_preview_profiles():
    assert supported_profile_ids() == ("production", "standard", "standard-kafka")
    assert buildable_profile_ids() == (
        "minimal",
        "production",
        "prototype",
        "standard",
        "standard-kafka",
    )
    assert module_builder._smoke_profile_ids() == (
        "minimal",
        "production",
        "prototype",
        "standard",
        "standard-kafka",
    )


def test_smoke_matrix_never_drops_an_unbuildable_supported_profile(monkeypatch):
    monkeypatch.setattr(
        module_builder,
        "supported_profile_ids",
        lambda: ("supported-regression",),
    )
    monkeypatch.setattr(
        module_builder,
        "buildable_profile_ids",
        lambda: ("preview",),
    )
    assert module_builder._smoke_profile_ids() == (
        "preview",
        "supported-regression",
    )


def test_standard_kafka_dependency_order_is_stable():
    plan = resolve_plan("standard-kafka")
    assert [module.id for module in plan.modules] == [
        "core-runtime",
        "stock-server",
        "audit-kafka",
    ]
    assert plan.dependencies["audit-kafka"] == ("stock-server",)
    assert plan.buildable


def test_prototype_uses_its_own_build_target():
    plan = resolve_plan("prototype")
    assert plan.buildable
    assert plan.profile.build_package == "./cmd/sso-minimal"
    assert plan.profile.binary_name == "snaplink"
    assert plan.profile.program_name == "snaplink"
    assert plan.profile.composition_module == "sso-prototype-runtime"
    assert "stock-server" not in {module.id for module in plan.modules}


def test_product_tiers_are_buildable_and_inherit_capabilities():
    prototype = resolve_plan("prototype")
    minimal = resolve_plan("minimal")
    production = resolve_plan("production")
    prototype_modules = {module.id for module in prototype.modules}
    minimal_modules = {module.id for module in minimal.modules}
    production_modules = {module.id for module in production.modules}

    assert prototype_modules < minimal_modules < production_modules
    assert minimal.profile.build_package == "./cmd/sso-minimal"
    assert minimal.profile.composition_module == "sso-minimal-runtime"
    assert production.profile.build_package == "./cmd/sso-server"
    assert production.profile.composition_module == "sso-production-runtime"
    assert {"stock-server", "audit-kafka"} <= production_modules
    assert production.dependencies["sso-production-runtime"] == (
        "audit-kafka",
        "sso-minimal-runtime",
        "stock-server",
    )
    assert prototype.buildable
    assert minimal.buildable
    assert production.buildable


@pytest.mark.parametrize(
    "version",
    (
        "v0.0.0-dev",
        "v1.1.1",
        "v2.0.0-rc.1+build.7",
    ),
)
def test_build_version_accepts_strict_semver(version):
    assert module_builder._build_version(version) == version


@pytest.mark.parametrize(
    "version",
    (
        "1.1.1",
        "v01.1.1",
        "v1.01.1",
        "v1.1.01",
        "v1.1",
        "v1.1.1-01",
        "v1.1.1 ",
    ),
)
def test_build_version_rejects_invalid_values(version):
    with pytest.raises(argparse.ArgumentTypeError, match="vMAJOR.MINOR.PATCH"):
        module_builder._build_version(version)


def test_tier_version_lines_and_ldflags_are_exact():
    plan = resolve_plan("minimal")
    version = "v1.1.1"
    assert (
        module_builder._expected_version_line(plan, version)
        == "snaplink-v1.1.1.minimal"
    )
    ldflags = module_builder._build_ldflags(plan, "sha256:test", version)
    assert (
        "-X github.com/yangwb1123/snaplink/platform/buildinfo.Version=v1.1.1"
        in ldflags
    )
    assert (
        "-X github.com/yangwb1123/snaplink/platform/buildinfo.BuildProfile=minimal"
        in ldflags
    )


def test_profile_inheritance_cycle_is_rejected(tmp_path, monkeypatch):
    base = {
        "schema_version": 1,
        "summary": "test",
        "maturity": "planned",
        "modules": [],
        "policy": {"allow_cgo": False, "fips": "any"},
    }
    (tmp_path / "first.json").write_text(
        json.dumps(dict(base, id="first", extends="second"))
    )
    (tmp_path / "second.json").write_text(
        json.dumps(dict(base, id="second", extends="first"))
    )
    monkeypatch.setattr(module_catalog, "PROFILES_DIR", tmp_path)
    with pytest.raises(ModuleConfigError, match="inheritance cycle"):
        load_profile("first")


def test_embedded_module_cannot_be_excluded():
    with pytest.raises(ModuleConfigError, match="cannot be excluded"):
        resolve_plan("standard", without_modules=["stock-server"])


def test_generated_hook_uses_explicit_register_call():
    source = render_registration(resolve_plan("standard-kafka"))
    assert "//go:build snaplink_configured" in source
    assert "func Register()" in source
    assert "RegisterAuditKafkaSinkFactory(module0.Factory)" in source
    assert "func init()" not in source
    assert 'import _ "' not in source


def test_lock_normalization_drops_absolute_replace_path(tmp_path):
    normalized = _normalize_go_module(
        {
            "Path": "example.com/plugin",
            "Version": "v0.0.0",
            "Replace": {
                "Path": str(tmp_path),
                "Dir": str(tmp_path),
            },
        }
    )
    encoded = json.dumps(normalized)
    assert str(tmp_path) not in encoded
    assert normalized["replace"]["local"].startswith("local:")


def test_local_source_fingerprint_distinguishes_same_named_directories(tmp_path):
    first = tmp_path / "first" / "module"
    second = tmp_path / "second" / "module"
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    (first / "go.mod").write_text("module example.com/first\n")
    (second / "go.mod").write_text("module example.com/second\n")
    assert _local_source_ref(first) != _local_source_ref(second)
    assert str(tmp_path) not in _local_source_ref(first)


def test_generated_output_cannot_pollute_source_tree(tmp_path):
    _validate_output_dir(tmp_path)
    _validate_output_dir(ROOT / "dist" / "modules" / "test")
    with pytest.raises(BuildModulesError, match="must be under dist"):
        _validate_output_dir(ROOT / "generated-modules")


def test_output_marker_must_have_the_owned_format(tmp_path):
    output = tmp_path / "configured"
    output.mkdir()
    (output / ".snaplink-modules-output").write_bytes(b"\xff")
    with pytest.raises(BuildModulesError, match="unowned"):
        _validate_owned_output(output)


def test_binary_dependency_parser_matches_exact_module_paths():
    metadata = (
        "binary: go1.25\n"
        "\tdep\texample.com/plugin\tv1.2.3\th1:first\n"
        "\tdep\texample.com/plugin-extra\tv1.2.3\th1:second\n"
    )
    assert _binary_module_paths(metadata) == {
        "example.com/plugin",
        "example.com/plugin-extra",
    }


def test_configure_supports_external_output_directory(tmp_path):
    output = tmp_path / "configured"
    result = subprocess.run(
        [
            sys.executable,
            "cli.py",
            "configure",
            "--profile",
            "standard-kafka",
            "--out",
            str(output),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert str(output / "modules.lock.json") in result.stdout
    assert (output / "modules.lock.json").is_file()
    assert stat.S_IMODE(output.stat().st_mode) == 0o755
    lock = json.loads((output / "modules.lock.json").read_text())
    assert lock["target"]["version"] == "v0.0.0-dev"
    module_file = json.loads(
        subprocess.check_output(
            [
                "go",
                "mod",
                "edit",
                "-json",
                f"-modfile={output / 'modules.mod'}",
            ],
            cwd=ROOT,
            text=True,
        )
    )
    replacement = module_file["Replace"][0]["New"]["Path"]
    assert not Path(replacement).is_absolute()


def test_build_version_changes_the_lock_identity(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    assert (
        module_builder.configure(
            [
                "--profile",
                "prototype",
                "--version",
                "v1.1.1",
                "--out",
                str(first),
            ]
        )
        == 0
    )
    assert (
        module_builder.configure(
            [
                "--profile",
                "prototype",
                "--version",
                "v1.1.2",
                "--out",
                str(second),
            ]
        )
        == 0
    )
    first_lock = json.loads((first / "modules.lock.json").read_text())
    second_lock = json.loads((second / "modules.lock.json").read_text())
    assert first_lock["target"]["version"] == "v1.1.1"
    assert second_lock["target"]["version"] == "v1.1.2"
    assert first_lock["lock_digest"] != second_lock["lock_digest"]


def test_native_target_uses_host_not_environment_target(monkeypatch):
    def fake_run(args, **_kwargs):
        assert args == ["go", "env", "GOHOSTOS", "GOHOSTARCH"]
        return "linux\namd64\n"

    monkeypatch.setattr(module_builder, "_run", fake_run)
    assert module_builder._is_native_target({"GOOS": "linux", "GOARCH": "amd64"})
    assert not module_builder._is_native_target({"GOOS": "windows", "GOARCH": "amd64"})


def test_failed_build_keeps_previous_lock_and_binary(tmp_path, monkeypatch):
    output = tmp_path / "configured"
    assert (
        module_builder.configure(["--profile", "standard", "--out", str(output)]) == 0
    )
    old_lock = (output / "modules.lock.json").read_bytes()
    binary = output / "sso-server"
    binary.write_bytes(b"previous-binary")

    def fail_build(*_args, **_kwargs):
        raise BuildModulesError("injected build failure")

    monkeypatch.setattr(module_builder, "_build_binary", fail_build)
    with pytest.raises(BuildModulesError, match="injected build failure"):
        module_builder.configure(
            ["--profile", "standard", "--out", str(output), "--build"]
        )
    assert (output / "modules.lock.json").read_bytes() == old_lock
    assert binary.read_bytes() == b"previous-binary"


def test_added_manifest_rejects_unknown_registration_type(tmp_path):
    manifest = {
        "schema_version": 1,
        "id": "unsafe-extension",
        "summary": "test",
        "kind": "cold",
        "state": "planned",
        "activation": "restart",
        "host_api": "v1alpha1",
        "provides": ["test.extension.v1"],
        "requires": ["core.runtime.v1"],
        "conflicts": [],
        "registration": {
            "type": "shell.template.v1",
            "package": "example.com/unsafe",
            "symbol": "Register",
        },
        "security": {
            "removable": True,
            "failure_policy": "fail-closed",
        },
    }
    (tmp_path / "snaplink.module.json").write_text(json.dumps(manifest))
    with pytest.raises(ModuleConfigError, match="unsupported type"):
        resolve_plan("standard", add_modules=[tmp_path])


def test_isolated_module_path_must_match_go_mod(tmp_path):
    manifest = {
        "schema_version": 1,
        "id": "mismatched-module",
        "summary": "test",
        "kind": "cold",
        "state": "isolated",
        "activation": "restart",
        "host_api": "v1alpha1",
        "version": "v0.0.0",
        "module_path": "example.com/declared",
        "source": ".",
        "provides": ["audit.sink.kafka.v1"],
        "requires": ["audit.host.v1"],
        "conflicts": [],
        "registration": {
            "type": "audit.kafka.factory.v1",
            "package": "example.com/declared",
            "symbol": "Factory",
        },
        "targets": {"cgo": False, "fips": "unknown"},
        "licenses": ["Apache-2.0"],
        "security": {
            "removable": True,
            "failure_policy": "fail-open",
        },
    }
    (tmp_path / "go.mod").write_text("module example.com/actual\n")
    (tmp_path / "snaplink.module.json").write_text(json.dumps(manifest))
    with pytest.raises(ModuleConfigError, match="does not match go.mod"):
        resolve_plan("standard", add_modules=[tmp_path])


def test_hot_external_module_cannot_enter_static_registrar(tmp_path):
    manifest = {
        "schema_version": 1,
        "id": "unsafe-hot-plugin",
        "summary": "test",
        "kind": "hot-external",
        "state": "isolated",
        "activation": "hot",
        "host_api": "v1alpha1",
        "version": "v0.0.0",
        "module_path": "example.com/unsafe-hot-plugin",
        "source": ".",
        "provides": ["test.hot.v1"],
        "requires": ["core.runtime.v1"],
        "conflicts": [],
        "registration": {
            "type": "audit.kafka.factory.v1",
            "package": "example.com/unsafe-hot-plugin",
            "symbol": "Factory",
        },
        "targets": {"cgo": False, "fips": "unknown"},
        "licenses": ["Apache-2.0"],
        "security": {
            "removable": True,
            "failure_policy": "fail-closed",
        },
    }
    (tmp_path / "go.mod").write_text("module example.com/unsafe-hot-plugin\n")
    (tmp_path / "snaplink.module.json").write_text(json.dumps(manifest))
    with pytest.raises(ModuleConfigError, match="isolated modules must be cold"):
        resolve_plan("standard", add_modules=[tmp_path])


def test_kernel_module_must_be_locked_and_non_removable(tmp_path):
    manifest = {
        "schema_version": 1,
        "id": "unsafe-kernel",
        "summary": "test",
        "kind": "kernel",
        "state": "planned",
        "activation": "locked",
        "locked": False,
        "host_api": "v1alpha1",
        "provides": ["test.kernel.v1"],
        "requires": [],
        "conflicts": [],
        "security": {
            "removable": True,
            "failure_policy": "fail-closed",
        },
    }
    manifest_path = tmp_path / "kernel.json"
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ModuleConfigError, match="kernel modules must be"):
        resolve_plan("standard", add_modules=[manifest_path])


def test_custom_profile_cannot_hide_stock_composition(tmp_path):
    profile = {
        "schema_version": 1,
        "id": "false-minimal",
        "summary": "test",
        "maturity": "supported",
        "modules": [],
        "policy": {
            "allow_cgo": False,
            "fips": "any",
            "allowed_licenses": ["Apache-2.0"],
        },
    }
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile))
    plan = resolve_plan(str(path))
    assert not plan.buildable
    assert any("requires composition module stock-server" in item for item in plan.blockers)


def test_custom_profile_cannot_reuse_builtin_id(tmp_path):
    profile = {
        "schema_version": 1,
        "id": "standard",
        "summary": "test",
        "maturity": "supported",
        "modules": ["stock-server"],
        "policy": {"allow_cgo": False, "fips": "any"},
    }
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile))
    with pytest.raises(ModuleConfigError, match="cannot reuse built-in id"):
        resolve_plan(str(path))


def test_profile_rejects_boolean_schema_version(tmp_path):
    profile = {
        "schema_version": True,
        "id": "invalid-version",
        "summary": "test",
        "maturity": "supported",
        "modules": ["stock-server"],
        "policy": {"allow_cgo": False, "fips": "any"},
    }
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile))
    with pytest.raises(ModuleConfigError, match="invalid schema_version"):
        resolve_plan(str(path))


def test_manifest_type_errors_are_reported_as_validation_errors(tmp_path):
    manifest = {
        "schema_version": 1,
        "id": "invalid-kind",
        "summary": "test",
        "kind": [],
        "state": "planned",
        "activation": "restart",
        "host_api": "v1alpha1",
        "provides": ["test.invalid.v1"],
        "requires": [],
        "conflicts": [],
        "security": {
            "removable": True,
            "failure_policy": "fail-closed",
        },
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ModuleConfigError, match="kind: invalid"):
        resolve_plan("standard", add_modules=[path])


def test_manifest_rejects_empty_declared_license_list(tmp_path):
    manifest = {
        "schema_version": 1,
        "id": "empty-licenses",
        "summary": "test",
        "kind": "cold",
        "state": "planned",
        "activation": "restart",
        "host_api": "v1alpha1",
        "provides": ["test.licenses.v1"],
        "requires": [],
        "conflicts": [],
        "licenses": [],
        "security": {
            "removable": True,
            "failure_policy": "fail-closed",
        },
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ModuleConfigError, match="non-empty array"):
        resolve_plan("standard", add_modules=[path])


def test_empty_license_allowlist_denies_isolated_module(tmp_path):
    profile = {
        "schema_version": 1,
        "id": "deny-licenses",
        "summary": "test",
        "maturity": "supported",
        "modules": ["stock-server", "audit-kafka"],
        "policy": {
            "allow_cgo": False,
            "fips": "any",
            "allowed_licenses": [],
        },
    }
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile))
    plan = resolve_plan(str(path))
    assert not plan.buildable
    assert any("disallowed licenses: Apache-2.0" in item for item in plan.blockers)


def test_singleton_registration_slot_is_rejected_in_plan(tmp_path):
    manifest = {
        "schema_version": 1,
        "id": "second-kafka",
        "summary": "test",
        "kind": "cold",
        "state": "isolated",
        "activation": "restart",
        "host_api": "v1alpha1",
        "version": "v0.0.0",
        "module_path": "example.com/second-kafka",
        "source": ".",
        "provides": ["audit.sink.kafka.v1"],
        "requires": ["audit.host.v1"],
        "conflicts": [],
        "registration": {
            "type": "audit.kafka.factory.v1",
            "package": "example.com/second-kafka",
            "symbol": "Factory",
        },
        "targets": {"cgo": False, "fips": "unknown"},
        "licenses": ["Apache-2.0"],
        "security": {
            "removable": True,
            "failure_policy": "fail-open",
        },
    }
    (tmp_path / "go.mod").write_text("module example.com/second-kafka\n")
    (tmp_path / "snaplink.module.json").write_text(json.dumps(manifest))
    with pytest.raises(ModuleConfigError, match="registration slot"):
        resolve_plan(
            "standard-kafka",
            with_modules=["second-kafka"],
            add_modules=[tmp_path],
        )


def test_dependency_cycle_is_rejected(tmp_path):
    base = {
        "schema_version": 1,
        "summary": "test",
        "kind": "cold",
        "state": "planned",
        "activation": "restart",
        "host_api": "v1alpha1",
        "conflicts": [],
        "security": {
            "removable": True,
            "failure_policy": "fail-closed",
        },
    }
    first = dict(
        base,
        id="cycle-first",
        provides=["cycle.first.v1"],
        requires=["cycle.second.v1"],
    )
    second = dict(
        base,
        id="cycle-second",
        provides=["cycle.second.v1"],
        requires=["cycle.first.v1"],
    )
    first_path, second_path = tmp_path / "first.json", tmp_path / "second.json"
    first_path.write_text(json.dumps(first))
    second_path.write_text(json.dumps(second))
    with pytest.raises(ModuleConfigError, match="dependency cycle"):
        resolve_plan(
            "standard",
            with_modules=["cycle-first"],
            add_modules=[first_path, second_path],
        )
