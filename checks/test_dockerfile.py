#!/usr/bin/env python3
"""Pin deployable Docker targets and the documented default runtime."""

import re
import subprocess
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "Dockerfile"
FROM = r"^FROM(?:\s+--platform=\S+)?\s+\S+\s+AS\s+"
STAGE = re.compile(FROM + r"([a-z0-9-]+)\s*$", re.MULTILINE)


def stage_body(text: str, name: str) -> str:
    match = re.search(
        FROM + rf"{re.escape(name)}\s*$([\s\S]*?)(?=^FROM\s|\Z)",
        text,
        re.MULTILINE,
    )
    return "" if match is None else match.group(1)


class TestDockerfileTargets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = DOCKERFILE.read_text(encoding="utf-8")
        cls.stages = STAGE.findall(cls.text)

    def test_sso_server_remains_default_last_stage(self):
        self.assertTrue(self.stages)
        self.assertEqual(self.stages[-1], "sso-server")
        self.assertIn('ENTRYPOINT ["/sso-server"]', self.text)

    def test_billing_has_dedicated_static_build_and_runtime(self):
        self.assertIn("snaplink-billing-builder", self.stages)
        self.assertIn("snaplink-billing", self.stages)
        build = stage_body(self.text, "snaplink-billing-builder")
        self.assertRegex(
            build,
            r"CGO_ENABLED=0\s+GOOS=\$\{TARGETOS\}\s+GOARCH=\$\{TARGETARCH\}[^\n]*go build[\s\S]*?"
            r"-o /out/snaplink-billing\s+\\\n\s+\./cmd/snaplink-billing",
        )
        self.assertIn('ENTRYPOINT ["/snaplink-billing"]', self.text)

    def test_stripe_adapter_has_dedicated_static_build_and_runtime(self):
        self.assertIn("snaplink-stripe-adapter-builder", self.stages)
        self.assertIn("snaplink-stripe-adapter", self.stages)
        build = stage_body(self.text, "snaplink-stripe-adapter-builder")
        self.assertRegex(
            build,
            r"CGO_ENABLED=0\s+GOOS=\$\{TARGETOS\}\s+GOARCH=\$\{TARGETARCH\}[^\n]*go build[\s\S]*?"
            r"-o /out/snaplink-stripe-adapter\s+\\\n\s+\./cmd/snaplink-stripe-adapter",
        )
        self.assertIn('ENTRYPOINT ["/snaplink-stripe-adapter"]', self.text)

    def test_audit_provisioner_has_dedicated_static_build_and_runtime(self):
        self.assertIn("snaplink-audit-provisioner-builder", self.stages)
        self.assertIn("snaplink-audit-provisioner", self.stages)
        build = stage_body(self.text, "snaplink-audit-provisioner-builder")
        self.assertRegex(
            build,
            r"CGO_ENABLED=0\s+GOOS=\$\{TARGETOS\}\s+GOARCH=\$\{TARGETARCH\}[^\n]*go build[\s\S]*?"
            r"-o /out/snaplink-audit-provisioner\s+\\\n\s+\./cmd/snaplink-audit-provisioner",
        )
        self.assertIn('ENTRYPOINT ["/snaplink-audit-provisioner"]', self.text)

    def test_mcp_named_target_remains_available(self):
        self.assertIn("sso-mcp", self.stages)
        self.assertIn('ENTRYPOINT ["/sso-mcp"]', self.text)

    def test_builder_is_native_and_target_args_are_inherited(self):
        self.assertIn("FROM --platform=$BUILDPLATFORM golang:", self.text)
        base = stage_body(self.text, "builder-base")
        self.assertIn("ARG TARGETOS", base)
        self.assertIn("ARG TARGETARCH", base)
        self.assertLess(base.index("COPY . ."), base.index("ARG TARGETARCH"))
        for stage in self.stages:
            if stage.endswith("-builder"):
                self.assertIn(f"FROM builder-base AS {stage}", self.text)

    def test_every_binary_including_probe_uses_target_architecture(self):
        commands = re.findall(r"CGO_ENABLED=0[^\n]*go build", self.text)
        self.assertEqual(len(commands), 6)
        for command in commands:
            self.assertIn("GOOS=${TARGETOS}", command)
            self.assertIn("GOARCH=${TARGETARCH}", command)
        probe = stage_body(self.text, "sso-server-builder")
        self.assertIn("-o /out/healthcheck", probe)

    def test_runtime_stages_remain_distroless_nonroot(self):
        targets = ["sso-server", "sso-mcp", "snaplink-billing",
                   "snaplink-stripe-adapter", "snaplink-audit-provisioner"]
        for target in targets:
            self.assertIn(f"FROM gcr.io/distroless/static:nonroot AS {target}", self.text)
            self.assertIn("USER nonroot:nonroot", stage_body(self.text, target))

    def test_build_context_excludes_sdk_outputs_and_local_env_files(self):
        ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        for entry in ("/sdks/rust/target/", "/sdks/python/build/", "/sdks/build/",
                      "/sdks/*/build/", "/sdks/.gradle/", "**/node_modules/",
                      "**/.build/", "**/.swiftpm/", "**/.env", "**/.env.*"):
            self.assertIn(entry, ignored)
        self.assertIn("!**/.env.example", ignored)


class TestDockerBuildCommands(unittest.TestCase):
    def dry_run(self, target, *overrides):
        result = subprocess.run(
            ["make", "--no-print-directory", "-n", target,
             "PLATFORM=linux/arm64", "IMAGE=example.invalid/team/sso",
             "IMAGE_TAG=test", "VERSION=v1.2.3",
             "OCI_ARCHIVE=dist/images/test.oci.tar", *overrides],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        return result.stdout

    def test_single_platform_is_loaded_without_publishing(self):
        output = self.dry_run("docker")
        self.assertIn('--platform "linux/arm64" --load .', output)
        self.assertIn('-t "example.invalid/team/sso:test"', output)
        self.assertIn('--build-arg "VERSION=v1.2.3"', output)
        self.assertNotIn("--push", output)

    def test_multiplatform_export_is_not_docker_load(self):
        output = self.dry_run("docker-multiarch")
        self.assertIn('--platform "linux/amd64,linux/arm64"', output)
        self.assertIn('--output "type=oci,dest=dist/images/test.oci.tar"', output)
        self.assertNotIn("--load", output)
        self.assertNotIn("--push", output)

    def test_push_uses_requested_image_and_platforms(self):
        output = self.dry_run("docker-push", "PLATFORMS=linux/arm64")
        self.assertIn('--platform "linux/arm64" --push .', output)
        self.assertIn('-t "example.invalid/team/sso:test"', output)
        self.assertNotIn(":latest", output)
        self.assertNotIn("--load", output)

    def test_target_and_build_arguments_are_configurable(self):
        output = self.dry_run("docker-multiarch", "DOCKER_TARGET=snaplink-billing",
                              "DOCKER_BUILD_ARGS=--build-arg GOFIPS140=latest")
        self.assertIn('--target "snaplink-billing"', output)
        self.assertIn("--build-arg GOFIPS140=latest", output)

    def test_local_load_rejects_a_platform_list_before_calling_docker(self):
        result = subprocess.run(
            ["make", "--no-print-directory", "docker", "DOCKER=false",
             "PLATFORM=linux/amd64,linux/arm64"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires one PLATFORM", result.stderr)
        self.assertNotIn("false buildx build", result.stdout)

    def test_ci_builds_and_runs_on_both_native_architectures(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        job = re.search(r"^  docker:\n[\s\S]*?(?=^  kustomize:)", workflow, re.MULTILINE).group()
        self.assertIn("runs-on: ${{ matrix.runner }}", job)
        self.assertIn("arch: amd64\n            runner: ubuntu-latest", job)
        self.assertIn("arch: arm64\n            runner: ubuntu-24.04-arm", job)
        self.assertEqual(job.count("platforms: linux/${{ matrix.arch }}"), 4)
        self.assertEqual(job.count("load: true"), 4)
        self.assertNotIn("push: true", job)
        self.assertIn("python3 ops/scripts/container_smoke.py --image snaplink/sso-server:ci", job)
        smoke = (ROOT / "ops/scripts/container_smoke.py").read_text()
        self.assertIn('docker("restart", name)', smoke)
        self.assertIn('"exec", container, "/healthcheck"', smoke)
        self.assertIn('check_active(base, revoked, False)', smoke)


class TestComposeStartupContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compose = yaml.safe_load((ROOT / "ops/deploy/compose/compose.yaml").read_text())
        cls.config = yaml.safe_load((ROOT / "ops/deploy/compose/config.yaml").read_text())

    def test_bootstrap_dependency_and_ledger_are_durable(self):
        self.assertTrue(self.config["permissions"]["enabled"])
        for name in ("identity", "permissions", "oauth"):
            self.assertEqual(self.config[name]["backend"], "sqlite")
            self.assertTrue(self.config[name]["sqlite"]["dsn"].startswith("file:/var/lib/snaplink/"))
        self.assertEqual(self.config["bootstrap"]["state_path"], "/var/lib/snaplink/bootstrap.json")
        self.assertEqual(self.config["keys"]["signing"]["revocation_backend"], "sqlite")
        self.assertEqual(self.config["keys"]["signing"]["key_file"], "/var/lib/snaplink/signing.pem")

    def test_nonroot_state_owner_is_initialized_before_api(self):
        services = self.compose["services"]
        self.assertIn("65532:65532", services["sso-state-init"]["command"][-1])
        self.assertIn("chmod 0700", services["sso-state-init"]["command"][-1])
        self.assertEqual(services["sso-server"]["depends_on"]["sso-state-init"]["condition"], "service_completed_successfully")
        self.assertIn("sso-data:/var/lib/snaplink", services["sso-server"]["volumes"])
        self.assertEqual(services["sso-server"]["healthcheck"]["test"], ["CMD", "/healthcheck"])

    def test_all_development_ports_are_loopback_only(self):
        for name, service in self.compose["services"].items():
            for port in service.get("ports", []):
                self.assertTrue(port.startswith("127.0.0.1:"), f"{name} exposes {port}")


if __name__ == "__main__":
    unittest.main()
