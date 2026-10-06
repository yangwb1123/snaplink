"""Guard Kotlin release wiring without reading secrets or contacting Central."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SECRET_PROPERTIES = {
    "ORG_GRADLE_PROJECT_signingInMemoryKey": "MAVEN_SIGNING_KEY",
    "ORG_GRADLE_PROJECT_signingInMemoryKeyPassword": "MAVEN_SIGNING_PASSWORD",
    "ORG_GRADLE_PROJECT_mavenCentralUsername": "CENTRAL_TOKEN_USERNAME",
    "ORG_GRADLE_PROJECT_mavenCentralPassword": "CENTRAL_TOKEN_PASSWORD",
}


class KotlinReleaseWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/sdk-kotlin-release.yml").read_text()
        )
        cls.verify = workflow["jobs"]["verify"]
        cls.publish = workflow["jobs"]["publish"]
        cls.upload = cls.step(cls.publish, "Sign and upload to Maven Central")

    @staticmethod
    def step(job: dict, name: str) -> dict:
        return next(step for step in job["steps"] if step.get("name") == name)

    def test_four_secrets_use_native_gradle_project_properties(self) -> None:
        actual = {
            name: value for name, value in self.upload["env"].items()
            if "secrets." in value
        }
        expected = {
            prop: "${{ secrets." + secret + " }}"
            for prop, secret in SECRET_PROPERTIES.items()
        }
        self.assertEqual(actual, expected)
        self.assertNotIn("ORG_GRADLE_PROJECT_signingInMemoryKeyId", actual)

    def test_portal_and_signing_are_enabled_and_wait_for_publication(self) -> None:
        environment = self.upload["env"]
        self.assertEqual(environment["ORG_GRADLE_PROJECT_mavenCentralPublishing"], "true")
        self.assertEqual(environment["ORG_GRADLE_PROJECT_signAllPublications"], "true")
        self.assertEqual(
            environment["ORG_GRADLE_PROJECT_mavenCentralDeploymentValidation"], "PUBLISHED"
        )
        command = self.upload["run"]
        self.assertIn(":snaplink:publishAndReleaseToMavenCentral", command)
        for flag in ("--no-daemon", "--no-configuration-cache", "--no-build-cache"):
            self.assertIn(flag, command)
        self.assertNotIn("-P", command)
        self.assertNotIn("set -x", command)

    def test_settings_do_not_forward_secrets_or_mutate_system_properties(self) -> None:
        settings = (ROOT / "sdks/settings.gradle.kts").read_text()
        self.assertNotIn("beforeProject", settings)
        self.assertNotIn("System.setProperty", settings)
        for name in SECRET_PROPERTIES:
            self.assertNotIn(name, settings)

    def test_publish_requires_verification_tag_review_and_dispatch_opt_in(self) -> None:
        self.assertEqual(self.publish["needs"], "verify")
        self.assertEqual(self.publish["environment"], "maven-central")
        self.assertEqual(
            self.publish["if"],
            "startsWith(github.ref, 'refs/tags/sdk-kotlin-v') && "
            "(github.event_name == 'push' || inputs.publish)",
        )

    def run_upload(self, missing: str | None = None) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gradlew = root / "gradlew"
            gradlew.write_text('#!/bin/sh\nprintf "GRADLE_INVOKED\\n"\n')
            gradlew.chmod(0o700)
            environment = {
                **os.environ,
                **{name: "test-value-not-a-credential" for name in SECRET_PROPERTIES},
            }
            if missing is not None:
                environment[missing] = ""
            return subprocess.run(
                ["bash", "-c", self.upload["run"]], cwd=root, env=environment,
                capture_output=True, text=True, timeout=10, check=False,
            )

    def test_each_missing_secret_stops_before_gradle_without_logging_values(self) -> None:
        for name in SECRET_PROPERTIES:
            with self.subTest(property=name):
                result = self.run_upload(missing=name)
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("::error::", output)
                self.assertNotIn("GRADLE_INVOKED", output)
                self.assertNotIn("test-value-not-a-credential", output)

    def test_complete_secret_set_reaches_gradle_without_logging_values(self) -> None:
        result = self.run_upload()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("GRADLE_INVOKED", result.stdout)
        self.assertNotIn("test-value-not-a-credential", result.stdout + result.stderr)

    def test_release_ref_guard_rejects_unprotected_branch_and_version_mismatch(self) -> None:
        step = self.step(self.verify, "Verify the tag matches the published version")
        build = (ROOT / "sdks/kotlin/build.gradle.kts").read_text()
        version = re.search(r'^version = "([^"]+)"', build, re.MULTILINE).group(1)
        expected = f"sdk-kotlin-v{version}"
        cases = (
            ("tag", "true", expected, 0),
            ("tag", "false", expected, 1),
            ("branch", "true", expected, 1),
            ("tag", "true", "sdk-kotlin-v999.0.0", 1),
        )
        for ref_type, protected, ref_name, code in cases:
            with self.subTest(ref_type=ref_type, protected=protected, ref_name=ref_name):
                environment = {
                    **os.environ, "GITHUB_REF_TYPE": ref_type,
                    "GITHUB_REF_PROTECTED": protected, "GITHUB_REF_NAME": ref_name,
                }
                result = subprocess.run(
                    ["bash", "-c", step["run"]], cwd=ROOT, env=environment,
                    capture_output=True, text=True, timeout=10, check=False,
                )
                self.assertEqual(result.returncode, code, result.stderr)

    def test_experimental_marker_still_blocks_publication(self) -> None:
        step = self.step(self.verify, "Verify the publication gate")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            readme = root / "sdks/kotlin/README.md"
            readme.parent.mkdir(parents=True)
            for text, code in (
                ("# Snaplink Android SDK (experimental, 0.3.0)\n", 1),
                ("# Snaplink Android SDK\n", 0),
                ("", 1),
                (None, 1),
            ):
                with self.subTest(marker=text):
                    if text is None:
                        readme.unlink(missing_ok=True)
                    else:
                        readme.write_text(text)
                    result = subprocess.run(
                        ["bash", "-c", step["run"]], cwd=root,
                        capture_output=True, text=True, timeout=10, check=False,
                    )
                    self.assertEqual(result.returncode, code, result.stderr)

    def test_registry_dependency_is_installed_before_python_gates(self) -> None:
        steps = self.verify["steps"]
        install = next(
            index for index, step in enumerate(steps)
            if "PyYAML" in step.get("run", "")
        )
        gate = next(
            index for index, step in enumerate(steps)
            if "python cli.py" in step.get("run", "")
        )
        self.assertLess(install, gate)


if __name__ == "__main__":
    unittest.main()
