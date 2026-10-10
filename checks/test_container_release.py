"""Release index and publication-boundary regression tests; no Docker required."""

import copy
import importlib.util
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("container_manifest", ROOT / "ops/scripts/container_manifest.py")
manifest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manifest)


def index():
    entries = []
    for number, arch in enumerate(("amd64", "arm64"), 1):
        digest = "sha256:" + str(number) * 64
        entries.append({"mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": digest, "size": 123,
                        "platform": {"os": "linux", "architecture": arch}})
        entries.append({"mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": "sha256:" + str(number + 2) * 64, "size": 123,
                        "platform": {"os": "unknown", "architecture": "unknown"},
                        "annotations": {"vnd.docker.reference.type": "attestation-manifest",
                                        "vnd.docker.reference.digest": digest}})
    return {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": entries}


class TestReleaseIndex(unittest.TestCase):
    def test_exact_platforms_with_linked_attestations(self):
        manifest.validate(index())

    def test_missing_architecture(self):
        body = index()
        body["manifests"] = body["manifests"][:2]
        with self.assertRaises(ValueError):
            manifest.validate(body)

    def test_duplicate_architecture(self):
        body = index()
        body["manifests"].append(copy.deepcopy(body["manifests"][0]))
        with self.assertRaises(ValueError):
            manifest.validate(body)

    def test_wrong_os_or_missing_attestation(self):
        for change in ("os", "attestation", "link", "digest", "size"):
            body = index()
            if change == "os":
                body["manifests"][0]["platform"]["os"] = "windows"
            elif change == "attestation":
                body["manifests"].pop(1)
            elif change == "link":
                body["manifests"][1]["annotations"]["vnd.docker.reference.digest"] = "sha256:" + "f" * 64
            elif change == "digest":
                body["manifests"][0]["digest"] = "not-a-digest"
            else:
                body["manifests"][0]["size"] = 0
            with self.subTest(change=change), self.assertRaises(ValueError):
                manifest.validate(body)

    def test_distinct_platforms_require_distinct_manifests(self):
        body = index()
        body["manifests"][2]["digest"] = body["manifests"][0]["digest"]
        with self.assertRaises(ValueError):
            manifest.validate(body)

    def test_schema_and_sizes_must_be_integers_not_booleans(self):
        for change in ("schema", "size"):
            body = index()
            if change == "schema":
                body["schemaVersion"] = 2.0
            else:
                body["manifests"][0]["size"] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                manifest.validate(body)

    def test_unknown_platform_is_not_silently_skipped(self):
        body = index()
        del body["manifests"][1]["annotations"]
        with self.assertRaises(ValueError):
            manifest.validate(body)


class TestDockerHubPublicationContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (ROOT / ".github/workflows/dockerhub.yml").read_text()
        cls.workflow = yaml.load(cls.text, Loader=yaml.BaseLoader)
        cls.jobs = cls.workflow["jobs"]

    def test_only_explicit_dispatch_can_publish(self):
        self.assertEqual(set(self.workflow["on"]), {"workflow_dispatch"})
        verify = self.jobs["verify"]["steps"][1]
        self.assertEqual(verify["env"]["ENABLED"], "${{ vars.ENABLE_DOCKERHUB_PUBLICATION }}")
        self.assertIn('test "$GITHUB_REF" = "refs/heads/$DEFAULT_BRANCH"', verify["run"])
        self.assertIn('git merge-base --is-ancestor "$sha" "origin/$DEFAULT_BRANCH"', verify["run"])
        self.assertIn('git checkout --detach "$sha"', verify["run"])

    def test_publication_waits_for_complete_gate_and_both_native_runs(self):
        self.assertEqual(self.jobs["publish"]["needs"], ["verify", "native"])
        self.assertEqual(self.jobs["publish"]["environment"], "dockerhub")
        self.assertTrue(any("make ci" in step.get("run", "") for step in self.jobs["verify"]["steps"]))
        includes = self.jobs["native"]["strategy"]["matrix"]["include"]
        self.assertEqual({row["arch"] for row in includes}, {"amd64", "arm64"})
        self.assertEqual(self.jobs["native"]["needs"], "verify")

    def test_registry_credentials_exist_only_in_publication_job(self):
        for name in ("verify", "native"):
            self.assertNotIn("secrets.", str(self.jobs[name]))
            self.assertNotIn("id-token", str(self.jobs[name]))
        self.assertIn("secrets.DOCKERHUB_TOKEN", str(self.jobs["publish"]))
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})

    def test_publish_promotes_tested_bytes_instead_of_rebuilding(self):
        steps = self.jobs["publish"]["steps"]
        self.assertFalse(any("docker/build-push-action" in step.get("uses", "") for step in steps))
        self.assertIn("skopeo copy --all --preserve-digests", self.text)
        self.assertIn('imagetools create --tag "$IMAGE:$VERSION"', self.text)
        self.assertNotIn(":latest", self.text)
        builds = [step for step in self.jobs["native"]["steps"] if "docker/build-push-action" in step.get("uses", "")]
        self.assertEqual(len(builds), 1)
        self.assertEqual(builds[0]["with"]["pull"], "true")
        self.assertEqual(builds[0]["with"]["push"], "false")
        self.assertEqual(builds[0]["with"]["sbom"], "true")
        self.assertEqual(builds[0]["with"]["provenance"], "mode=max")

    def test_cached_ci_builds_refresh_base_images(self):
        workflow = yaml.load((ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)
        builds = [step for job in workflow["jobs"].values() for step in job.get("steps", [])
                  if "docker/build-push-action" in step.get("uses", "")]
        self.assertEqual(len(builds), 4)
        for build in builds:
            self.assertEqual(build["with"]["pull"], "true")
            self.assertEqual(build["with"]["push"], "false")

    def test_digest_and_oidc_identity_are_verified(self):
        self.assertIn('--digest "$digest"', self.text)
        self.assertIn('cosign sign --yes "$IMAGE@$digest"', self.text)
        self.assertIn('cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com', self.text)
        self.assertIn('--certificate-identity "https://github.com/$GITHUB_WORKFLOW_REF"', self.text)
        self.assertIn('exit-code: "1"', self.text)
        self.assertIn("severity: HIGH,CRITICAL", self.text)


if __name__ == "__main__":
    unittest.main()
