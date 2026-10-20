"""Release index and publication-boundary regression tests; no Docker required."""

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("container_manifest", ROOT / "ops/scripts/container_manifest.py")
manifest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manifest)
ARCHIVE_SPEC = importlib.util.spec_from_file_location("container_archive", ROOT / "ops/scripts/container_archive.py")
archive_tool = importlib.util.module_from_spec(ARCHIVE_SPEC)
ARCHIVE_SPEC.loader.exec_module(archive_tool)


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

    def test_scanner_reads_original_oci_layout_not_daemon_config(self):
        steps = self.jobs["native"]["steps"]
        extract = next(step for step in steps if "container_archive.py" in step.get("run", ""))
        self.assertEqual(extract["env"]["ARCHIVE"], "${{ runner.temp }}/sso-${{ matrix.arch }}.oci.tar")
        self.assertIn('--platform "linux/${{ matrix.arch }}"', extract["run"])
        scan = next(step for step in steps if "trivy-action" in step.get("uses", ""))["with"]
        self.assertNotIn("image-ref", scan)
        self.assertEqual(scan["scan-type"], "image")
        self.assertEqual(scan["input"], extract["env"]["LAYOUT"])
        self.assertEqual(scan["format"], "json")
        self.assertEqual(scan["severity"], "HIGH,CRITICAL")
        self.assertEqual(scan["exit-code"], "1")
        self.assertEqual(scan["ignore-unfixed"], "false")
        upload = next(step for step in steps if "upload-artifact" in step.get("uses", ""))
        self.assertIn(scan["output"], upload["with"]["path"])

    def test_digest_and_oidc_identity_are_verified(self):
        self.assertIn('--digest "$digest"', self.text)
        self.assertIn('cosign sign --yes "$IMAGE@$digest"', self.text)
        self.assertIn('cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com', self.text)
        self.assertIn('--certificate-identity "https://github.com/$GITHUB_WORKFLOW_REF"', self.text)
        self.assertIn('exit-code: "1"', self.text)
        self.assertIn("severity: HIGH,CRITICAL", self.text)


class TestOCIArchiveExtraction(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "image.tar"
        self.destination = self.root / "layout"
        self.blob = b'{"test":"original bytes"}'
        self.blob_path = "blobs/sha256/" + hashlib.sha256(self.blob).hexdigest()

    def write_archive(self, extras=(), omit=()):
        entries = [("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
                   ("index.json", b'{"schemaVersion":2,"manifests":[{}]}'),
                   (self.blob_path, self.blob)]
        with tarfile.open(self.archive, "w") as output:
            for name, data in [entry for entry in entries if entry[0] not in omit] + list(extras):
                if isinstance(name, tarfile.TarInfo):
                    output.addfile(name)
                    continue
                info = tarfile.TarInfo(name)
                info.size = len(data)
                output.addfile(info, io.BytesIO(data))

    def test_extracts_original_blob_bytes(self):
        self.write_archive()
        archive_tool.extract(self.archive, self.destination)
        self.assertEqual((self.destination / self.blob_path).read_bytes(), self.blob)

    def write_platform_archive(self, *, duplicate=False, mismatch=False, depth=1, repeated_index=False):
        blobs, descriptors = [], []
        def add(body, media_type):
            raw = json.dumps(body).encode()
            digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            blobs.append(("blobs/" + digest.replace(":", "/"), raw))
            return {"mediaType": media_type, "digest": digest, "size": len(raw)}
        for arch in ("amd64", "arm64"):
            config = add({"os": "linux", "architecture": "wrong" if mismatch else arch}, "application/vnd.oci.image.config.v1+json")
            image = add({"schemaVersion": 2, "config": config, "layers": []}, "application/vnd.oci.image.manifest.v1+json")
            image["platform"] = {"os": "linux", "architecture": arch}
            descriptors.append(image)
        expected = descriptors[1]
        if duplicate:
            descriptors.append(expected)
        body = {"schemaVersion": 2, "manifests": descriptors}
        for _ in range(depth):
            body = {"schemaVersion": 2, "manifests": [add(body, "application/vnd.oci.image.index.v1+json")]}
        if repeated_index:
            body["manifests"].append(body["manifests"][0])
        self.write_archive(blobs + [("index.json", json.dumps(body).encode())], omit=("index.json",))
        return expected, blobs

    def test_selects_nested_arm_without_rewriting_content_addressed_bytes(self):
        expected, blobs = self.write_platform_archive()
        archive_tool.extract(self.archive, self.destination, "linux/arm64")
        index = json.loads((self.destination / "index.json").read_text())
        self.assertEqual(index["manifests"], [expected])
        for name, raw in blobs:
            self.assertEqual((self.destination / name).read_bytes(), raw)

    def test_platform_selection_refuses_absent_ambiguous_or_mismatched_config(self):
        for mode in ("absent", "ambiguous", "mismatch", "depth"):
            self.write_platform_archive(duplicate=mode == "ambiguous", mismatch=mode == "mismatch", depth=10 if mode == "depth" else 1)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                archive_tool.extract(self.archive, self.destination, "linux/missing" if mode == "absent" else "linux/arm64")
            self.assertFalse(self.destination.exists())

    def test_bounds_tar_stream_members_and_metadata(self):
        for budget in ("MAX_TAR_BYTES", "MAX_MEMBERS", "MAX_METADATA_BYTES"):
            self.write_archive()
            with self.subTest(budget=budget), patch.object(archive_tool, budget, 1), self.assertRaises(ValueError):
                archive_tool.extract(self.archive, self.destination)
            self.assertFalse(self.destination.exists())
        info = tarfile.TarInfo("pax")
        info.type = tarfile.XHDTYPE
        self.write_archive([(info, None)])
        with self.assertRaises(ValueError):
            archive_tool.extract(self.archive, self.destination)
        self.assertFalse(self.destination.exists())

    def test_normalizes_malformed_tar_errors_and_cleans_destination(self):
        self.archive.write_bytes(b"not an OCI tar stream")
        with self.assertRaisesRegex(ValueError, "invalid OCI tar stream"):
            archive_tool.extract(self.archive, self.destination)
        self.assertFalse(self.destination.exists())

    def test_bounds_index_descriptor_visits_and_repeated_references(self):
        self.write_platform_archive()
        with patch.object(archive_tool, "MAX_INDEX_DESCRIPTORS", 1), self.assertRaises(ValueError):
            archive_tool.extract(self.archive, self.destination, "linux/arm64")
        self.assertFalse(self.destination.exists())
        self.write_platform_archive(repeated_index=True)
        with patch.object(archive_tool, "_blob_json", wraps=archive_tool._blob_json) as load, self.assertRaisesRegex(ValueError, "repeated"):
            archive_tool.extract(self.archive, self.destination, "linux/arm64")
        self.assertEqual(load.call_count, 1)
        self.assertFalse(self.destination.exists())

    def test_refuses_existing_or_symlink_destination(self):
        self.write_archive()
        for symlink in (False, True):
            target = self.root / "existing"
            target.mkdir(exist_ok=True)
            if symlink:
                self.destination.symlink_to(target, target_is_directory=True)
            else:
                self.destination.mkdir()
            with self.subTest(symlink=symlink), self.assertRaises(FileExistsError):
                archive_tool.extract(self.archive, self.destination)
            self.assertTrue(target.is_dir())
            if symlink:
                self.destination.unlink()
            else:
                self.destination.rmdir()

    def test_refuses_traversal_absolute_and_non_oci_paths(self):
        for name in ("../escape", "/escape", "blobs/../escape", "other", "blobs/sha256/not-a-digest"):
            self.write_archive([(name, b"unsafe")])
            with self.subTest(name=name), self.assertRaises(ValueError):
                archive_tool.extract(self.archive, self.destination)
            self.assertFalse(self.destination.exists())
        self.assertFalse((self.root / "escape").exists())

    def test_refuses_links_and_special_members(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            info = tarfile.TarInfo("index.json")
            info.type, info.linkname = kind, "../escape"
            self.write_archive([(info, None)])
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                archive_tool.extract(self.archive, self.destination)
            self.assertFalse(self.destination.exists())

    def test_refuses_duplicate_or_mismatched_blobs(self):
        for name, data in ((self.blob_path, self.blob), ("blobs/sha256/" + "f" * 64, b"wrong")):
            self.write_archive([(name, data)])
            with self.subTest(name=name), self.assertRaises(ValueError):
                archive_tool.extract(self.archive, self.destination)
            self.assertFalse(self.destination.exists())

    def test_refuses_missing_metadata_and_oversized_archive(self):
        self.write_archive(omit=("oci-layout",))
        with self.assertRaises(ValueError):
            archive_tool.extract(self.archive, self.destination)
        self.assertFalse(self.destination.exists())
        self.write_archive()
        with patch.object(archive_tool, "MAX_ARCHIVE_BYTES", 1), self.assertRaises(ValueError):
            archive_tool.extract(self.archive, self.destination)
        self.assertFalse(self.destination.exists())

    def test_refuses_invalid_layout_or_index_version(self):
        for filename, body in (("oci-layout", {"imageLayoutVersion": "9"}),
                               ("index.json", {"schemaVersion": 2.0, "manifests": [{}]}),
                               ("index.json", {"schemaVersion": 2, "manifests": []})):
            self.write_archive([(filename, json.dumps(body).encode())], omit=(filename,))
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                archive_tool.extract(self.archive, self.destination)
            self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
