#!/usr/bin/env python3
"""Coverage decisions fail closed without changing the generated allowlist."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sdk_surface

ROOT = Path(__file__).resolve().parents[2]
OPENAPI = ROOT / "docs/openapi.yaml"
COVERAGE = ROOT / "ops/build/sdk-surface-coverage.json"
REGISTRY = ROOT / "ops/build/sdk-surface.json"


class CoverageGateTests(unittest.TestCase):
    """Exercise the old check's concrete holes before the helper exists."""

    def check_text(self, text: str) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "openapi.yaml"
            path.write_text(text, encoding="utf-8")
            output, errors = io.StringIO(), io.StringIO()
            with patch.object(sdk_surface, "OPENAPI_PATH", path):
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    result = sdk_surface.run(["check"])
        return result, errors.getvalue()

    def test_unclassified_operation_rejected_by_existing_check(self) -> None:
        doc = yaml.safe_load(OPENAPI.read_text())
        doc["paths"]["/coverage-new"] = {"get": {"operationId": "coverageUnclassified"}}
        result, error = self.check_text(yaml.safe_dump(doc))
        self.assertEqual(result, 1)
        self.assertIn("coverageUnclassified", error)

    def test_existing_component_schema_validation_is_preserved(self) -> None:
        doc = yaml.safe_load(OPENAPI.read_text())
        doc["components"]["schemas"]["CoverageInvalidSchema"] = {"type": "array", "items": ["invalid"]}
        result, error = self.check_text(yaml.safe_dump(doc))
        self.assertEqual(result, 1)
        self.assertIn("CoverageInvalidSchema", error)

    def test_stale_exclusion_rejected_by_existing_check(self) -> None:
        doc = yaml.safe_load(OPENAPI.read_text())
        del doc["paths"]["/metrics"]
        result, error = self.check_text(yaml.safe_dump(doc))
        self.assertEqual(result, 1)
        self.assertIn("getMetrics", error)

    def test_duplicate_operation_id_rejected_before_set_conversion(self) -> None:
        doc = yaml.safe_load(OPENAPI.read_text())
        doc["paths"]["/coverage-duplicate"] = {"get": {"operationId": "getMetrics"}}
        result, error = self.check_text(yaml.safe_dump(doc))
        self.assertEqual(result, 1)
        self.assertIn("duplicate operationId", error)

    def test_duplicate_raw_yaml_path_rejected(self) -> None:
        text = OPENAPI.read_text().replace(
            "paths:\n", "paths:\n  /metrics:\n    get:\n      operationId: getMetrics\n", 1
        )
        result, error = self.check_text(text)
        self.assertEqual(result, 1)
        self.assertIn("duplicate YAML key", error)

    def test_duplicate_raw_yaml_method_rejected(self) -> None:
        text = OPENAPI.read_text().replace(
            "  /metrics:\n    get:",
            "  /metrics:\n    get:\n      operationId: getMetrics\n    get:", 1,
        )
        self.assertNotEqual(text, OPENAPI.read_text())
        result, error = self.check_text(text)
        self.assertEqual(result, 1)
        self.assertIn("duplicate YAML key", error)


class CoverageContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.helper = importlib.import_module("sdk_surface_coverage")
        cls.registry = json.loads(REGISTRY.read_text())
        cls.coverage = json.loads(COVERAGE.read_text())
        cls.operations = cls.helper.load_operations(OPENAPI)

    def validate(self, coverage=None, operations=None, registry=None) -> dict:
        return self.helper.validate_coverage(
            copy.deepcopy(self.coverage if coverage is None else coverage),
            copy.deepcopy(self.registry if registry is None else registry),
            copy.deepcopy(self.operations if operations is None else operations), ROOT,
        )

    def assert_invalid(self, coverage=None, operations=None, registry=None, message="") -> None:
        with self.assertRaisesRegex(self.helper.SDKCoverageError, message):
            self.validate(coverage, operations, registry)

    def test_actual_sets_and_all_included_groups_are_exact(self) -> None:
        report = self.validate()
        included = {op for group in self.registry["groups"] for op in group["operations"]}
        excluded = {op["operationId"] for group in self.coverage["excluded_groups"] for op in group["operations"]}
        self.assertEqual((len(self.operations), len(included), len(excluded)), (366, 321, 45))
        self.assertFalse(included & excluded)
        self.assertEqual(included | excluded, set(self.operations))
        self.assertEqual(report["counts"], {"documented": 366, "included": 321, "excluded": 45})
        self.assertEqual({g["id"] for g in self.registry["groups"]}, {g["id"] for g in self.coverage["included_groups"]})
        self.assertEqual(len(report["operations"]), 366)

    def test_same_id_method_or_path_drift_rejected(self) -> None:
        for field, value in [("method", "PUT"), ("path", "/metrics-moved")]:
            with self.subTest(field=field):
                ops = copy.deepcopy(self.operations)
                ops["getMetrics"][field] = value
                self.assert_invalid(operations=ops, message="getMetrics.*identity")

    def test_deleted_or_renamed_exclusion_rejected(self) -> None:
        for rename in [False, True]:
            with self.subTest(rename=rename):
                ops = copy.deepcopy(self.operations)
                original = ops.pop("getMetrics")
                if rename:
                    ops["newMetrics"] = {**original, "operationId": "newMetrics"}
                self.assert_invalid(operations=ops, message="stale exclusion.*getMetrics")

    def test_overlap_and_duplicate_exclusion_rejected(self) -> None:
        coverage = copy.deepcopy(self.coverage)
        entry = coverage["excluded_groups"][0]["operations"][0]
        included = self.registry["groups"][0]["operations"][0]
        entry.update({k: self.operations[included][k] for k in ("operationId", "method", "path")})
        self.assert_invalid(coverage=coverage, message="included and excluded")
        coverage = copy.deepcopy(self.coverage)
        coverage["excluded_groups"][0]["operations"].append(copy.deepcopy(coverage["excluded_groups"][0]["operations"][0]))
        self.assert_invalid(coverage=coverage, message="duplicate exclusion")

    def test_included_group_reasons_must_match_registry_exactly(self) -> None:
        coverage = copy.deepcopy(self.coverage)
        coverage["included_groups"].pop()
        self.assert_invalid(coverage=coverage, message="included groups")
        coverage = copy.deepcopy(self.coverage)
        coverage["included_groups"][0]["id"] = "unknown-group"
        self.assert_invalid(coverage=coverage, message="included groups")

    def test_duplicate_groups_and_selected_ids_rejected(self) -> None:
        for group_key in ["included_groups", "excluded_groups"]:
            with self.subTest(group_key=group_key):
                coverage = copy.deepcopy(self.coverage)
                coverage[group_key].append(copy.deepcopy(coverage[group_key][0]))
                self.assert_invalid(coverage=coverage, message="duplicate.*group")
        registry = copy.deepcopy(self.registry)
        registry["groups"][0]["operations"].append(registry["groups"][0]["operations"][0])
        self.assert_invalid(registry=registry, message="duplicate.*selected")

    def test_unknown_version_fields_empty_reasons_and_malformed_shapes_rejected(self) -> None:
        mutations = [
            lambda c: c.update(schema_version=2),
            lambda c: c.update(schema_version=True),
            lambda c: c.update(unexpected=True),
            lambda c: c.update(included_groups={}),
            lambda c: c["included_groups"][0].update(unexpected=True),
            lambda c: c["excluded_groups"][0]["operations"][0].update(unexpected=True),
            lambda c: c["excluded_groups"][0]["operations"][0].update(method="post"),
            lambda c: c["excluded_groups"][0].update(operations=[]),
        ]
        for field in ["rationale", "exposure", "authentication", "defaults", "licensing"]:
            mutations.append(lambda c, f=field: c["included_groups"][0].update({f: " \n"}))
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                coverage = copy.deepcopy(self.coverage)
                mutate(coverage)
                self.assert_invalid(coverage=coverage)

    def test_references_require_real_internal_files_and_reject_symlink_escape(self) -> None:
        for ref in ["../AGENTS.md", "/etc/passwd", "https://example.invalid/spec", "does-not-exist", "docs"]:
            with self.subTest(ref=ref):
                coverage = copy.deepcopy(self.coverage)
                coverage["included_groups"][0]["references"] = [ref]
                self.assert_invalid(coverage=coverage, message="reference")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "link").symlink_to(ROOT / "AGENTS.md")
            coverage = copy.deepcopy(self.coverage)
            coverage["included_groups"][0]["references"] = ["link"]
            with self.assertRaisesRegex(self.helper.SDKCoverageError, "reference"):
                self.helper.validate_coverage(coverage, self.registry, self.operations, root)

    def test_cyclic_and_control_character_references_have_closed_diagnostics(self) -> None:
        coverage = copy.deepcopy(self.coverage)
        coverage["included_groups"][0]["references"] = ["bad\x00reference"]
        self.assert_invalid(coverage=coverage, message="reference")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "loop").symlink_to("loop")
            coverage["included_groups"][0]["references"] = ["loop"]
            with self.assertRaisesRegex(self.helper.SDKCoverageError, "reference"):
                self.helper.validate_coverage(coverage, self.registry, self.operations, root)

    def test_malformed_schema_structure_has_closed_diagnostics(self) -> None:
        schema = json.loads(self.helper.SCHEMA_PATH.read_text())
        schema["required"] = None
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "schema.json"
            path.write_text(json.dumps(schema))
            with patch.object(self.helper, "SCHEMA_PATH", path):
                with self.assertRaises(self.helper.SDKCoverageError):
                    self.helper.coverage_report(self.registry, OPENAPI)

    def test_json_duplicates_and_missing_files_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coverage.json"
            with self.assertRaises(self.helper.SDKCoverageError):
                self.helper.load_coverage_file(path)
            path.write_text('{"schema_version": 1, "schema_version": 1}')
            with self.assertRaisesRegex(self.helper.SDKCoverageError, "duplicate JSON key"):
                self.helper.load_coverage_file(path)
            path.write_text("{")
            with self.assertRaises(self.helper.SDKCoverageError):
                self.helper.load_coverage_file(path)

    def test_security_inheritance_explicit_empty_and_explicit_override(self) -> None:
        operations = self.helper.load_operations_text("""
security: [{bearerAuth: []}]
paths:
  /inherited:
    get: {operationId: inherited}
  /empty:
    get: {operationId: empty, security: []}
  /override:
    get: {operationId: override, security: [{clientAuth: [read]}]}
""", "security test")
        self.assertEqual(operations["inherited"]["openapi_security"], {"source": "root", "declaration": [{"bearerAuth": []}]})
        self.assertEqual(operations["empty"]["openapi_security"], {"source": "operation", "declaration": []})
        self.assertEqual(operations["override"]["openapi_security"], {"source": "operation", "declaration": [{"clientAuth": ["read"]}]})
        ciba = self.operations["postBackchannelAuthentication"]
        self.assertEqual(ciba["openapi_security"], {"source": "unspecified", "declaration": None})
        report = self.validate()
        ciba_report = next(r for r in report["operations"] if r["operationId"] == ciba["operationId"])
        self.assertIn("client authentication", ciba_report["boundary"]["authentication"])

    def test_ciba_report_distinguishes_confidential_auth_from_public_identity(self) -> None:
        report = self.validate()
        ciba = next(row for row in report["operations"] if row["operationId"] == "postBackchannelAuthentication")
        self.assertEqual((ciba["selection"], ciba["group"]), ("excluded", "ciba"))
        authentication = ciba["boundary"]["authentication"]
        for distinction in [
            "Confidential client authentication requires a non-empty secret",
            "Basic takes precedence over body credentials",
            "verified private_key_jwt assertion",
            'Registered public clients with token_endpoint_auth_method="none" may supply client_id without a secret or assertion',
            "identifies the client, not proof of possession",
            "Both paths enforce registered/active client, tenant, resource and scope checks",
            "not unrestricted anonymous access",
        ]:
            with self.subTest(distinction=distinction):
                self.assertIn(distinction, authentication)
        for owner in ["protocols/oauth/handle_ciba.go", "protocols/oauth/handle_ciba_test.go"]:
            self.assertIn(owner, ciba["boundary"]["references"])

    def test_netpolicy_discovery_reports_open_current_request_classification(self) -> None:
        report = self.validate()
        row = next(r for r in report["operations"] if r["operationId"] == "resolveMeNetPolicy")
        self.assertEqual((row["selection"], row["group"]), ("included", "discovery"))
        self.assertEqual((row["method"], row["path"]), ("GET", "/api/v1/netpolicy/resolve-me"))
        self.assertEqual(row["openapi_security"], {"source": "unspecified", "declaration": None})
        operation = yaml.safe_load(OPENAPI.read_text())["paths"][row["path"]]["get"]
        self.assertIn("Intentionally open", operation["description"])
        authentication = row["boundary"]["authentication"]
        with self.subTest(distinction="reject authenticated self-resolution claim"):
            self.assertNotIn("authenticated netpolicy resolution", authentication.lower())
        for distinction in [
            "GET /api/v1/netpolicy/resolve-me is intentionally open",
            "current-request peer/host classification",
            "r.RemoteAddr and r.Host",
            "no bearer authentication by this handler or AdminMiddleware",
        ]:
            with self.subTest(distinction=distinction):
                self.assertIn(distinction, authentication)

    def test_netpolicy_management_boundary_is_distinct_and_owner_linked(self) -> None:
        rows = {r["operationId"]: r for r in self.validate()["operations"]}
        discovery = rows["resolveMeNetPolicy"]["boundary"]
        for operation_id, method, path in [
            ("classifyNetPolicy", "GET", "/api/v1/netpolicy/classify"),
            ("listNetPolicies", "GET", "/api/v1/netpolicy/policies"),
            ("applyNetPolicy", "POST", "/api/v1/netpolicy/policies"),
            ("getNetPolicy", "GET", "/api/v1/netpolicy/policies/{name}"),
            ("deleteNetPolicy", "DELETE", "/api/v1/netpolicy/policies/{name}"),
        ]:
            with self.subTest(operation_id=operation_id):
                row = rows[operation_id]
                self.assertEqual((row["selection"], row["group"]), ("included", "admin"))
                self.assertEqual((row["method"], row["path"]), (method, path))
                self.assertEqual(row["openapi_security"], {"source": "operation", "declaration": [{"bearerAuth": []}]})
                self.assertIn("Admin bearer", row["boundary"]["authentication"])
                self.assertNotEqual(row["boundary"]["authentication"], discovery["authentication"])
        for distinction in [
            "Managed /api/v1/netpolicy/classify (arbitrary inputs)",
            "/api/v1/netpolicy/policies*",
            "GET admin:read, mutations admin:write",
            "when AdminMiddleware is installed",
            "SDK/custom compositions must supply equivalent protection",
            "stock admin-disabled wiring leaves these managed routes unauthenticated",
            "Missing OpenAPI security alone does not prove public access",
        ]:
            with self.subTest(distinction=distinction):
                self.assertIn(distinction, discovery["authentication"])
        for owner in [
            "platform/netpolicy/handlers.go", "platform/netpolicy/handlers_test.go",
            "interfaces/admin/middleware.go", "test/admin_middleware_test.go",
            "interfaces/sso/server_routes_admin.go", "cmd/sso-server/build_http.go",
        ]:
            with self.subTest(owner=owner):
                self.assertIn(owner, discovery["references"])
                self.assertTrue((ROOT / owner).is_file())

    def test_ciba_documentation_preserves_public_client_policy_boundary(self) -> None:
        documentation = " ".join((ROOT / "docs/sdk-paradigm.md").read_text().split())
        for distinction in [
            "Confidential CIBA clients authenticate with a non-empty secret",
            "Basic takes precedence over body credentials",
            "verified `private_key_jwt` assertion",
            'Registered public CIBA clients with `token_endpoint_auth_method="none"` may supply `client_id` without a secret or assertion',
            "identifies the client, not proof of possession",
            "Both paths still enforce registered/active client, tenant, resource and scope checks",
            "protocols/oauth/handle_ciba.go",
        ]:
            with self.subTest(distinction=distinction):
                self.assertIn(distinction, documentation)
        self.assertNotIn("CIBA endpoints still require client authentication", documentation)

    def test_all_http_methods_and_missing_ids_or_malformed_yaml_rejected(self) -> None:
        operations = self.helper.load_operations_text("paths: {/a: {head: {operationId: headA}, options: {operationId: optionsA}, trace: {operationId: traceA}}}", "methods")
        self.assertEqual({o["method"] for o in operations.values()}, {"HEAD", "OPTIONS", "TRACE"})
        for text in ["paths: {/a: {get: {}}}", "paths: []", "paths: {/a: null}", "paths: {/a: {get: []}}", "paths: [", "[]", "paths: {/a: {get: {operationId: a, security: null}}}"]:
            with self.subTest(text=text):
                with self.assertRaises(self.helper.SDKCoverageError):
                    self.helper.load_operations_text(text, "bad")

    def test_media_types_resolve_only_local_response_references(self) -> None:
        operations = self.helper.load_operations_text("""
paths:
  /media:
    post:
      operationId: media
      requestBody: {content: {application/json: {}}}
      responses: {'200': {$ref: '#/components/responses/EventStream'}}
components:
  responses:
    EventStream: {content: {text/event-stream: {}}}
""", "media")
        self.assertEqual(operations["media"]["media_types"], {"request": ["application/json"], "responses": {"200": ["text/event-stream"]}})
        for ref in ["https://example.invalid/schema", "#/components/responses/Unknown"]:
            with self.assertRaises(self.helper.SDKCoverageError):
                self.helper.load_operations_text("paths: {/a: {get: {operationId: a, responses: {'200': {$ref: '" + ref + "'}}}}}", "bad ref")

    def test_report_is_deterministic_sorted_and_read_only(self) -> None:
        paths = [OPENAPI, REGISTRY, COVERAGE]
        before = [hashlib.sha256(p.read_bytes()).hexdigest() for p in paths]
        first = self.helper.coverage_report(self.registry, OPENAPI)
        second = self.helper.coverage_report(self.registry, OPENAPI)
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
        ids = [o["operationId"] for o in first["operations"]]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(before, [hashlib.sha256(p.read_bytes()).hexdigest() for p in paths])
        self.assertIn("not runtime authentication", first["scope"])
        self.assertEqual(self.operations["streamMyNotifications"]["media_types"]["responses"]["200"], ["text/event-stream"])

    def test_cli_coverage_and_check_fail_closed_for_bad_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coverage.json"
            path.write_text('{"schema_version": 3}')
            for action in ["check", "coverage"]:
                with self.subTest(action=action), patch.object(self.helper, "COVERAGE_PATH", path):
                    errors = io.StringIO()
                    with contextlib.redirect_stderr(errors):
                        self.assertEqual(sdk_surface.run([action]), 1)
                    self.assertIn("ERROR:", errors.getvalue())
                    self.assertNotIn("Traceback", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
