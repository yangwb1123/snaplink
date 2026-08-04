#!/usr/bin/env python3
"""Pin deployable Docker targets and the documented default runtime."""

import re
import unittest
from pathlib import Path


DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"
STAGE = re.compile(r"^FROM\s+\S+\s+AS\s+([a-z0-9-]+)\s*$", re.MULTILINE)


def stage_body(text: str, name: str) -> str:
    match = re.search(
        rf"^FROM\s+\S+\s+AS\s+{re.escape(name)}\s*$([\s\S]*?)(?=^FROM\s|\Z)",
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
            r"CGO_ENABLED=0\s+GOOS=linux[^\n]*go build[\s\S]*?"
            r"-o /out/snaplink-billing\s+\\\n\s+\./cmd/snaplink-billing",
        )
        self.assertIn('ENTRYPOINT ["/snaplink-billing"]', self.text)

    def test_stripe_adapter_has_dedicated_static_build_and_runtime(self):
        self.assertIn("snaplink-stripe-adapter-builder", self.stages)
        self.assertIn("snaplink-stripe-adapter", self.stages)
        build = stage_body(self.text, "snaplink-stripe-adapter-builder")
        self.assertRegex(
            build,
            r"CGO_ENABLED=0\s+GOOS=linux[^\n]*go build[\s\S]*?"
            r"-o /out/snaplink-stripe-adapter\s+\\\n\s+\./cmd/snaplink-stripe-adapter",
        )
        self.assertIn('ENTRYPOINT ["/snaplink-stripe-adapter"]', self.text)

    def test_audit_provisioner_has_dedicated_static_build_and_runtime(self):
        self.assertIn("snaplink-audit-provisioner-builder", self.stages)
        self.assertIn("snaplink-audit-provisioner", self.stages)
        build = stage_body(self.text, "snaplink-audit-provisioner-builder")
        self.assertRegex(
            build,
            r"CGO_ENABLED=0\s+GOOS=linux[^\n]*go build[\s\S]*?"
            r"-o /out/snaplink-audit-provisioner\s+\\\n\s+\./cmd/snaplink-audit-provisioner",
        )
        self.assertIn('ENTRYPOINT ["/snaplink-audit-provisioner"]', self.text)

    def test_mcp_named_target_remains_available(self):
        self.assertIn("sso-mcp", self.stages)
        self.assertIn('ENTRYPOINT ["/sso-mcp"]', self.text)


if __name__ == "__main__":
    unittest.main()
