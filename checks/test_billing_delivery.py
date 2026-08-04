#!/usr/bin/env python3
"""Pin Billing entitlement-to-retention production delivery contracts."""

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class TestBillingRetentionDelivery(unittest.TestCase):
    def test_kustomize_uses_a_dedicated_retention_secret(self):
        settings = read("ops/deploy/billing/settings.env")
        deployment = read("ops/deploy/billing/deployment.yaml")
        for name in (
            "SNAPLINK_BILLING_RETENTION_BASE_URL",
            "SNAPLINK_BILLING_RETENTION_TOKEN_URL",
            "SNAPLINK_BILLING_RETENTION_CLIENT_ID",
            "SNAPLINK_BILLING_RETENTION_RESOURCE",
            "SNAPLINK_BILLING_RETENTION_HTTP_TIMEOUT",
        ):
            self.assertIn(f"{name}=", settings)
        self.assertIn("SNAPLINK_BILLING_RETENTION_CLIENT_SECRET", deployment)
        self.assertIn("snaplink-billing-retention-secrets", deployment)

    def test_helm_schema_requires_retention_and_quota_together(self):
        schema = json.loads(
            read("ops/deploy/helm/snaplink-billing/values.schema.json")
        )
        settings = schema["properties"]["settings"]
        self.assertIn("retention", settings["required"])
        self.assertFalse(settings["properties"]["retention"]["additionalProperties"])
        serialized = json.dumps(schema["allOf"], sort_keys=True)
        self.assertIn("retentionExistingSecret", serialized)
        self.assertIn('"quota"', serialized)

    def test_helm_uses_a_separate_external_secret(self):
        values = read("ops/deploy/helm/snaplink-billing/values.yaml")
        deployment = read("ops/deploy/helm/snaplink-billing/templates/deployment.yaml")
        configmap = read("ops/deploy/helm/snaplink-billing/templates/configmap.yaml")
        self.assertIn("retentionExistingSecret: snaplink-billing-retention-secrets", values)
        self.assertIn("SNAPLINK_BILLING_RETENTION_CLIENT_SECRET", deployment)
        self.assertIn("secrets.retentionExistingSecret", deployment)
        self.assertIn("SNAPLINK_BILLING_RETENTION_BASE_URL", configmap)

    def test_baremetal_declares_third_distinct_identity(self):
        environment = read("ops/deploy/baremetal-ha/.env.example")
        compose = read("ops/deploy/baremetal-ha/docker-compose.yml")
        self.assertIn("BILLING_RETENTION_CLIENT_ID=", environment)
        self.assertIn("BILLING_RETENTION_CLIENT_SECRET=", environment)
        self.assertIn("SNAPLINK_BILLING_RETENTION_CLIENT_SECRET", compose)
        self.assertIn("SNAPLINK_BILLING_RETENTION_BASE_URL", compose)


if __name__ == "__main__":
    unittest.main()
