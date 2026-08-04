#!/usr/bin/env python3
"""Pin the Stripe adapter's production delivery surfaces."""

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class TestStripeDelivery(unittest.TestCase):
    def test_kustomize_declares_new_required_runtime_fields(self):
        settings = read("ops/deploy/billing/stripe-adapter/settings.env")
        for name in (
            "SNAPLINK_STRIPE_LIVE_MODE",
            "SNAPLINK_STRIPE_ACCOUNT",
            "SNAPLINK_STRIPE_WEBHOOK_API_VERSION",
            "SNAPLINK_STRIPE_HANDLER_TIMEOUT",
        ):
            self.assertIn(f"{name}=", settings)

    def test_ci_builds_image_and_renders_both_kubernetes_forms(self):
        workflow = read(".github/workflows/ci.yml")
        self.assertIn("target: snaplink-stripe-adapter", workflow)
        self.assertIn("kustomize build ops/deploy/billing/stripe-adapter/", workflow)
        self.assertIn("helm lint --strict ops/deploy/helm/snaplink-stripe-adapter", workflow)
        self.assertIn("--profile payment config", workflow)

    def test_makefile_exposes_build_and_render_contracts(self):
        makefile = read("Makefile")
        self.assertIn("docker-stripe-adapter:", makefile)
        self.assertIn("--target snaplink-stripe-adapter", makefile)
        self.assertIn("kustomize build ops/deploy/billing/stripe-adapter", makefile)
        self.assertIn("helm lint --strict ops/deploy/helm/snaplink-stripe-adapter", makefile)

    def test_static_config_validation_injects_nonsecret_postgres_dsn(self):
        makefile = read("Makefile")
        self.assertIn(
            "VALIDATION_POSTGRES_DSN := "
            "postgres://validation@postgres.invalid/snaplink?sslmode=verify-full",
            makefile,
        )
        self.assertGreaterEqual(makefile.count("SSO_POSTGRES__DSN='$(VALIDATION_POSTGRES_DSN)'"), 2)

    def test_helm_values_schema_is_strict_and_digest_aware(self):
        schema_path = ROOT / "ops/deploy/helm/snaplink-stripe-adapter/values.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertFalse(schema["properties"]["settings"]["additionalProperties"])
        self.assertFalse(schema["properties"]["secrets"]["additionalProperties"])
        digest = schema["definitions"]["image"]["properties"]["digest"]["pattern"]
        self.assertIn("sha256", digest)

    def test_helm_mounts_one_binding_file_and_external_secrets(self):
        deployment = read(
            "ops/deploy/helm/snaplink-stripe-adapter/templates/deployment.yaml"
        )
        settings = read(
            "ops/deploy/helm/snaplink-stripe-adapter/templates/configmap.yaml"
        )
        self.assertIn("subPath: {{ .Values.bindings.key }}", deployment)
        self.assertIn("secrets.existingSecret", deployment)
        self.assertIn("tls.existingSecret", deployment)
        self.assertIn("topologySpreadConstraints", deployment)
        self.assertIn("readOnlyRootFilesystem: true", deployment)
        for name in (
            "SNAPLINK_STRIPE_LIVE_MODE",
            "SNAPLINK_STRIPE_ACCOUNT",
            "SNAPLINK_STRIPE_WEBHOOK_API_VERSION",
            "SNAPLINK_STRIPE_HANDLER_TIMEOUT",
        ):
            self.assertIn(name, settings)

    def test_compose_profile_keeps_adapter_behind_loopback_edge(self):
        compose = read("ops/deploy/compose/compose.yaml")
        self.assertIn('profiles: ["payment"]', compose)
        self.assertIn('network_mode: "service:stripe-edge"', compose)
        self.assertIn("SNAPLINK_STRIPE_LISTEN: 127.0.0.1:8091", compose)
        self.assertIn("stripe-bindings-init:", compose)
        self.assertIn("chmod 0444 /target/bindings.json", compose)

    def test_baremetal_is_two_instance_active_active(self):
        compose = read("ops/deploy/baremetal-ha/docker-compose.yml")
        haproxy = read("ops/deploy/baremetal-ha/haproxy/haproxy.cfg")
        unit = read("ops/deploy/baremetal-ha/systemd/snaplink-stripe-adapter.service")
        self.assertIn("stripe-a: &stripe-adapter", compose)
        self.assertIn("stripe-b:", compose)
        self.assertIn("server stripe-local 127.0.0.1:8091 check", haproxy)
        self.assertIn("http-check send meth GET uri /readyz", haproxy)
        self.assertIn("EnvironmentFile=/etc/snaplink/stripe-adapter.env", unit)

    def test_docker_context_excludes_generated_and_secret_material(self):
        ignored = read(".dockerignore")
        for entry in (
            "/bin/",
            "/dist/",
            "/snaplink-billing",
            "/sso-server",
            "/ops/deploy/compose/secrets/",
            "/ops/deploy/baremetal-ha/secrets/",
        ):
            self.assertIn(entry, ignored)


if __name__ == "__main__":
    unittest.main()
