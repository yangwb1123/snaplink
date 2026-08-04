package config

import (
	"strings"
	"testing"
)

func TestTopologyConfigLoadsMultiReplicaOverride(t *testing.T) {
	path := writeTemp(t, "topology.yaml", `
server:
  topology:
    mode: MULTI
    allow_per_pod_state: true
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Topology.Mode != TopologyModeMulti {
		t.Fatalf("mode = %q; want %q", cfg.Server.Topology.Mode, TopologyModeMulti)
	}
	if !cfg.Server.Topology.AllowPerPodState {
		t.Fatal("allow_per_pod_state did not round-trip")
	}
}

func TestTopologyConfigRejectsUnknownMode(t *testing.T) {
	path := writeTemp(t, "topology.yaml", "server:\n  topology:\n    mode: elastic\n")
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "server.topology.mode") {
		t.Fatalf("err = %v; want topology mode validation error", err)
	}
}

func TestTopologyConfigRejectsUnsafeOverrideForSingleReplica(t *testing.T) {
	path := writeTemp(t, "topology.yaml", `
server:
  topology:
    mode: single
    allow_per_pod_state: true
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "allow_per_pod_state") {
		t.Fatalf("err = %v; want unsafe override validation error", err)
	}
}

func TestTenantResourceQuotaConfigNormalizesAndValidates(t *testing.T) {
	t.Run("empty backend is disabled", func(t *testing.T) {
		cfg, err := Load(writeTemp(t, "quota-disabled.yaml", "tenant:\n  enabled: false\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Tenant.ResourceQuota.Backend != "disabled" {
			t.Fatalf("backend = %q, want disabled", cfg.Tenant.ResourceQuota.Backend)
		}
	})

	t.Run("memory is rejected for every multi replica deployment", func(t *testing.T) {
		path := writeTemp(t, "quota-multi.yaml", `
server:
  topology:
    mode: multi
    allow_per_pod_state: true
tenant:
  enabled: true
  resource_quota:
    backend: memory
`)
		_, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), "resource_quota.backend=memory") {
			t.Fatalf("err = %v, want memory/multi validation error", err)
		}
	})

	t.Run("postgres requires shared pool", func(t *testing.T) {
		path := writeTemp(t, "quota-postgres.yaml", `
tenant:
  enabled: true
  resource_quota:
    backend: postgres
`)
		_, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), "postgres.dsn") {
			t.Fatalf("err = %v, want postgres pool validation error", err)
		}
	})

	t.Run("negative cleanup is rejected while disabled", func(t *testing.T) {
		path := writeTemp(t, "quota-negative-cleanup.yaml", `
tenant:
  resource_quota:
    backend: disabled
    cleanup_interval: -1s
`)
		_, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), "cleanup_interval") {
			t.Fatalf("err = %v, want cleanup interval validation error", err)
		}
	})

	t.Run("valid limits load", func(t *testing.T) {
		path := writeTemp(t, "quota-memory.yaml", `
tenant:
  enabled: true
  resource_quota:
    backend: memory
    cleanup_interval: 2m
    limits:
      - tenant_id: acme
        max_clients: 12
        max_users: 200
        max_sessions: 300
        max_token_rate: 25
`)
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if got := cfg.Tenant.ResourceQuota.Limits[0].MaxTokenRate; got != 25 {
			t.Fatalf("max_token_rate = %d, want 25", got)
		}
	})
}

func TestTenantQuotaProjectionIngressValidatesVersionedCompositeBindings(t *testing.T) {
	valid := `
tenant:
  enabled: true
  resource_quota:
    backend: memory
    projection_ingress:
      enabled: true
      audience: snaplink-sso
      sources:
        - id: billing-a
          client_id: billing-relay
          tenant_id: tenant-a
          source_system: billing:tenant-a
          enabled: true
          revision: 1
        - id: billing-b
          client_id: billing-relay
          tenant_id: tenant-b
          source_system: billing:tenant-b
          enabled: true
          revision: 1
`
	cfg, err := Load(writeTemp(t, "quota-projection.yaml", valid))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := len(cfg.Tenant.ResourceQuota.ProjectionIngress.Sources); got != 2 {
		t.Fatalf("sources = %d, want 2", got)
	}

	invalid := strings.Replace(valid, "billing:tenant-b", "billing:tenant-a", 1)
	if _, err := Load(writeTemp(t, "quota-projection-conflict.yaml", invalid)); err == nil || !strings.Contains(err.Error(), "projection_ingress sources") {
		t.Fatalf("cross-tenant source error = %v", err)
	}

	disabledBackend := strings.Replace(valid, "backend: memory", "backend: disabled", 1)
	if _, err := Load(writeTemp(t, "quota-projection-disabled.yaml", disabledBackend)); err == nil || !strings.Contains(err.Error(), "requires an enabled quota backend") {
		t.Fatalf("disabled backend error = %v", err)
	}
}
