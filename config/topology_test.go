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
