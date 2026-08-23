package config

import (
	"strings"
	"testing"
)

func TestActivationConfigValidation(t *testing.T) {
	valid := ActivationConfig{Backend: "memory", Codes: []ActivationCodeConfig{{
		ID: "license-1", ProductID: "pro", TenantID: "tenant-1", LicenseKey: "secret://static/pro-1",
	}}}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid activation config rejected: %v", err)
	}
	cases := []struct {
		name string
		cfg  ActivationConfig
		want string
	}{
		{"codes without backend", ActivationConfig{Codes: valid.Codes}, "backend=memory"},
		{"unknown backend", ActivationConfig{Backend: "postgres"}, "must be memory"},
		{"both credentials", ActivationConfig{Backend: "memory", Codes: []ActivationCodeConfig{{
			ID: "code", ProductID: "pro", TenantID: "tenant", LicenseKey: "a", InvitationCode: "b",
		}}}, "exactly one"},
		{"duplicate id", ActivationConfig{Backend: "memory", Codes: []ActivationCodeConfig{{
			ID: "same", ProductID: "pro", TenantID: "tenant", LicenseKey: "a",
		}, {
			ID: "same", ProductID: "pro", TenantID: "tenant", LicenseKey: "b",
		}}}, "duplicates"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := test.cfg.validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestActivationMemoryBackendRejectedForMultiReplica(t *testing.T) {
	cfg := &Config{
		Server:     ServerConfig{Topology: TopologyConfig{Mode: TopologyModeMulti}},
		Activation: ActivationConfig{Backend: "memory"},
	}
	if err := cfg.validateTopology(); err == nil || !strings.Contains(err.Error(), "activation.backend=memory") {
		t.Fatalf("multi-replica memory activation error = %v", err)
	}
	cfg.Server.Topology.AllowPerPodState = true
	if err := cfg.validateTopology(); err != nil {
		t.Fatalf("explicit per-pod activation override rejected: %v", err)
	}
}
