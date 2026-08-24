package config

import (
	"strings"
	"testing"
)

func TestValidateVersion(t *testing.T) {
	t.Run("valid version", func(t *testing.T) {
		err := ValidateVersion(&Config{Version: CurrentSchemaVersion})
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("unset version", func(t *testing.T) {
		err := ValidateVersion(&Config{Version: 0})
		if err != nil {
			t.Errorf("expected nil (warning only) for unset version, got %v", err)
		}
	})

	t.Run("wrong version", func(t *testing.T) {
		err := ValidateVersion(&Config{Version: 999})
		if err == nil {
			t.Error("expected error for wrong version")
		}
	})
}

func TestCurrentSchemaVersion(t *testing.T) {
	if CurrentSchemaVersion != 1 {
		t.Errorf("expected 1, got %d", CurrentSchemaVersion)
	}
}

func TestDefaultFileName(t *testing.T) {
	if DefaultFileName != "config.yaml" {
		t.Errorf("expected 'config.yaml', got %q", DefaultFileName)
	}
}

func TestReBACConfigValidation(t *testing.T) {
	if err := (ReBACConfig{Enabled: true, Backend: "memory"}).validate(); err != nil {
		t.Fatalf("memory config rejected: %v", err)
	}
	if err := (ReBACConfig{Enabled: true, Backend: "sqlite"}).validate(); err == nil {
		t.Fatal("sqlite config without DSN accepted")
	}
	if err := (ReBACConfig{Enabled: true, Backend: "redis"}).validate(); err == nil {
		t.Fatal("unknown backend accepted")
	}
	multi := &Config{
		Server: ServerConfig{Topology: TopologyConfig{Mode: TopologyModeMulti}},
		ReBAC:  ReBACConfig{Enabled: true, Backend: "memory"},
	}
	if err := multi.validateTopology(); err == nil {
		t.Fatal("multi-replica memory ReBAC was accepted")
	}
	multi.Server.Topology.AllowPerPodState = true
	if err := multi.validateTopology(); err != nil {
		t.Fatalf("explicit per-pod override rejected: %v", err)
	}
}

func TestExternalAuditWorkerValidationRequiresSignedLocalAdmission(t *testing.T) {
	cfg := &Config{Audit: AuditConfig{ExternalWorker: ExternalAuditWorkerConfig{
		Enabled: true, ModuleID: "audit-worker", Executable: "/opt/audit-worker",
		SocketPath: "/run/snaplink/audit.sock", AuthToken: "secret",
		ExpectedSHA256: strings.Repeat("a", 64), ProvenancePath: "/etc/snaplink/audit.json",
		ProvenancePublicKey: strings.Repeat("b", 64), ReleaseID: "release-1", BuildProfile: "standard",
	}}}
	if err := cfg.Audit.ExternalWorker.validate(); err != nil {
		t.Fatalf("valid local worker rejected: %v", err)
	}
	cfg.Audit.ExternalWorker.ProvenancePath = "relative.json"
	if err := cfg.Audit.ExternalWorker.validate(); err == nil {
		t.Fatal("relative provenance path accepted")
	}
}

func TestExternalAuditWorkerValidationRequiresAuditAndSeparatesRemoteMode(t *testing.T) {
	cfg := &Config{Audit: AuditConfig{ExternalWorker: ExternalAuditWorkerConfig{
		Enabled: true, ModuleID: "audit-worker", AuthToken: "secret",
		RemoteAddress: "worker.example:9443", TLS: ExternalAuditWorkerTLSConfig{
			CertFile: "/etc/snaplink/client.crt", KeyFile: "/etc/snaplink/client.key",
		}, ProvenancePublicKey: "must-not-be-here",
	}}}
	if err := cfg.validateFeatureConfig(); err == nil || !strings.Contains(err.Error(), "audit.enabled") {
		t.Fatalf("external worker without audit enabled error = %v", err)
	}
	cfg.Audit.Enabled = true
	if err := cfg.validateFeatureConfig(); err == nil || !strings.Contains(err.Error(), "local provenance") {
		t.Fatalf("remote worker with local provenance error = %v", err)
	}
}
