package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestAuditNotaryValidation(t *testing.T) {
	t.Parallel()
	if cfg := (AuditConfig{}); cfg.Notary.Enabled {
		t.Fatal("notary must default to disabled")
	}
	if err := (AuditNotaryConfig{}).validate(AuditConfig{}); err != nil {
		t.Fatalf("disabled notary rejected: %v", err)
	}

	tests := []struct {
		name string
		cfg  AuditConfig
		want string
	}{
		{
			name: "audit disabled",
			cfg:  AuditConfig{Notary: AuditNotaryConfig{Enabled: true, KeyFile: "/etc/sso/notary.pem"}},
			want: "audit.enabled",
		},
		{
			name: "hash chain disabled",
			cfg:  AuditConfig{Enabled: true, Backend: "sqlite", Notary: AuditNotaryConfig{Enabled: true, KeyFile: "/etc/sso/notary.pem"}},
			want: "audit.hash_chain",
		},
		{
			name: "memory backend",
			cfg:  AuditConfig{Enabled: true, HashChain: true, Backend: "memory", Notary: AuditNotaryConfig{Enabled: true, KeyFile: "/etc/sso/notary.pem"}},
			want: "durable audit.backend",
		},
		{
			name: "relative key",
			cfg:  AuditConfig{Enabled: true, HashChain: true, Backend: "postgres", Notary: AuditNotaryConfig{Enabled: true, KeyFile: "notary.pem"}},
			want: "absolute",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.cfg.Notary.validate(test.cfg); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v; want %q", err, test.want)
			}
		})
	}

	valid := AuditConfig{
		Enabled:   true,
		HashChain: true,
		Backend:   "sqlite",
		Notary: AuditNotaryConfig{
			Enabled:  true,
			Interval: -time.Second,
			KeyFile:  filepath.Join("/", "etc", "sso", "notary.pem"),
		},
	}
	if err := valid.Notary.validate(valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
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
