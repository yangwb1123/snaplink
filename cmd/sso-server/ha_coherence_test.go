package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/config"
)

func TestHACoherenceRejectsPerProcessCriticalStores(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Topology:         config.TopologyConfig{Mode: config.TopologyModeMulti},
			PairwiseSubjects: config.PairwiseSubjectsConfig{Enabled: true},
		},
		MFA: config.MFAConfig{Enabled: true},
	}
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	err := b.enforceHACoherence()
	if err == nil {
		t.Fatal("multi-replica topology accepted process-local critical stores")
	}
	for _, key := range []string{
		"oauth.backend",
		"identity.session_backend",
		"identity.backend",
		"mfa.challenge.backend",
		"server.pairwise_subjects.backend",
	} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error %q does not identify %s", err, key)
		}
	}
}

func TestHACoherenceAcceptsSharedCriticalStores(t *testing.T) {
	cfg := &config.Config{
		OAuth:    config.OAuthConfig{Backend: "redis"},
		Identity: config.IdentityConfig{Backend: "postgres", SessionBackend: "redis"},
		Security: config.SecurityConfig{
			JTIReplay: config.JTIReplayConfig{Enabled: true, Backend: "redis"},
		},
		CIBA: config.CIBAConfig{Enabled: true, Backend: "redis"},
		MFA: config.MFAConfig{
			Enabled:   true,
			Challenge: config.MFAChallengeConfig{Backend: "redis"},
		},
		Server: config.ServerConfig{
			Topology:         config.TopologyConfig{Mode: config.TopologyModeMulti},
			PairwiseSubjects: config.PairwiseSubjectsConfig{Enabled: true, Backend: "postgres"},
		},
	}
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	if err := b.enforceHACoherence(); err != nil {
		t.Fatalf("shared topology rejected: %v", err)
	}
}

func TestHACoherenceUnsafeOverrideIsExplicit(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Topology: config.TopologyConfig{
				Mode:             config.TopologyModeMulti,
				AllowPerPodState: true,
			},
		},
	}
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	if err := b.enforceHACoherence(); err != nil {
		t.Fatalf("explicit development override rejected: %v", err)
	}
}

func TestKubernetesAdmissionPolicyCoversHACoherenceContract(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Topology:         config.TopologyConfig{Mode: config.TopologyModeMulti},
			PairwiseSubjects: config.PairwiseSubjectsConfig{Enabled: true},
		},
		Security: config.SecurityConfig{
			JTIReplay: config.JTIReplayConfig{Enabled: true},
		},
		CIBA: config.CIBAConfig{Enabled: true},
		MFA:  config.MFAConfig{Enabled: true},
		SelfService: config.SelfServiceConfig{
			IdentityLink: config.IdentityLinkConfig{Enabled: true},
		},
	}
	issues := (&appBuilder{cfg: cfg}).haCoherenceIssues()
	contract := map[string]string{
		"oauth.backend":                      "SSO_OAUTH__BACKEND",
		"identity.session_backend":           "SSO_IDENTITY__SESSION_BACKEND",
		"security.jti_replay.backend":        "SSO_SECURITY__JTI_REPLAY__BACKEND",
		"ciba.backend":                       "SSO_CIBA__BACKEND",
		"identity.backend":                   "SSO_IDENTITY__BACKEND",
		"mfa.challenge.backend":              "SSO_MFA__CHALLENGE__BACKEND",
		"self_service.identity_link.backend": "SSO_SELF_SERVICE__IDENTITY_LINK__BACKEND",
		"server.pairwise_subjects.backend":   "SSO_SERVER__PAIRWISE_SUBJECTS__BACKEND",
	}
	root := filepath.Join("..", "..")
	policy := readHAContractFile(t, filepath.Join(root, "ops", "deploy", "k8s-admission", "topology-policy.yaml"))
	prod := readHAContractFile(t, filepath.Join(root, "ops", "deploy", "kustomize", "overlays", "prod", "patch-deployment.yaml"))
	for _, issue := range issues {
		env, ok := contract[issue]
		if !ok {
			t.Fatalf("startup HA issue %q has no admission mapping", issue)
		}
		if !strings.Contains(policy, env) || !strings.Contains(prod, env) {
			t.Errorf("HA issue %q (%s) is absent from policy or prod deployment", issue, env)
		}
	}
	for _, required := range []string{"deployments/scale", "ALLOW_PER_POD_STATE", "snaplink.io/topology"} {
		if !strings.Contains(policy, required) {
			t.Errorf("admission policy missing %q guard", required)
		}
	}
}

func readHAContractFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
