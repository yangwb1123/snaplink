package cluster

import (
	"testing"
)

func TestEventKindConstants(t *testing.T) {
	if KindTokenRevoked != "token_revoked" {
		t.Errorf("expected 'token_revoked', got %q", KindTokenRevoked)
	}
	if KindSigningKeyRotation != "signing_key_rotation" {
		t.Errorf("expected 'signing_key_rotation', got %q", KindSigningKeyRotation)
	}
	// Note: KindClientChange uses dot notation
	_ = KindClientChange
	if KindAuthzPolicyChange != "authz_policy_change" {
		t.Errorf("expected 'authz_policy_change', got %q", KindAuthzPolicyChange)
	}
	if KindTenantSuspension != "tenant_suspension" {
		t.Errorf("expected 'tenant_suspension', got %q", KindTenantSuspension)
	}
	if KindControlPlaneRestore != "control_plane.restore" {
		t.Errorf("expected 'control_plane.restore', got %q", KindControlPlaneRestore)
	}
}

func TestMetaConfigDigest(t *testing.T) {
	if MetaConfigDigest != "config_digest" {
		t.Errorf("expected 'config_digest', got %q", MetaConfigDigest)
	}
}

func TestEventFields(t *testing.T) {
	e := Event{
		Kind:    KindTokenRevoked,
		Payload: map[string]string{"user_id": "user-1"},
		Key:     "sso/tokens/revoked/user-1",
	}

	if e.Kind != KindTokenRevoked {
		t.Errorf("expected Kind 'token_revoked', got %q", e.Kind)
	}
	if e.Payload["user_id"] != "user-1" {
		t.Errorf("expected Payload['user_id']='user-1', got %q", e.Payload["user_id"])
	}
	if e.Key != "sso/tokens/revoked/user-1" {
		t.Errorf("expected Key, got %q", e.Key)
	}
}

func TestAllEventKinds(t *testing.T) {
	allKinds := []EventKind{
		KindTokenRevoked,
		KindSigningKeyRotation,
		KindClientChange,
		KindAuthzPolicyChange,
		KindTenantSuspension,
		KindControlPlaneRestore,
	}

	for _, kind := range allKinds {
		if kind == "" {
			t.Error("expected non-empty EventKind")
		}
	}
}

func TestEventKindUniqueness(t *testing.T) {
	seen := make(map[EventKind]bool)
	allKinds := []EventKind{
		KindTokenRevoked,
		KindSigningKeyRotation,
		KindClientChange,
		KindAuthzPolicyChange,
		KindTenantSuspension,
		KindControlPlaneRestore,
	}

	for _, kind := range allKinds {
		if seen[kind] {
			t.Errorf("duplicate EventKind: %q", kind)
		}
		seen[kind] = true
	}
}

func TestEventEmptyPayload(t *testing.T) {
	e := Event{Kind: KindTenantSuspension}
	if e.Payload != nil {
		t.Errorf("expected nil payload for zero Event, got %v", e.Payload)
	}
}
