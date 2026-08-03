package tokenpolicy

import (
	"testing"
	"time"
)

// TestParseYAML_FullDocument proves a realistic rule set round-trips, including
// Go duration strings decoding into MaxTTL and the nested block_scope_combos.
func TestParseYAML_FullDocument(t *testing.T) {
	t.Parallel()
	doc := []byte(`
token_policies:
  - name: high-value-short-ttl
    client_id: payments-api
    scopes: [payments]
    max_ttl: 5m
    require_renew_after: 0.5
  - name: no-admin-openid
    block_scope_combos:
      - [admin:*, openid]
    max_refresh_depth: 3
    max_active_sessions: 4
  - name: tenant-svc
    tenant_id: ta
    subject: svc-*
    subject_roles: [admin, member]
    max_ttl: 2m
`)
	policies, err := ParseYAML(doc)
	if err != nil {
		t.Fatalf("ParseYAML: %v", err)
	}
	if len(policies) != 3 {
		t.Fatalf("got %d policies, want 3", len(policies))
	}

	p0 := policies[0]
	if p0.Name != "high-value-short-ttl" || p0.ClientID != "payments-api" {
		t.Errorf("policy[0] selector = %+v", p0)
	}
	if p0.MaxTTL != 5*time.Minute {
		t.Errorf("policy[0].MaxTTL = %v, want 5m", p0.MaxTTL)
	}
	if len(p0.Scopes) != 1 || p0.Scopes[0] != "payments" {
		t.Errorf("policy[0].Scopes = %v", p0.Scopes)
	}
	if p0.RequireRenewAfter != 0.5 {
		t.Errorf("policy[0].RequireRenewAfter = %v, want 0.5", p0.RequireRenewAfter)
	}

	p1 := policies[1]
	if p1.MaxRefreshDepth != 3 || p1.MaxActiveSessions != 4 {
		t.Errorf("policy[1] caps = %+v", p1)
	}
	if len(p1.BlockScopeCombos) != 1 || len(p1.BlockScopeCombos[0]) != 2 ||
		p1.BlockScopeCombos[0][0] != "admin:*" || p1.BlockScopeCombos[0][1] != "openid" {
		t.Errorf("policy[1].BlockScopeCombos = %v", p1.BlockScopeCombos)
	}

	p2 := policies[2]
	if p2.TenantID != "ta" || p2.Subject != "svc-*" {
		t.Errorf("policy[2] tenant/subject = %q/%q, want ta/svc-*", p2.TenantID, p2.Subject)
	}
	if len(p2.SubjectRoles) != 2 || p2.SubjectRoles[0] != "admin" || p2.SubjectRoles[1] != "member" {
		t.Errorf("policy[2].SubjectRoles = %v, want [admin member]", p2.SubjectRoles)
	}
	if p2.MaxTTL != 2*time.Minute {
		t.Errorf("policy[2].MaxTTL = %v, want 2m", p2.MaxTTL)
	}
}

// TestParseYAML_Empty proves an absent/empty list is a valid "no policies"
// configuration, not an error. NOTE: a stray top-level key (e.g. `other: 1`)
// is now a strict-parse ERROR, not "no policies" — see TestParseYAML_Malformed
// (the strictness flip, design 3d).
func TestParseYAML_Empty(t *testing.T) {
	t.Parallel()
	for _, doc := range [][]byte{[]byte(""), []byte("token_policies: []\n")} {
		policies, err := ParseYAML(doc)
		if err != nil {
			t.Fatalf("ParseYAML(%q): %v", doc, err)
		}
		if len(policies) != 0 {
			t.Fatalf("ParseYAML(%q) = %d policies, want 0", doc, len(policies))
		}
	}
}

// TestParseYAML_Malformed proves invalid documents surface an error rather
// than a silent empty set: malformed YAML, a stray top-level key (previously
// tolerated as "no policies" — now strict), and a misspelled selector field
// on an item (the tennat_id typo that would silently demote a tenant rule to
// a fleet-wide global rule).
func TestParseYAML_Malformed(t *testing.T) {
	t.Parallel()
	for _, doc := range [][]byte{
		[]byte("token_policies: [:::not yaml"),
		[]byte("other: 1\n"),                                        // stray top-level key (was tolerated)
		[]byte("token_policies:\n  - name: x\n    tennat_id: ta\n"), // misspelled selector
	} {
		if _, err := ParseYAML(doc); err == nil {
			t.Fatalf("ParseYAML(%q) = nil error, want a decode error", doc)
		}
	}
}

// TestParseYAML_LegacyBareStarScopeStillLoads pins the legacy-compat corner:
// a bare "*" SCOPE selector keeps today's match-all semantics (Validate
// deliberately leaves scopes unvalidated), so an existing bundle keeps
// loading — the strictness flip gates only the new client_id/subject
// selectors and tenant_id.
func TestParseYAML_LegacyBareStarScopeStillLoads(t *testing.T) {
	t.Parallel()
	doc := []byte("token_policies:\n  - name: legacy\n    scopes: [\"*\"]\n")
	policies, err := ParseYAML(doc)
	if err != nil {
		t.Fatalf("ParseYAML(legacy bare-star scope): %v", err)
	}
	if len(policies) != 1 || len(policies[0].Scopes) != 1 || policies[0].Scopes[0] != "*" {
		t.Fatalf("legacy scope selector = %+v, want [*] to survive", policies)
	}
}
