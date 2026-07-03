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
`)
	policies, err := ParseYAML(doc)
	if err != nil {
		t.Fatalf("ParseYAML: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("got %d policies, want 2", len(policies))
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
}

// TestParseYAML_Empty proves an absent/empty list is a valid "no policies"
// configuration, not an error.
func TestParseYAML_Empty(t *testing.T) {
	t.Parallel()
	for _, doc := range [][]byte{[]byte(""), []byte("token_policies: []\n"), []byte("other: 1\n")} {
		policies, err := ParseYAML(doc)
		if err != nil {
			t.Fatalf("ParseYAML(%q): %v", doc, err)
		}
		if len(policies) != 0 {
			t.Fatalf("ParseYAML(%q) = %d policies, want 0", doc, len(policies))
		}
	}
}

// TestParseYAML_Malformed proves invalid YAML surfaces an error rather than a
// silent empty set.
func TestParseYAML_Malformed(t *testing.T) {
	t.Parallel()
	if _, err := ParseYAML([]byte("token_policies: [:::not yaml")); err == nil {
		t.Fatal("ParseYAML(malformed) = nil error, want a decode error")
	}
}
