package oauth

import (
	"encoding/json"
	"testing"
)

func TestParseRequestedClaimsEmpty(t *testing.T) {
	t.Parallel()
	id, ui, err := ParseRequestedClaims(nil)
	if err != nil || id != nil || ui != nil {
		t.Fatalf("empty raw: want nil,nil,nil got %v,%v,%v", id, ui, err)
	}
}

func TestParseRequestedClaimsNullEntry(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{"id_token":{"sub":null},"userinfo":{"email":null}}`)
	id, ui, err := ParseRequestedClaims(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cr, ok := id["sub"]; !ok || cr != nil {
		t.Fatalf("id_token.sub: want nil ClaimRequest got %v", cr)
	}
	if cr, ok := ui["email"]; !ok || cr != nil {
		t.Fatalf("userinfo.email: want nil ClaimRequest got %v", cr)
	}
}

func TestParseRequestedClaimsEssential(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{"id_token":{"acr":{"essential":true,"values":["urn:level:2"]}}}`)
	id, _, err := ParseRequestedClaims(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cr := id["acr"]
	if cr == nil {
		t.Fatal("acr ClaimRequest should not be nil")
	}
	if !cr.Essential {
		t.Error("Essential should be true")
	}
	if len(cr.Values) != 1 {
		t.Fatalf("want 1 value got %d", len(cr.Values))
	}
	var got string
	if err := json.Unmarshal(cr.Values[0], &got); err != nil {
		t.Fatalf("unmarshal value: %v", err)
	}
	if got != "urn:level:2" {
		t.Errorf("want urn:level:2 got %q", got)
	}
}

func TestParseRequestedClaimsSingleValue(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{"userinfo":{"given_name":{"essential":true,"value":"Alice"}}}`)
	_, ui, err := ParseRequestedClaims(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cr := ui["given_name"]
	if cr == nil {
		t.Fatal("given_name ClaimRequest should not be nil")
	}
	if !cr.Essential {
		t.Error("Essential should be true")
	}
	var got string
	if err := json.Unmarshal(cr.Value, &got); err != nil {
		t.Fatalf("unmarshal Value: %v", err)
	}
	if got != "Alice" {
		t.Errorf("want Alice got %q", got)
	}
}

func TestParseRequestedClaimsMissingSection(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{"userinfo":{"email":null}}`)
	id, ui, err := ParseRequestedClaims(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != nil {
		t.Errorf("id_token section absent: want nil got %v", id)
	}
	if _, ok := ui["email"]; !ok {
		t.Error("userinfo.email should be present")
	}
}
