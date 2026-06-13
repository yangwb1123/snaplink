package ssotest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	sso "github.com/snaplink/sso"
)

// claimsACRLogin posts to /auth/login requesting an ACR through the OIDC
// Core §5.5.1.1 claims parameter (id_token.acr) instead of acr_values.
// claimsParam is the raw JSON object for the "claims" request parameter.
func claimsACRLogin(t *testing.T, srv *httptest.Server, claimsParam string) (int, map[string]any) {
	t.Helper()
	req := map[string]any{
		"provider":   "password",
		"client_id":  acrClientID,
		"credential": map[string]string{"username": acrUserID, "password": acrPassword},
	}
	if claimsParam != "" {
		req["claims"] = json.RawMessage(claimsParam)
	}
	raw, _ := json.Marshal(req)
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

// TestClaimsACR_ValuesMatchIssuesToken: the RP requests acr via the claims
// parameter's id_token.acr.values and the authenticator achieves one of them
// -> login succeeds (the claims channel is honored, not silently ignored).
func TestClaimsACR_ValuesMatchIssuesToken(t *testing.T) {
	const wantACR = "urn:mace:incommon:iap:silver"
	srv := newACREnforcementServer(t, wantACR)
	status, body := claimsACRLogin(t, srv, `{"id_token":{"acr":{"values":["urn:mace:incommon:iap:silver","urn:mace:incommon:iap:bronze"]}}}`)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if _, ok := body["access_token"].(string); !ok {
		t.Fatalf("expected access_token: %v", body)
	}
}

// TestClaimsACR_ValueMatchIssuesToken: the single-value `value` form of the
// claims-parameter acr request is also honored.
func TestClaimsACR_ValueMatchIssuesToken(t *testing.T) {
	const wantACR = "urn:level:high"
	srv := newACREnforcementServer(t, wantACR)
	status, body := claimsACRLogin(t, srv, `{"id_token":{"acr":{"value":"urn:level:high"}}}`)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if _, ok := body["access_token"].(string); !ok {
		t.Fatalf("expected access_token: %v", body)
	}
}

// TestClaimsACR_NonMatchingRejected: acr requested via claims parameter but
// the authenticator achieves a value not in the requested set ->
// 400 unmet_authentication_requirements (same strictness as acr_values).
func TestClaimsACR_NonMatchingRejected(t *testing.T) {
	srv := newACREnforcementServer(t, "urn:level:low")
	status, body := claimsACRLogin(t, srv, `{"id_token":{"acr":{"values":["urn:mace:incommon:iap:silver"]}}}`)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["error"] != sso.ErrUnmetAuthReqs {
		t.Errorf("error=%v want %q", body["error"], sso.ErrUnmetAuthReqs)
	}
}

// TestClaimsACR_EmptyAchievedRejected: claims-parameter acr requested but the
// authenticator reports no ACR -> rejected.
func TestClaimsACR_EmptyAchievedRejected(t *testing.T) {
	srv := newACREnforcementServer(t, "")
	status, body := claimsACRLogin(t, srv, `{"id_token":{"acr":{"values":["urn:mace:incommon:iap:bronze"]}}}`)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["error"] != sso.ErrUnmetAuthReqs {
		t.Errorf("error=%v want %q", body["error"], sso.ErrUnmetAuthReqs)
	}
}

// TestClaimsACR_NoACRClaimSucceeds: a claims parameter that requests other
// id_token claims but NOT acr imposes no ACR constraint -> login succeeds
// regardless of AchievedACR (the gate only fires on a real acr request).
func TestClaimsACR_NoACRClaimSucceeds(t *testing.T) {
	srv := newACREnforcementServer(t, "")
	status, body := claimsACRLogin(t, srv, `{"id_token":{"email":null}}`)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v (claims without acr must not gate)", status, body)
	}
	if _, ok := body["access_token"].(string); !ok {
		t.Errorf("expected access_token: %v", body)
	}
}

// TestClaimsACR_UnionWithACRValues: when BOTH acr_values and the claims
// parameter request ACRs, achieving a value from EITHER channel satisfies the
// gate (the enforced set is their union).
func TestClaimsACR_UnionWithACRValues(t *testing.T) {
	const achieved = "urn:from:claims"
	srv := newACREnforcementServer(t, achieved)
	req := map[string]any{
		"provider":   "password",
		"client_id":  acrClientID,
		"credential": map[string]string{"username": acrUserID, "password": acrPassword},
		"acr_values": "urn:from:acrvalues",
		"claims":     json.RawMessage(`{"id_token":{"acr":{"values":["urn:from:claims"]}}}`),
	}
	raw, _ := json.Marshal(req)
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%v (claims-channel ACR should satisfy the union)", resp.StatusCode, out)
	}
	if _, ok := out["access_token"].(string); !ok {
		t.Errorf("expected access_token: %v", out)
	}
}
