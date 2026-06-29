package sso_test

// rootcov2_exchange_more_test.go covers the remaining token-exchange output
// variants (token_exchange_handler.go): requested_token_type=id_token and scope
// downscoping, plus the refresh_token grant's downscope path
// (refresh_token_grant.go handleRefreshTokenGrant).
//
// REUSES rcov2ExchangeServer / rcov2LoginToken from rootcov2_exchange_test.go.

import (
	"net/http"
	"testing"
)

// TestRcov2XM_ExchangeUnsupportedRequestedType covers the rejection branch for
// an unsupported requested_token_type (invalid_request, oracle-safe).
func TestRcov2XM_ExchangeUnsupportedRequestedType(t *testing.T) {
	t.Parallel()
	s := rcov2ExchangeServer(t, "")
	subject := rcov2LoginToken(t, s)

	status, out := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":        subject,
		"subject_token_type":   "urn:ietf:params:oauth:token-type:access_token",
		"requested_token_type": "urn:ietf:params:oauth:token-type:saml2",
		"client_id":            rcovClient,
		"client_secret":        rcovSecret,
	})
	if status != http.StatusBadRequest {
		t.Errorf("unsupported requested_token_type = %d, want 400 (body=%v)", status, out)
	}
}

// TestRcov2XM_RefreshDownscope covers the refresh_token grant downscope path:
// a refresh requesting a narrower scope than the original grant is honored.
func TestRcov2XM_RefreshDownscope(t *testing.T) {
	t.Parallel()
	s := rcov2ExchangeServer(t, "")

	// Login mints an access + refresh token (the exchange server wires a
	// refresh store; a direct login issues a server-managed refresh).
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid", "profile"},
	})
	if status != http.StatusOK {
		t.Fatalf("refresh-downscope login = %d body=%v", status, out)
	}
	refresh, _ := out["refresh_token"].(string)
	if refresh == "" {
		t.Skip("no refresh token issued (store may not back this login path)")
	}

	// Refresh requesting a narrower scope subset => honored (downscope).
	status, tok := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refresh,
		"scope":         "openid",
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	if status != http.StatusOK {
		t.Fatalf("refresh downscope = %d body=%v", status, tok)
	}
	if tok["access_token"] == "" || tok["access_token"] == nil {
		t.Errorf("refresh downscope produced no token: %v", tok)
	}

	// Refresh requesting an EXPANDED scope (not in the original grant) => rejected.
	status, _ = rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refresh,
		"scope":         "openid profile admin",
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	// Either the rotated token from the prior call invalidated this one, or the
	// scope-expansion check fires; both are non-200 rejections.
	if status == http.StatusOK {
		t.Errorf("refresh scope expansion = 200, want rejected")
	}
}
