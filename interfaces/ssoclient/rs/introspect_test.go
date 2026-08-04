package rs_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
)

// introspectServer builds a minimal RFC 7662 endpoint: requires the given
// HTTP Basic client creds, form-encoded request, and answers with resp for
// any token (tests only ever probe one token per server).
func introspectServer(t *testing.T, wantID, wantSecret string, resp map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != wantID || secret != wantSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := r.ParseForm(); err != nil || r.PostForm.Get("token") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestValidateTokenWithIntrospect_Active(t *testing.T) {
	t.Parallel()
	srv := introspectServer(t, "rs-client", "rs-secret", map[string]any{
		"active": true,
		"iss":    "https://as.test",
		"sub":    "user-1",
		"aud":    "api://orders",
		"scope":  "orders:read",
		"exp":    9999999999,
	})
	cfg := rs.Config{
		Issuer:          "https://as.test",
		ExpectedAud:     "api://orders",
		IntrospectURL:   srv.URL,
		IntrospectCreds: &rs.ClientCreds{ID: "rs-client", Secret: "rs-secret"},
	}

	claims, err := rs.ValidateTokenWithIntrospect(context.Background(), "opaque-or-jwt-token", cfg)
	if err != nil {
		t.Fatalf("ValidateTokenWithIntrospect: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", claims.Subject)
	}
	if claims.RenewAfter != 0 {
		t.Errorf("RenewAfter = %d, want 0 (field absent from response)", claims.RenewAfter)
	}
}

// TestValidateTokenWithIntrospect_ServingRegion pins the remote-mode gate:
// the echoed serving_region must be PROJECTED onto Claims (the
// wireIntrospection embed alone is not enough — the projection literal is
// field-by-field), and the fail-closed gate applies to missing claims — a
// deliberate asymmetry with the optional iss/aud/exp neighbors, which are
// enforced only when present.
func TestValidateTokenWithIntrospect_ServingRegion(t *testing.T) {
	t.Parallel()
	mk := func(region string) rs.Config {
		srv := introspectServer(t, "rs-client", "rs-secret", map[string]any{
			"active":         true,
			"iss":            "https://as.test",
			"sub":            "user-1",
			"aud":            "api://orders",
			"exp":            9999999999,
			"serving_region": region,
		})
		return rs.Config{
			Issuer:          "https://as.test",
			ExpectedAud:     "api://orders",
			IntrospectURL:   srv.URL,
			IntrospectCreds: &rs.ClientCreds{ID: "rs-client", Secret: "rs-secret"},
		}
	}

	// In-set region -> valid, typed claim populated from the echo.
	inSet := mk("eu-west-1")
	inSet.AllowedServingRegions = []string{"eu-west-1"}
	claims, err := rs.ValidateTokenWithIntrospect(context.Background(), "opaque", inSet)
	if err != nil {
		t.Fatalf("ValidateTokenWithIntrospect(in-set): %v", err)
	}
	if claims.ServingRegion != "eu-west-1" {
		t.Errorf("ServingRegion = %q, want eu-west-1 (projected from echo)", claims.ServingRegion)
	}

	// Out-of-set region -> governance sentinel.
	outOfSet := mk("us-east-1")
	outOfSet.AllowedServingRegions = []string{"eu-west-1"}
	_, err = rs.ValidateTokenWithIntrospect(context.Background(), "opaque", outOfSet)
	if !errors.Is(err, rs.ErrServingRegionMismatch) {
		t.Fatalf("err = %v, want ErrServingRegionMismatch (out-of-set)", err)
	}

	// Missing echo + configured allowlist -> FAIL CLOSED: an AS that does
	// not echo the claim cannot serve a region-pinned deployment.
	noEcho := mk("")
	noEcho.AllowedServingRegions = []string{"eu-west-1"}
	_, err = rs.ValidateTokenWithIntrospect(context.Background(), "opaque", noEcho)
	if !errors.Is(err, rs.ErrServingRegionMismatch) {
		t.Fatalf("err = %v, want ErrServingRegionMismatch (no echo, configured)", err)
	}

	// Empty config -> gate skipped; the claim still projects.
	claims, err = rs.ValidateTokenWithIntrospect(context.Background(), "opaque", mk("eu-west-1"))
	if err != nil {
		t.Fatalf("ValidateTokenWithIntrospect(unconfigured): %v", err)
	}
	if claims.ServingRegion != "eu-west-1" || !claims.HasServingRegion() {
		t.Errorf("ServingRegion = %q, HasServingRegion = %v", claims.ServingRegion, claims.HasServingRegion())
	}
}

// TestValidateTokenWithIntrospect_RenewAfter proves the opt-in token-policy
// early-warning field is projected onto Claims.RenewAfter, not left
// reachable only via Claims.Raw.
func TestValidateTokenWithIntrospect_RenewAfter(t *testing.T) {
	t.Parallel()
	srv := introspectServer(t, "rs-client", "rs-secret", map[string]any{
		"active":      true,
		"iss":         "https://as.test",
		"sub":         "user-1",
		"aud":         "api://orders",
		"exp":         9999999999,
		"renew_after": 1234567890,
	})
	cfg := rs.Config{
		Issuer:          "https://as.test",
		ExpectedAud:     "api://orders",
		IntrospectURL:   srv.URL,
		IntrospectCreds: &rs.ClientCreds{ID: "rs-client", Secret: "rs-secret"},
	}

	claims, err := rs.ValidateTokenWithIntrospect(context.Background(), "opaque-or-jwt-token", cfg)
	if err != nil {
		t.Fatalf("ValidateTokenWithIntrospect: %v", err)
	}
	if claims.RenewAfter != 1234567890 {
		t.Errorf("RenewAfter = %d, want 1234567890", claims.RenewAfter)
	}
	if got, ok := claims.Raw["renew_after"]; !ok || got != float64(1234567890) {
		t.Errorf("Raw[renew_after] = %v, want 1234567890 (still reachable via Raw too)", got)
	}
}

func TestValidateTokenWithIntrospect_Inactive(t *testing.T) {
	t.Parallel()
	srv := introspectServer(t, "rs-client", "rs-secret", map[string]any{"active": false})
	cfg := rs.Config{
		Issuer:          "https://as.test",
		IntrospectURL:   srv.URL,
		IntrospectCreds: &rs.ClientCreds{ID: "rs-client", Secret: "rs-secret"},
	}

	_, err := rs.ValidateTokenWithIntrospect(context.Background(), "revoked-token", cfg)
	if !errors.Is(err, rs.ErrTokenInactive) {
		t.Fatalf("err = %v, want ErrTokenInactive", err)
	}
}

func TestValidateTokenWithIntrospect_WrongCredsFails(t *testing.T) {
	t.Parallel()
	srv := introspectServer(t, "rs-client", "rs-secret", map[string]any{"active": true})
	cfg := rs.Config{
		Issuer:          "https://as.test",
		IntrospectURL:   srv.URL,
		IntrospectCreds: &rs.ClientCreds{ID: "rs-client", Secret: "wrong"},
	}

	_, err := rs.ValidateTokenWithIntrospect(context.Background(), "any-token", cfg)
	if !errors.Is(err, rs.ErrIntrospection) {
		t.Fatalf("err = %v, want ErrIntrospection", err)
	}
}

func TestValidateTokenWithIntrospect_AudienceMismatch(t *testing.T) {
	t.Parallel()
	srv := introspectServer(t, "rs-client", "rs-secret", map[string]any{
		"active": true,
		"aud":    "api://billing",
	})
	cfg := rs.Config{
		Issuer:          "https://as.test",
		ExpectedAud:     "api://orders",
		IntrospectURL:   srv.URL,
		IntrospectCreds: &rs.ClientCreds{ID: "rs-client", Secret: "rs-secret"},
	}

	_, err := rs.ValidateTokenWithIntrospect(context.Background(), "any-token", cfg)
	if !errors.Is(err, rs.ErrAudienceMismatch) {
		t.Fatalf("err = %v, want ErrAudienceMismatch", err)
	}
}

func TestValidateTokenWithIntrospect_RequiresURLAndIssuer(t *testing.T) {
	t.Parallel()
	if _, err := rs.ValidateTokenWithIntrospect(context.Background(), "t", rs.Config{Issuer: "https://as.test"}); !errors.Is(err, rs.ErrConfig) {
		t.Fatalf("missing IntrospectURL: err = %v, want ErrConfig", err)
	}
}
