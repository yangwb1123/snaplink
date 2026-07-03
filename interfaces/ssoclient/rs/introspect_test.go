package rs_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/interfaces/ssoclient/rs"
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
