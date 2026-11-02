package rs_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
)

func revocationRequest(cfg rs.Config, token, scheme, proof string, ctx context.Context, next http.Handler) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, testHTU, nil).WithContext(ctx)
	req.Header.Set("Authorization", scheme+" "+token)
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	rec := httptest.NewRecorder()
	rs.HTTPMiddleware(cfg, next).ServeHTTP(rec, req)
	return rec
}

func assertRevocationWireFailure(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusUnauthorized || rec.Body.String() != `{"error":"invalid_token"}` {
		t.Errorf("status/body = %d/%q, want identical 401 invalid_token", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer error="invalid_token", error_description="token validation failed"` {
		t.Errorf("WWW-Authenticate = %q, want existing coarse challenge", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
}

func TestRevocationCheck_HTTPMiddlewareOracle(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		missing   bool
		revoked   bool
		err       error
		cancel    bool
		wantCalls int
	}{
		{name: "revoked", revoked: true, wantCalls: 1},
		{name: "backend_failure", err: errors.New("private backend secret\r\nInjected: detail"), wantCalls: 1},
		{name: "backend_expiry_error", err: fmt.Errorf("%w: private backend", rs.ErrTokenExpired), wantCalls: 1},
		{name: "backend_governance_error", err: fmt.Errorf("%w: private backend", rs.ErrServingRegionMismatch), wantCalls: 1},
		{name: "missing_jti", missing: true},
		{name: "canceled", cancel: true, wantCalls: 1},
	}
	for _, mode := range []string{"local", "introspection"} {
		for _, tc := range cases {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				overrides := map[string]any{}
				if tc.missing {
					overrides["jti"] = nil
				}
				token, cfg := revocationFixture(t, mode, overrides)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				calls, served := 0, false
				cfg.RevocationCheck = func(context.Context, rs.RevocationToken) (bool, error) {
					calls++
					if tc.cancel {
						cancel()
					}
					return tc.revoked, tc.err
				}
				next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served = true })
				rec := revocationRequest(cfg, token, "Bearer", "", ctx, next)
				assertRevocationWireFailure(t, rec)
				if served || calls != tc.wantCalls {
					t.Errorf("served=%v, callback calls=%d, want false/%d", served, calls, tc.wantCalls)
				}
			})
		}
	}
}

func TestRevocationCheck_HTTPMiddlewareNilCompatibility(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"local", "introspection"} {
		t.Run(mode, func(t *testing.T) {
			token, cfg := revocationFixture(t, mode, map[string]any{"jti": nil})
			served := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				served = true
				claims, ok := rs.ClaimsFromContext(r.Context())
				if !ok || claims == nil || claims.JTI != "" || claims.TenantID != "tenant-1" {
					t.Errorf("nil hook changed missing-jti or tenant behavior: claims=%+v, ok=%v", claims, ok)
				}
				w.WriteHeader(http.StatusNoContent)
			})
			rec := revocationRequest(cfg, token, "Bearer", "", context.Background(), next)
			if !served || rec.Code != http.StatusNoContent || rec.Header().Get("WWW-Authenticate") != "" {
				t.Errorf("nil hook: served=%v, status=%d, headers=%v", served, rec.Code, rec.Header())
			}
		})
	}
}

func TestRevocationCheck_HTTPMiddlewareRegionUnchanged(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"local", "introspection"} {
		t.Run(mode, func(t *testing.T) {
			token, cfg := revocationFixture(t, mode, map[string]any{"serving_region": "us-east-1"})
			calls, served := 0, false
			cfg.RevocationCheck = func(context.Context, rs.RevocationToken) (bool, error) {
				calls++
				return false, nil
			}
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served = true })
			rec := revocationRequest(cfg, token, "Bearer", "", context.Background(), next)
			if served || calls != 0 || rec.Code != http.StatusForbidden || rec.Body.String() != `{"error":"region_not_allowed"}` {
				t.Errorf("region denial changed: served=%v, calls=%d, status/body=%d/%q", served, calls, rec.Code, rec.Body.String())
			}
			if rec.Header().Get("WWW-Authenticate") != "" || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
				t.Errorf("region denial headers changed: %v", rec.Header())
			}
		})
	}
}

func TestRevocationCheck_DPoPStillEnforced(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"local", "introspection"} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/enabled=%v", mode, enabled), func(t *testing.T) {
				key, attacker := newDPoPKey(t), newDPoPKey(t)
				token, cfg := revocationFixture(t, mode, map[string]any{"cnf": map[string]any{"jkt": key.thumbprint()}})
				cfg.DPoPVerifier = rs.NewDPoPVerifier()
				calls := 0
				if enabled {
					cfg.RevocationCheck = func(_ context.Context, value rs.RevocationToken) (bool, error) {
						calls++
						value.JTI, value.ClientID = "changed", "changed"
						return false, nil
					}
				}
				proof := key.proof(t, testHTM, testHTU, token, time.Now().Unix(), "good-proof")
				cases := []struct {
					name, scheme, proof string
					status              int
				}{
					{"bearer_without_proof", "Bearer", "", http.StatusUnauthorized},
					{"dpop_without_proof", "DPoP", "", http.StatusUnauthorized},
					{"wrong_method", "DPoP", key.proof(t, "POST", testHTU, token, time.Now().Unix(), "wrong-method"), http.StatusUnauthorized},
					{"wrong_key", "DPoP", attacker.proof(t, testHTM, testHTU, token, time.Now().Unix(), "wrong-key"), http.StatusUnauthorized},
					{"valid_proof", "DPoP", proof, http.StatusNoContent},
					{"replayed_proof", "DPoP", proof, http.StatusUnauthorized},
				}
				for _, tc := range cases {
					served := false
					next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						served = true
						claims, ok := rs.ClaimsFromContext(r.Context())
						if !ok || claims == nil || claims.CnfJKT != key.thumbprint() || claims.TenantID != "tenant-1" || claims.JTI != "token-1" {
							t.Errorf("validated DPoP claims changed: %+v, ok=%v", claims, ok)
						}
						w.WriteHeader(http.StatusNoContent)
					})
					rec := revocationRequest(cfg, token, tc.scheme, tc.proof, context.Background(), next)
					if rec.Code != tc.status || served != (tc.status == http.StatusNoContent) {
						t.Errorf("%s: served=%v, status/body=%d/%q; want %d", tc.name, served, rec.Code, rec.Body.String(), tc.status)
					}
					if tc.status == http.StatusUnauthorized && (!strings.Contains(rec.Header().Get("WWW-Authenticate"), `error_description="invalid dpop proof"`) || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache") {
						t.Errorf("%s: DPoP failure headers changed: %v", tc.name, rec.Header())
					}
				}
				wantCalls := 0
				if enabled {
					wantCalls = len(cases) // The access token is valid even when its proof is not.
				}
				if calls != wantCalls {
					t.Errorf("callback calls=%d, want %d", calls, wantCalls)
				}
			})
		}
	}
}

func TestRevocationCheck_RevokedDPoP(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"local", "introspection"} {
		t.Run(mode, func(t *testing.T) {
			key := newDPoPKey(t)
			token, cfg := revocationFixture(t, mode, map[string]any{"cnf": map[string]any{"jkt": key.thumbprint()}})
			cfg.DPoPVerifier = rs.NewDPoPVerifier()
			cfg.RevocationCheck = func(context.Context, rs.RevocationToken) (bool, error) { return true, nil }
			proof := key.proof(t, testHTM, testHTU, token, time.Now().Unix(), "revoked-proof")
			served := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served = true })
			rec := revocationRequest(cfg, token, "DPoP", proof, context.Background(), next)
			if served || rec.Code != http.StatusUnauthorized || rec.Body.String() != `{"error":"invalid_token"}` {
				t.Errorf("revoked DPoP token: served=%v, status/body=%d/%q", served, rec.Code, rec.Body.String())
			}
			challenge := rec.Header().Get("WWW-Authenticate")
			if !strings.HasPrefix(challenge, "DPoP ") || !strings.Contains(challenge, `error_description="token validation failed"`) || !strings.Contains(challenge, "algs=") {
				t.Errorf("revoked DPoP challenge changed: %q", challenge)
			}
			if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
				t.Errorf("revoked DPoP response cache headers = %v", rec.Header())
			}
		})
	}
}
