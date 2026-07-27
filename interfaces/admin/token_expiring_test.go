package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystoreoauth"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// expiringCtx builds a GET expiry-calendar HandlerContext with the given raw
// query string (e.g. "before=24h&limit=10").
func expiringCtx(rawQuery string) (core.HandlerContext, *httptest.ResponseRecorder) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/tokens/expiring?"+rawQuery, nil)
	w := httptest.NewRecorder()
	return core.NewContext(w, r), w
}

func decodeExpiring(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return out
}

// TestTokenExpiring_Success proves the 200 success shape: the real memory
// store (implements RefreshTokenExpiryLister) returns tokens expiring within
// the requested horizon, soonest-first, thumbprint only.
func TestTokenExpiring_Success(t *testing.T) {
	s := memorystoreoauth.NewMemoryRefreshTokenStore()
	ctx := context.Background()
	seed := func(tok, user string, in time.Duration) {
		if err := s.Issue(ctx, tok, &oauth.RefreshToken{
			UserID: user, ClientID: "c1", ExpiresAt: time.Now().Add(in),
		}); err != nil {
			t.Fatalf("seed Issue: %v", err)
		}
	}
	seed("soon", "u1", time.Minute)
	seed("later", "u2", 12*time.Hour)
	seed("far", "u3", 30*24*time.Hour) // outside the default 24h horizon

	hctx, w := expiringCtx("") // default 24h horizon, default limit
	HandleTokenExpiring(s, testLogger{}, hctx)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	out := decodeExpiring(t, w)
	if out["count"] != float64(2) {
		t.Fatalf("count = %v, want 2 (soon, later); body=%s", out["count"], w.Body.String())
	}
	tokens, ok := out["tokens"].([]any)
	if !ok || len(tokens) != 2 {
		t.Fatalf("tokens = %v, want 2 entries", out["tokens"])
	}
	first := tokens[0].(map[string]any)
	if first["subject"] != "u1" {
		t.Errorf("first entry subject = %v, want u1 (soonest-first)", first["subject"])
	}
	if _, hasTok := first["token"]; hasTok {
		t.Errorf("response leaked a raw 'token' field: %+v", first)
	}
	if tp, _ := first["token_thumbprint"].(string); tp == "" || tp == "soon" {
		t.Errorf("token_thumbprint = %q, want a non-empty hash, never the raw token", tp)
	}
}

// TestTokenExpiring_Limit proves ?limit= is honored and clamps the result.
func TestTokenExpiring_Limit(t *testing.T) {
	s := memorystoreoauth.NewMemoryRefreshTokenStore()
	ctx := context.Background()
	for i, tok := range []string{"t1", "t2", "t3"} {
		if err := s.Issue(ctx, tok, &oauth.RefreshToken{
			UserID: tok, ClientID: "c1",
			ExpiresAt: time.Now().Add(time.Duration(i+1) * time.Minute),
		}); err != nil {
			t.Fatalf("seed Issue: %v", err)
		}
	}
	hctx, w := expiringCtx("before=1h&limit=2")
	HandleTokenExpiring(s, testLogger{}, hctx)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	out := decodeExpiring(t, w)
	if out["count"] != float64(2) {
		t.Fatalf("count = %v, want 2 (limit applied)", out["count"])
	}
}

// TestTokenExpiring_InvalidBefore proves a malformed ?before= is a 400, not a
// silent fallback or a panic.
func TestTokenExpiring_InvalidBefore(t *testing.T) {
	s := memorystoreoauth.NewMemoryRefreshTokenStore()
	hctx, w := expiringCtx("before=not-a-time")
	HandleTokenExpiring(s, testLogger{}, hctx)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
	if got := decodeExpiring(t, w)["error"]; got != core.ErrInvalidRequest {
		t.Fatalf("error = %v, want %s", got, core.ErrInvalidRequest)
	}
}

// unsupportedRefreshStore is a bare oauth.RefreshTokenStore that implements
// NONE of the optional extensions — a real (if minimal) store, not a mock,
// used to exercise the "backend doesn't support this" degrade path.
type unsupportedRefreshStore struct{}

func (unsupportedRefreshStore) Issue(context.Context, string, *oauth.RefreshToken) error {
	return nil
}
func (unsupportedRefreshStore) Consume(context.Context, string) (*oauth.RefreshToken, error) {
	return nil, oauth.ErrRefreshTokenNotFound
}

var _ oauth.RefreshTokenStore = unsupportedRefreshStore{}

// TestTokenExpiring_UnsupportedBackend proves a wired store that doesn't
// implement RefreshTokenExpiryLister answers 501 with the SAME error code
// HandleBulkRevoke's unsupported-backend path uses.
func TestTokenExpiring_UnsupportedBackend(t *testing.T) {
	hctx, w := expiringCtx("")
	HandleTokenExpiring(unsupportedRefreshStore{}, testLogger{}, hctx)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501: %s", w.Code, w.Body.String())
	}
	if got := decodeExpiring(t, w)["error"]; got != core.ErrRefreshTokenNotConfigured {
		t.Fatalf("error = %v, want %s", got, core.ErrRefreshTokenNotConfigured)
	}
}

// TestTokenExpiring_NilStore: no refresh store wired => 501, never a panic.
func TestTokenExpiring_NilStore(t *testing.T) {
	hctx, w := expiringCtx("")
	HandleTokenExpiring(nil, testLogger{}, hctx)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501: %s", w.Code, w.Body.String())
	}
}

// scopeCheckAuthorizer grants ONLY the exact scope listed in allowed — a
// hand-written stub (not a mock: no call-count/argument assertions), the
// same shape as allowAllAuthorizer in middleware_test.go.
type scopeCheckAuthorizer struct{ allowed string }

func (a scopeCheckAuthorizer) HasAdminScope(_ context.Context, _, _, requiredScope string) (bool, error) {
	return requiredScope == a.allowed, nil
}

// TestTokenExpiring_ScopeGating proves GET /api/v1/admin/tokens/expiring is
// gated through the REAL AdminMiddleware exactly like every sibling
// /api/v1/admin/tokens/* route: no bearer -> 401, a bearer lacking admin:read
// -> 403, admin:read -> 200. The endpoint itself never checks scope — the
// middleware wrapping it does, via the default GET=admin:read method-scope
// rule (no per-path override registered for this route, matching
// HandleSubjectTokens / HandleAdminPortfolio).
func TestTokenExpiring_ScopeGating(t *testing.T) {
	s := memorystoreoauth.NewMemoryRefreshTokenStore()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/tokens/expiring", func(w http.ResponseWriter, r *http.Request) {
		HandleTokenExpiring(s, testLogger{}, core.NewContext(w, r))
	})

	newMW := func(allowedScope string) *Middleware {
		return &Middleware{
			validator:    fakeValidator{claims: &core.TokenClaims{Subject: "admin-1"}},
			authorizer:   scopeCheckAuthorizer{allowed: allowedScope},
			methodScopes: defaultMethodScopes(),
		}
	}
	get := func(mw *Middleware, withBearer bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/tokens/expiring", nil)
		if withBearer {
			r.Header.Set("Authorization", "Bearer tok")
		}
		w := httptest.NewRecorder()
		mw.HTTPMiddleware(mux).ServeHTTP(w, r)
		return w
	}

	if w := get(newMW(ScopeRead), false); w.Code != http.StatusUnauthorized {
		t.Fatalf("no bearer: status = %d, want 401", w.Code)
	}
	if w := get(newMW(ScopeWrite), true); w.Code != http.StatusForbidden {
		t.Fatalf("bearer without admin:read: status = %d, want 403", w.Code)
	}
	if w := get(newMW(ScopeRead), true); w.Code != http.StatusOK {
		t.Fatalf("bearer with admin:read: status = %d, want 200: %s", w.Code, w.Body.String())
	}
}
