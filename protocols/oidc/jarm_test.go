package oidc_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
)

// fakeSigner is a deterministic JARMSigner that JSON-encodes the claims
// into the JWT payload (header.payload.sig) so tests can inspect them
// without a real Ed25519 key. errOnSign forces SignMetadata to fail.
type fakeSigner struct{ errOnSign bool }

func (f *fakeSigner) SignMetadata(_ context.Context, claims map[string]any) (string, error) {
	if f.errOnSign {
		return "", errors.New("sign failed")
	}
	payload, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString(payload)
	return "eyJhbGciOiJFZERTQSJ9." + enc + ".sig", nil
}

func decodeJARMClaims(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt has %d parts, want 3: %q", len(parts), jwt)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims
}

func TestSignJARMResponse_Claims(t *testing.T) {
	t.Parallel()
	jwt, err := oidc.SignJARMResponse(context.Background(), &fakeSigner{}, "https://as.example", "client-1", "the-code", "the-state")
	if err != nil {
		t.Fatalf("SignJARMResponse: %v", err)
	}
	claims := decodeJARMClaims(t, jwt)
	if claims["iss"] != "https://as.example" {
		t.Errorf("iss = %v", claims["iss"])
	}
	if claims["aud"] != "client-1" {
		t.Errorf("aud = %v", claims["aud"])
	}
	if claims["code"] != "the-code" {
		t.Errorf("code = %v", claims["code"])
	}
	if claims["state"] != "the-state" {
		t.Errorf("state = %v", claims["state"])
	}
	if _, ok := claims["exp"]; !ok {
		t.Error("exp claim missing")
	}
}

func TestSignJARMResponse_OmitsEmptyState(t *testing.T) {
	t.Parallel()
	jwt, _ := oidc.SignJARMResponse(context.Background(), &fakeSigner{}, "iss", "c", "code", "")
	if _, ok := decodeJARMClaims(t, jwt)["state"]; ok {
		t.Error("empty state must be omitted")
	}
}

func newCtx(method, target string) (*core.Context, *httptest.ResponseRecorder) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, target, nil)
	return core.NewContext(rec, req), rec
}

func TestRenderJARMResponse_QueryDelivery(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{oidc.ResponseModeJWT, oidc.ResponseModeQueryJWT} {
		ctx, rec := newCtx(http.MethodGet, "/auth/login")
		ok := oidc.RenderJARMResponse(ctx, &fakeSigner{}, mode, "https://rp.example/cb?x=1", "iss", "c", "code", "st")
		if !ok {
			t.Fatalf("mode=%s: RenderJARMResponse returned false", mode)
		}
		if rec.Code != http.StatusFound {
			t.Errorf("mode=%s: status = %d, want 302", mode, rec.Code)
		}
		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if loc.Query().Get("response") == "" {
			t.Errorf("mode=%s: response param missing in query: %q", mode, rec.Header().Get("Location"))
		}
		if loc.Query().Get("x") != "1" {
			t.Errorf("mode=%s: existing query param lost", mode)
		}
	}
}

func TestRenderJARMResponse_FragmentDelivery(t *testing.T) {
	t.Parallel()
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	oidc.RenderJARMResponse(ctx, &fakeSigner{}, oidc.ResponseModeFragmentJWT, "https://rp.example/cb", "iss", "c", "code", "")
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "#response=") {
		t.Errorf("fragment delivery must carry #response=, got %q", loc)
	}
}

func TestRenderJARMResponse_FormPostDelivery(t *testing.T) {
	t.Parallel()
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	oidc.RenderJARMResponse(ctx, &fakeSigner{}, oidc.ResponseModeFormPostJWT, "https://rp.example/cb", "iss", "c", "code", "")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `name="response"`) {
		t.Errorf("form_post body missing response field: %q", body)
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("form_post must set X-Frame-Options: DENY")
	}
	if strings.Contains(body, "onload=") {
		t.Errorf("inline onload attribute survives — breaks under a strict CSP script-src:\n%s", body)
	}
}

func TestRenderJARMResponse_FormPostStampsCSPNonce(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	req = req.WithContext(core.WithCSPNonce(req.Context(), "jarm-nonce-456"))
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, req)
	oidc.RenderJARMResponse(ctx, &fakeSigner{}, oidc.ResponseModeFormPostJWT, "https://rp.example/cb", "iss", "c", "code", "")
	body := rec.Body.String()
	if !strings.Contains(body, `<script nonce="jarm-nonce-456">document.forms[0].submit()</script>`) {
		t.Errorf("script tag missing the per-request CSP nonce:\n%s", body)
	}
}

func TestRenderJARMResponse_SignFailureReturnsFalse(t *testing.T) {
	t.Parallel()
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	if oidc.RenderJARMResponse(ctx, &fakeSigner{errOnSign: true}, oidc.ResponseModeJWT, "https://rp.example/cb", "iss", "c", "code", "") {
		t.Error("RenderJARMResponse must return false on sign failure")
	}
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("on sign failure nothing must be written (code=%d, bodylen=%d)", rec.Code, rec.Body.Len())
	}
}

func TestIsJARMResponseMode(t *testing.T) {
	t.Parallel()
	for _, m := range []string{"jwt", "query.jwt", "fragment.jwt", "form_post.jwt"} {
		if !oidc.IsJARMResponseMode(m) {
			t.Errorf("%q should be a JARM mode", m)
		}
	}
	for _, m := range []string{"query", "fragment", "form_post", "", "jwt.extra"} {
		if oidc.IsJARMResponseMode(m) {
			t.Errorf("%q should not be a JARM mode", m)
		}
	}
}
