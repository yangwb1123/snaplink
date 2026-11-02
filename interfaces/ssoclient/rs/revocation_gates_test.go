package rs_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
)

func assertRevocationNotCalled(t *testing.T, token string, cfg rs.Config, want error) {
	t.Helper()
	calls := 0
	cfg.RevocationCheck = func(context.Context, rs.RevocationToken) (bool, error) {
		calls++
		return true, nil
	}
	claims, err := validateRevocationFixture(context.Background(), token, cfg)
	if claims != nil || !errors.Is(err, want) {
		t.Errorf("claims present=%v, err=%v; want nil/%v", claims != nil, err, want)
	}
	if calls != 0 {
		t.Errorf("callback invoked %d times before existing validation rejected token", calls)
	}
}

func tamperRevocationHeader(t *testing.T, token, name string, value any) string {
	t.Helper()
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatal(err)
	}
	if value == nil {
		delete(header, name)
	} else {
		header[name] = value
	}
	raw, err = json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	parts[0] = base64.RawURLEncoding.EncodeToString(raw)
	return strings.Join(parts, ".")
}

func TestRevocationCheck_SignedWrongType(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	token, err := iss.JWT.SignJWT(context.Background(), "JWT", map[string]any{
		"iss": iss.URL(), "aud": "api://orders", "jti": "token-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := newTestConfig(t, iss, "api://orders")
	assertRevocationNotCalled(t, token, cfg, rs.ErrTokenTypeMismatch)
}

func TestRevocationCheck_LocalCryptographicGates(t *testing.T) {
	t.Parallel()
	token, cfg := revocationFixture(t, "local", nil)
	parts := strings.Split(token, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 1
	badSignature := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(signature)
	cases := []struct {
		name  string
		token string
		algs  []string
		want  error
	}{
		{name: "malformed", token: "not-a-token", want: rs.ErrTokenMalformed},
		{name: "bad_signature", token: badSignature, want: rs.ErrSignatureInvalid},
		{name: "wrong_typ", token: tamperRevocationHeader(t, token, "typ", "JWT"), want: rs.ErrTokenTypeMismatch},
		{name: "missing_typ", token: tamperRevocationHeader(t, token, "typ", nil), want: rs.ErrTokenTypeMismatch},
		{name: "alg_none", token: tamperRevocationHeader(t, token, "alg", "none"), want: rs.ErrSignatureInvalid},
		{name: "alg_symmetric", token: tamperRevocationHeader(t, token, "alg", "HS256"), want: rs.ErrSignatureInvalid},
		{name: "alg_mismatch", token: tamperRevocationHeader(t, token, "alg", "RS256"), want: rs.ErrSignatureInvalid},
		{name: "alg_not_allowed", token: token, algs: []string{"ES256"}, want: rs.ErrSignatureInvalid},
		{name: "unknown_kid", token: tamperRevocationHeader(t, token, "kid", "unpublished-key"), want: rs.ErrSignatureInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := cfg
			c.AllowedAlgs = tc.algs
			assertRevocationNotCalled(t, tc.token, c, tc.want)
		})
	}
}

func TestRevocationCheck_LocalClaimGates(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		claim string
		value any
		want  error
	}{
		{"issuer", "iss", "https://wrong-issuer.test", rs.ErrIssuerMismatch},
		{"missing_issuer", "iss", "", rs.ErrIssuerMismatch},
		{"audience", "aud", "api://billing", rs.ErrAudienceMismatch},
		{"missing_audience", "aud", nil, rs.ErrAudienceMismatch},
		{"expired", "exp", time.Now().Add(-time.Hour).Unix(), rs.ErrTokenExpired},
		{"missing_expiry", "exp", 0, rs.ErrTokenMalformed},
		{"future_nbf", "nbf", time.Now().Add(time.Hour).Unix(), rs.ErrTokenNotYetValid},
		{"future_iat", "iat", time.Now().Add(time.Hour).Unix(), rs.ErrTokenNotYetValid},
		{"region", "serving_region", "us-east-1", rs.ErrServingRegionMismatch},
		{"missing_region", "serving_region", nil, rs.ErrServingRegionMismatch},
		{"malformed_claim", "jti", 123, rs.ErrTokenMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, cfg := revocationFixture(t, "local", map[string]any{tc.claim: tc.value})
			assertRevocationNotCalled(t, token, cfg, tc.want)
		})
	}
}

// Remote mode trusts the introspection endpoint for crypto/typ/alg and retains
// its existing optional issuer/expiry policy; only its existing gates run here.
func TestRevocationCheck_IntrospectionClaimGates(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		claim string
		value any
		want  error
	}{
		{"inactive", "active", false, rs.ErrTokenInactive},
		{"issuer", "iss", "https://wrong-issuer.test", rs.ErrIssuerMismatch},
		{"audience", "aud", "api://billing", rs.ErrAudienceMismatch},
		{"missing_audience", "aud", nil, rs.ErrAudienceMismatch},
		{"expired", "exp", time.Now().Add(-time.Hour).Unix(), rs.ErrTokenExpired},
		{"region", "serving_region", "us-east-1", rs.ErrServingRegionMismatch},
		{"missing_region", "serving_region", nil, rs.ErrServingRegionMismatch},
		{"malformed_claim", "jti", 123, rs.ErrIntrospection},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, cfg := revocationFixture(t, "introspection", map[string]any{tc.claim: tc.value})
			assertRevocationNotCalled(t, token, cfg, tc.want)
		})
	}
	t.Run("invalid_credentials", func(t *testing.T) {
		token, cfg := revocationFixture(t, "introspection", nil)
		cfg.IntrospectCreds = &rs.ClientCreds{ID: "wrong", Secret: "wrong"}
		assertRevocationNotCalled(t, token, cfg, rs.ErrIntrospection)
	})
}

func TestRevocationCheck_IntrospectionTransportGates(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		status int
		body   string
		close  bool
	}{
		{name: "non_200", status: http.StatusServiceUnavailable, body: `{"active":true,"jti":"token-1"}`},
		{name: "invalid_json", status: http.StatusOK, body: "not-json"},
		{name: "transport_failure", close: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)
			if tc.close {
				srv.Close()
			}
			cfg := rs.Config{Issuer: "https://as.test", IntrospectURL: srv.URL}
			assertRevocationNotCalled(t, "opaque-token", cfg, rs.ErrIntrospection)
		})
	}
}
