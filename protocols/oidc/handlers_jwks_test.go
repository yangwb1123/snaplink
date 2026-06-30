package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
)

// jwksDeps is a real, no-mock JWKSDeps backed by genuine Ed25519/ECDSA
// issuers. ComputeJWKSDocument runs the closure inline (the single-flight
// collapse is exercised by the server-level tests; here we want the marshal
// path itself).
type jwksDeps struct {
	issuers   map[string]core.TokenIssuer
	decrypter security.JWEDecrypter
	maxAge    time.Duration
}

func (d *jwksDeps) TokenIssuers() map[string]core.TokenIssuer { return d.issuers }
func (d *jwksDeps) JARDecrypter() security.JWEDecrypter       { return d.decrypter }
func (d *jwksDeps) SrvLogger() spi.Logger                     { return spi.NopLogger{} }
func (d *jwksDeps) JWKSCacheMaxAge() time.Duration            { return d.maxAge }
func (d *jwksDeps) ComputeJWKSDocument(compute func() ([]byte, error)) ([]byte, error) {
	return compute()
}
func (d *jwksDeps) CachedJWKSETag() string { return "" }

// errorIssuer is a TokenIssuer + JWKSProvider whose JWKS() always fails, so
// the handler's "provider failed → log + skip" branch is exercised without
// faking the rest of the interface.
type errorIssuer struct{ core.TokenIssuer }

func (errorIssuer) JWKS(context.Context) ([]core.JWK, error) {
	return nil, errors.New("boom")
}

func decodeJWKS(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	return doc.Keys
}

func TestHandleJWKS_AggregatesIssuerKeys(t *testing.T) {
	t.Parallel()
	ed := defaultimpl.NewEd25519JWTIssuer()
	ec := defaultimpl.NewECDSAJWTIssuer()
	d := &jwksDeps{issuers: map[string]core.TokenIssuer{"jwt": ed, "es256": ec}}

	ctx, rec := newCtx(http.MethodGet, "/.well-known/jwks.json")
	oidc.HandleJWKS(d, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != core.ContentTypeJSON {
		t.Errorf("Content-Type = %q, want %q", ct, core.ContentTypeJSON)
	}
	if etag := rec.Header().Get("ETag"); etag == "" {
		t.Error("ETag must be set")
	}
	if cc := rec.Header().Get("Cache-Control"); cc == "" {
		t.Error("Cache-Control must be set")
	}
	keys := decodeJWKS(t, rec.Body.Bytes())
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2 (one per issuer)", len(keys))
	}
}

func TestHandleJWKS_SkipsNonJWKSProvider(t *testing.T) {
	t.Parallel()
	// A TokenIssuer that does NOT implement JWKSProvider must be silently
	// skipped, not crash the walk.
	d := &jwksDeps{issuers: map[string]core.TokenIssuer{
		"opaque": plainIssuer{},
		"jwt":    defaultimpl.NewEd25519JWTIssuer(),
	}}
	ctx, rec := newCtx(http.MethodGet, "/.well-known/jwks.json")
	oidc.HandleJWKS(d, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := len(decodeJWKS(t, rec.Body.Bytes())); got != 1 {
		t.Errorf("got %d keys, want 1 (opaque issuer has no JWKS)", got)
	}
}

func TestHandleJWKS_ProviderErrorIsSkipped(t *testing.T) {
	t.Parallel()
	d := &jwksDeps{issuers: map[string]core.TokenIssuer{
		"bad":  errorIssuer{},
		"good": defaultimpl.NewEd25519JWTIssuer(),
	}}
	ctx, rec := newCtx(http.MethodGet, "/.well-known/jwks.json")
	oidc.HandleJWKS(d, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (one bad provider must not 500)", rec.Code)
	}
	if got := len(decodeJWKS(t, rec.Body.Bytes())); got != 1 {
		t.Errorf("got %d keys, want 1 (bad provider skipped)", got)
	}
}

func TestHandleJWKS_DecrypterEncKeyPublished(t *testing.T) {
	t.Parallel()
	ed := defaultimpl.NewEd25519JWTIssuer()
	// The JAR decrypter that also implements JWKSProvider must contribute
	// its enc key alongside the issuer sig keys.
	dec := jwksDecrypter{key: core.JWK{Kty: "RSA", Use: "enc", Kid: "enc-1", N: "abc", E: "AQAB"}}
	d := &jwksDeps{issuers: map[string]core.TokenIssuer{"jwt": ed}, decrypter: dec}

	ctx, rec := newCtx(http.MethodGet, "/.well-known/jwks.json")
	oidc.HandleJWKS(d, ctx)

	keys := decodeJWKS(t, rec.Body.Bytes())
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2 (sig + enc)", len(keys))
	}
	var sawEnc bool
	for _, k := range keys {
		if k["use"] == "enc" {
			sawEnc = true
		}
	}
	if !sawEnc {
		t.Error("decrypter enc key not published in JWKS")
	}
}

func TestHandleJWKS_DecrypterWithoutJWKSProviderIgnored(t *testing.T) {
	t.Parallel()
	ed := defaultimpl.NewEd25519JWTIssuer()
	// A decrypter that does NOT implement JWKSProvider contributes nothing
	// and must not error.
	d := &jwksDeps{issuers: map[string]core.TokenIssuer{"jwt": ed}, decrypter: plainDecrypter{}}
	ctx, rec := newCtx(http.MethodGet, "/.well-known/jwks.json")
	oidc.HandleJWKS(d, ctx)

	if got := len(decodeJWKS(t, rec.Body.Bytes())); got != 1 {
		t.Errorf("got %d keys, want 1", got)
	}
}

func TestHandleJWKS_IfNoneMatch304(t *testing.T) {
	t.Parallel()
	ed := defaultimpl.NewEd25519JWTIssuer()
	d := &jwksDeps{issuers: map[string]core.TokenIssuer{"jwt": ed}}

	// First fetch to learn the ETag.
	ctx1, rec1 := newCtx(http.MethodGet, "/.well-known/jwks.json")
	oidc.HandleJWKS(d, ctx1)
	etag := rec1.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on first fetch")
	}

	// Conditional refetch with matching If-None-Match → 304 + empty body.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	req2.Header.Set("If-None-Match", etag)
	oidc.HandleJWKS(d, core.NewContext(rec2, req2))

	if rec2.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", rec2.Code)
	}
	if rec2.Body.Len() != 0 {
		t.Errorf("304 must have empty body, got %d bytes", rec2.Body.Len())
	}
}

func TestHandleJWKS_StaleETagServesBody(t *testing.T) {
	t.Parallel()
	ed := defaultimpl.NewEd25519JWTIssuer()
	d := &jwksDeps{issuers: map[string]core.TokenIssuer{"jwt": ed}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	req.Header.Set("If-None-Match", `"stale"`)
	oidc.HandleJWKS(d, core.NewContext(rec, req))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for non-matching ETag", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Error("non-matching ETag must serve the full body")
	}
}

func TestHandleJWKS_DefaultMaxAgeWhenUnset(t *testing.T) {
	t.Parallel()
	ed := defaultimpl.NewEd25519JWTIssuer()
	d := &jwksDeps{issuers: map[string]core.TokenIssuer{"jwt": ed}, maxAge: 0}
	ctx, rec := newCtx(http.MethodGet, "/.well-known/jwks.json")
	oidc.HandleJWKS(d, ctx)
	if cc := rec.Header().Get("Cache-Control"); cc == "" {
		t.Error("Cache-Control must fall back to the default max-age")
	}
}

func TestHandleJWKS_ComputeErrorReturns500(t *testing.T) {
	t.Parallel()
	d := &computeErrDeps{}
	ctx, rec := newCtx(http.MethodGet, "/.well-known/jwks.json")
	oidc.HandleJWKS(d, ctx)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 on compute error", rec.Code)
	}
}

// plainIssuer satisfies core.TokenIssuer but NOT core.JWKSProvider.
type plainIssuer struct{}

func (plainIssuer) Issue(context.Context, *core.Subject, []string) (*core.Token, error) {
	return &core.Token{}, nil
}
func (plainIssuer) Validate(context.Context, string) (*core.TokenClaims, error) {
	return &core.TokenClaims{}, nil
}
func (plainIssuer) Revoke(context.Context, string) error { return nil }

// jwksDecrypter is a JWEDecrypter that also publishes a JWK (JWKSProvider).
type jwksDecrypter struct{ key core.JWK }

func (j jwksDecrypter) Decrypt(context.Context, string) ([]byte, error) { return nil, nil }
func (j jwksDecrypter) SupportedAlgs() []string                         { return []string{"RSA-OAEP-256"} }
func (j jwksDecrypter) SupportedEncs() []string                         { return []string{"A256GCM"} }
func (j jwksDecrypter) JWKS(context.Context) ([]core.JWK, error)        { return []core.JWK{j.key}, nil }

// plainDecrypter is a JWEDecrypter that does NOT implement JWKSProvider.
type plainDecrypter struct{}

func (plainDecrypter) Decrypt(context.Context, string) ([]byte, error) { return nil, nil }
func (plainDecrypter) SupportedAlgs() []string                         { return []string{"RSA-OAEP-256"} }
func (plainDecrypter) SupportedEncs() []string                         { return []string{"A256GCM"} }

// computeErrDeps forces ComputeJWKSDocument to return an error so the
// handler's 500 path is exercised.
type computeErrDeps struct{ jwksDeps }

func (computeErrDeps) ComputeJWKSDocument(func() ([]byte, error)) ([]byte, error) {
	return nil, errors.New("single-flight failed")
}
