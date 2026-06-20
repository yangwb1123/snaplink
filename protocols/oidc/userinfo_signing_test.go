package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
)

// userinfoDeps is a no-mock UserinfoSigningDeps. The issuer is a real
// Ed25519JWTIssuer (which implements UserinfoSigner); the client store is the
// real MemoryClientStore. The per-tenant selector behavior is configurable so
// the fail-closed branches (emit=false / resolution error) are reachable.
type userinfoDeps struct {
	issuer      oidc.IDTokenIssuer
	clients     core.ClientStore
	algs        []string
	encrypter   security.JWEEncrypter
	selectorErr error
	selectorOK  bool // emit value returned by IDTokenIssuerForClient
}

func (d *userinfoDeps) IDTokenIssuer() oidc.IDTokenIssuer { return d.issuer }
func (d *userinfoDeps) IDTokenIssuerForClient(*core.Client) (oidc.IDTokenIssuer, bool, error) {
	if d.selectorErr != nil {
		return nil, false, d.selectorErr
	}
	return d.issuer, d.selectorOK, nil
}
func (d *userinfoDeps) ClientStoreAccessor() core.ClientStore       { return d.clients }
func (d *userinfoDeps) SrvLogger() spi.Logger                       { return spi.NopLogger{} }
func (d *userinfoDeps) SigningAlgValues(context.Context) []string   { return d.algs }
func (d *userinfoDeps) JWEResponseEncrypter() security.JWEEncrypter { return d.encrypter }

func mustSeedClient(t *testing.T, store *defaultimpl.MemoryClientStore, c *core.Client) {
	t.Helper()
	if err := store.Add(context.Background(), c); err != nil {
		t.Fatalf("seed client: %v", err)
	}
}

func newSignDeps(t *testing.T) (*userinfoDeps, *core.Client) {
	t.Helper()
	store := defaultimpl.NewMemoryClientStore()
	c := &core.Client{ID: "rp-1", UserinfoSignedResponseAlg: oidc.UserinfoSignedAlgEdDSA}
	mustSeedClient(t, store, c)
	return &userinfoDeps{
		issuer:     defaultimpl.NewEd25519JWTIssuer(),
		clients:    store,
		algs:       []string{"EdDSA"},
		selectorOK: true,
	}, c
}

func TestMaybeSignUserInfo_SignedJWT(t *testing.T) {
	d, _ := newSignDeps(t)
	ctx, rec := newCtx(http.MethodGet, "/userinfo")
	handled := oidc.MaybeSignUserInfo(d, ctx, "rp-1", map[string]any{"sub": "user-1", "email": "a@b.c"})

	if !handled {
		t.Fatal("MaybeSignUserInfo returned false for a sign-configured client")
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/jwt" {
		t.Errorf("Content-Type = %q, want application/jwt", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if n := strings.Count(rec.Body.String(), "."); n != 2 {
		t.Errorf("body is not a compact JWS (dots=%d): %q", n, rec.Body.String())
	}
}

func TestMaybeSignUserInfo_NoClientStore(t *testing.T) {
	d := &userinfoDeps{issuer: defaultimpl.NewEd25519JWTIssuer(), clients: nil, selectorOK: true}
	ctx, _ := newCtx(http.MethodGet, "/userinfo")
	if oidc.MaybeSignUserInfo(d, ctx, "rp-1", map[string]any{"sub": "u"}) {
		t.Error("must fall through (return false) when no client store wired")
	}
}

func TestMaybeSignUserInfo_EmptyClientID(t *testing.T) {
	d, _ := newSignDeps(t)
	ctx, _ := newCtx(http.MethodGet, "/userinfo")
	if oidc.MaybeSignUserInfo(d, ctx, "", map[string]any{"sub": "u"}) {
		t.Error("must fall through on empty client id")
	}
}

func TestMaybeSignUserInfo_UnknownClient(t *testing.T) {
	d, _ := newSignDeps(t)
	ctx, _ := newCtx(http.MethodGet, "/userinfo")
	if oidc.MaybeSignUserInfo(d, ctx, "does-not-exist", map[string]any{"sub": "u"}) {
		t.Error("must fall through for an unknown client")
	}
}

func TestMaybeSignUserInfo_NoSignNoEncryptFallsThrough(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	mustSeedClient(t, store, &core.Client{ID: "plain"})
	d := &userinfoDeps{issuer: defaultimpl.NewEd25519JWTIssuer(), clients: store, algs: []string{"EdDSA"}, selectorOK: true}
	ctx, _ := newCtx(http.MethodGet, "/userinfo")
	if oidc.MaybeSignUserInfo(d, ctx, "plain", map[string]any{"sub": "u"}) {
		t.Error("client that opted into neither sign nor encrypt must fall through to JSON")
	}
}

func TestMaybeSignUserInfo_UnsupportedAlgFallsThrough(t *testing.T) {
	d, _ := newSignDeps(t)
	store := d.clients.(*defaultimpl.MemoryClientStore)
	// The resolved signer is Ed25519 (Alg "EdDSA"). A client that registered a
	// DIFFERENT alg the signer cannot produce must fall through to JSON rather
	// than mis-signing with EdDSA — even though the server's advertised set
	// happens to include ES256 (the signer, not the set, is authoritative).
	d.algs = []string{"EdDSA", "ES256"}
	mustSeedClient(t, store, &core.Client{ID: "rp-es256", UserinfoSignedResponseAlg: "ES256"})
	ctx, _ := newCtx(http.MethodGet, "/userinfo")
	if oidc.MaybeSignUserInfo(d, ctx, "rp-es256", map[string]any{"sub": "u"}) {
		t.Error("signer cannot produce the client's requested alg; must fall through to JSON")
	}
}

// noAlgSigner is a third-party UserinfoSigner/IDTokenIssuer that does NOT report
// its alg (no Alg() method — it holds the real issuer as a field rather than
// embedding it, so Alg() is not promoted). It exercises the fallback branch of
// userinfoSignerProducesAlg: the server's advertised SigningAlgValues set.
type noAlgSigner struct{ inner oidc.IDTokenIssuer }

func (s noAlgSigner) IssueIDToken(ctx context.Context, req *oidc.IDTokenRequest) (string, error) {
	return s.inner.IssueIDToken(ctx, req)
}

func (s noAlgSigner) SignUserInfo(ctx context.Context, audience string, claims map[string]any) (string, error) {
	return s.inner.(oidc.UserinfoSigner).SignUserInfo(ctx, audience, claims)
}

func TestMaybeSignUserInfo_NoAlgSignerFallsBackToServerSet(t *testing.T) {
	d, _ := newSignDeps(t)
	d.issuer = noAlgSigner{inner: defaultimpl.NewEd25519JWTIssuer()}

	// In the set → signs (fallback admits it). rp-1 requests EdDSA, set has EdDSA.
	d.algs = []string{"EdDSA"}
	ctx, _ := newCtx(http.MethodGet, "/userinfo")
	if !oidc.MaybeSignUserInfo(d, ctx, "rp-1", map[string]any{"sub": "u"}) {
		t.Error("no-Alg signer with requested alg in the server set must sign")
	}

	// Not in the set → falls through to JSON.
	d.algs = []string{"ES256"}
	ctx2, _ := newCtx(http.MethodGet, "/userinfo")
	if oidc.MaybeSignUserInfo(d, ctx2, "rp-1", map[string]any{"sub": "u"}) {
		t.Error("no-Alg signer with requested alg outside the server set must fall through to JSON")
	}
}

func TestMaybeSignUserInfo_SelectorErrorFallsThrough(t *testing.T) {
	d, _ := newSignDeps(t)
	// A misconfigured tenant issuer (resolution error) is fail-closed by
	// omission: no signer → fall through (sign-only, no encryption).
	d.selectorErr = errors.New("tenant misconfig")
	ctx, _ := newCtx(http.MethodGet, "/userinfo")
	if oidc.MaybeSignUserInfo(d, ctx, "rp-1", map[string]any{"sub": "u"}) {
		t.Error("selector error with sign-only client must fall through to JSON")
	}
}

func TestMaybeSignUserInfo_EmitFalseFallsThrough(t *testing.T) {
	d, _ := newSignDeps(t)
	// emit=false means the tenant strategy can't sign here → omit (fall
	// through), never reach for the shared key.
	d.selectorOK = false
	ctx, _ := newCtx(http.MethodGet, "/userinfo")
	if oidc.MaybeSignUserInfo(d, ctx, "rp-1", map[string]any{"sub": "u"}) {
		t.Error("emit=false sign-only client must fall through to JSON")
	}
}

func TestMaybeSignUserInfo_EncryptRequestedNoEncrypter(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	mustSeedClient(t, store, &core.Client{ID: "enc-rp", UserinfoEncryptedResponseAlg: "RSA-OAEP-256"})
	d := &userinfoDeps{issuer: defaultimpl.NewEd25519JWTIssuer(), clients: store, algs: []string{"EdDSA"}, selectorOK: true, encrypter: nil}
	ctx, rec := newCtx(http.MethodGet, "/userinfo")

	if !oidc.MaybeSignUserInfo(d, ctx, "enc-rp", map[string]any{"sub": "u"}) {
		t.Fatal("opted-in-to-encryption client must be handled (fail closed), not fall through")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (no encrypter wired → server_error)", rec.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body[core.KeyError] != oidc.ErrUserinfoServerError {
		t.Errorf("error = %q, want %q", body[core.KeyError], oidc.ErrUserinfoServerError)
	}
}

func TestMaybeSignUserInfo_EncryptOnlyJSON(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	encJWK := rsaEncJWK(t)
	mustSeedClient(t, store, &core.Client{
		ID:                           "enc-rp",
		UserinfoEncryptedResponseAlg: "RSA-OAEP-256",
		JWKS:                         []core.JWK{encJWK},
	})
	d := &userinfoDeps{
		issuer:     defaultimpl.NewEd25519JWTIssuer(),
		clients:    store,
		algs:       []string{"EdDSA"},
		selectorOK: true,
		encrypter:  defaultimpl.NewRSAJWEResponseEncrypter(),
	}
	ctx, rec := newCtx(http.MethodGet, "/userinfo")
	if !oidc.MaybeSignUserInfo(d, ctx, "enc-rp", map[string]any{"sub": "u"}) {
		t.Fatal("encrypt-only client must be handled")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/jwt" {
		t.Errorf("Content-Type = %q, want application/jwt", ct)
	}
	// A JWE compact serialization has 5 dot-separated segments.
	if n := strings.Count(rec.Body.String(), "."); n != 4 {
		t.Errorf("body is not a compact JWE (dots=%d)", n)
	}
}

func TestMaybeSignUserInfo_SignThenEncrypt(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	encJWK := rsaEncJWK(t)
	mustSeedClient(t, store, &core.Client{
		ID:                           "rp-both",
		UserinfoSignedResponseAlg:    oidc.UserinfoSignedAlgEdDSA,
		UserinfoEncryptedResponseAlg: "RSA-OAEP-256",
		JWKS:                         []core.JWK{encJWK},
	})
	d := &userinfoDeps{
		issuer:     defaultimpl.NewEd25519JWTIssuer(),
		clients:    store,
		algs:       []string{"EdDSA"},
		selectorOK: true,
		encrypter:  defaultimpl.NewRSAJWEResponseEncrypter(),
	}
	ctx, rec := newCtx(http.MethodGet, "/userinfo")
	if !oidc.MaybeSignUserInfo(d, ctx, "rp-both", map[string]any{"sub": "u"}) {
		t.Fatal("sign+encrypt client must be handled")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// Nested JWS-in-JWE is still a 5-segment compact JWE on the wire.
	if n := strings.Count(rec.Body.String(), "."); n != 4 {
		t.Errorf("body is not a compact JWE (dots=%d)", n)
	}
}

func TestMaybeSignUserInfo_EncryptFailureServerError(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	// Encrypter is wired but the client JWKS has no usable enc key → the
	// undifferentiated server_error path fires (never falls back to
	// cleartext).
	mustSeedClient(t, store, &core.Client{
		ID:                           "enc-rp",
		UserinfoEncryptedResponseAlg: "RSA-OAEP-256",
		JWKS:                         nil,
	})
	d := &userinfoDeps{
		issuer:     defaultimpl.NewEd25519JWTIssuer(),
		clients:    store,
		algs:       []string{"EdDSA"},
		selectorOK: true,
		encrypter:  defaultimpl.NewRSAJWEResponseEncrypter(),
	}
	ctx, rec := newCtx(http.MethodGet, "/userinfo")
	if !oidc.MaybeSignUserInfo(d, ctx, "enc-rp", map[string]any{"sub": "u"}) {
		t.Fatal("must be handled (fail closed)")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 on encrypt failure", rec.Code)
	}
}

// rsaEncJWK generates a fresh 2048-bit RSA key and returns its public half as
// a `use:enc` JWK the response encrypter accepts.
func rsaEncJWK(t *testing.T) core.JWK {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	pub := &key.PublicKey
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	return core.JWK{
		Kty: "RSA",
		Use: "enc",
		Alg: "RSA-OAEP-256",
		Kid: "enc-test",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}
