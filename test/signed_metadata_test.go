package ssotest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

func newSignedMetadataHarness(t *testing.T) (*httptest.Server, *defaultimpl.Ed25519JWTIssuer) {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "sm-c", Active: true, TokenStrategy: "jwt"})
	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("https://sm.example"),
		defaultimpl.WithEd25519TokenTTL(time.Minute),
	)
	srv := sso.NewServer(
		sso.WithIssuer("https://sm.example"),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithMetadataSigner(issuer),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, issuer
}

func fetchSignedDiscovery(t *testing.T, srv *httptest.Server) map[string]any {
	t.Helper()
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return doc
}

func TestSignedMetadata_EmittedWhenSignerWired(t *testing.T) {
	srv, _ := newSignedMetadataHarness(t)
	doc := fetchSignedDiscovery(t, srv)
	jws, _ := doc["signed_metadata"].(string)
	if jws == "" {
		t.Fatal("signed_metadata missing from discovery doc")
	}
	if strings.Count(jws, ".") != 2 {
		t.Errorf("signed_metadata = %q want 3-part JWS", jws)
	}
}

func TestSignedMetadata_AbsentWhenNoSigner(t *testing.T) {
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "sm-c2", Active: true, TokenStrategy: "jwt"})
	srv := sso.NewServer(
		sso.WithIssuer("https://sm.example"),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	doc := fetchSignedDiscovery(t, httpSrv)
	if _, present := doc["signed_metadata"]; present {
		t.Errorf("signed_metadata leaked into response without WithMetadataSigner")
	}
}

func TestSignedMetadata_SignatureVerifiesAndClaimsMatch(t *testing.T) {
	srv, issuer := newSignedMetadataHarness(t)
	doc := fetchSignedDiscovery(t, srv)
	jws, _ := doc["signed_metadata"].(string)
	if jws == "" {
		t.Fatal("no signed_metadata")
	}

	// Verify signature against JWKS.
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed JWS: %d parts", len(parts))
	}
	jwks, _ := issuer.JWKS(t.Context())
	if len(jwks) == 0 {
		t.Fatal("issuer JWKS empty")
	}
	pubBytes, _ := base64.RawURLEncoding.DecodeString(jwks[0].X)
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("signed_metadata signature failed JWKS verification")
	}

	// Decode payload and compare key fields against the plaintext.
	payloadRaw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]any
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		t.Fatalf("payload parse: %v", err)
	}
	if payload["issuer"] != doc["issuer"] {
		t.Errorf("issuer mismatch: signed=%v plaintext=%v", payload["issuer"], doc["issuer"])
	}
	if payload["token_endpoint"] != doc["token_endpoint"] {
		t.Errorf("token_endpoint mismatch: signed=%v plaintext=%v", payload["token_endpoint"], doc["token_endpoint"])
	}
	// signed_metadata itself MUST NOT recurse — the signed payload
	// must exclude it (RFC 8414 §2.1).
	if _, recurses := payload["signed_metadata"]; recurses {
		t.Error("signed payload recursively contains signed_metadata — verification on RP would loop")
	}
}
