package ssotest

// RFC 9101 §6.4 encrypted JAR. Exercises:
//   - JWE-wrapped JAR JWT is decrypted, the inner JWS is then validated
//     by the existing JAR pipeline → /auth/login proceeds as if the
//     payload had arrived plaintext
//   - JWE-wrapped JAR with NO WithJARDecrypter wired surfaces as
//     invalid_request_object (fail-closed — can't validate what we
//     can't decrypt)
//   - /.well-known/openid-configuration advertises
//     request_object_encryption_alg/enc lists when the decrypter is wired
//   - /.well-known/jwks.json includes the RSA public encryption key
//     with use:"enc" so RPs know which kid to encrypt to

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	jweClient   = "jwe-client"
	jweUser     = "u-jwe"
	jwePassword = "pw"
	jweSigKid   = "jwe-sig-1"
	jweEncKid   = "jwe-enc-1"
	jweASIssuer = "https://sso-jwe.test"
)

type jweHarness struct {
	srv     *httptest.Server
	signKey ed25519.PrivateKey
	encKey  *rsa.PrivateKey
}

// newJWEHarness mirrors newJARHarness with the addition of an RSA
// keypair for the AS's JWE decryption. The decrypter is wired so
// JWE-shaped JAR payloads are accepted; the unencrypted JAR signing
// keys stay on the client side as in the standard JAR pattern.
//
// withDecrypter controls whether the decrypter is plugged in — the
// "no-decrypter" negative test reuses the same harness without it
// so we get an apples-to-apples comparison.
func newJWEHarness(t *testing.T, withDecrypter bool) *jweHarness {
	t.Helper()

	sigPub, sigPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	encPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: jweUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    jweClient,
		Active:                true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{"https://app.example.com/cb"},
		JWKS: []sso.JWK{{
			Kty: "OKP", Crv: "Ed25519",
			Kid: jweSigKid,
			Alg: "EdDSA",
			Use: "sig",
			X:   base64.RawURLEncoding.EncodeToString(sigPub),
		}},
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == jweUser && p == jwePassword {
				return &sso.AuthResult{UserID: jweUser}, nil
			}
			return nil, errors.New("bad")
		},
	))

	opts := []sso.Option{
		sso.WithIssuer(jweASIssuer),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
	}
	if withDecrypter {
		dec, derr := defaultimpl.NewRSAJWEDecrypter(encPriv, jweEncKid)
		if derr != nil {
			t.Fatalf("NewRSAJWEDecrypter: %v", derr)
		}
		opts = append(opts, sso.WithJARDecrypter(dec))
	}

	server := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(server.Handler())
	t.Cleanup(httpSrv.Close)
	return &jweHarness{srv: httpSrv, signKey: sigPriv, encKey: encPriv}
}

// signJWE signs claims with the harness's Ed25519 key (same as JAR's
// signJAR), then wraps the resulting JWS in JWE using RSA-OAEP-256 +
// A256GCM. The JWE protected header carries the encryption key's kid
// so the AS can pick the right private key (single-key today; multi-key
// will need lookup).
func (h *jweHarness) signJWE(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := map[string]any{
		"alg": "EdDSA",
		"typ": "oauth-authz-req+jwt",
		"kid": jweSigKid,
	}
	hraw, _ := json.Marshal(header)
	praw, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hraw) + "." + base64.RawURLEncoding.EncodeToString(praw)
	sig := ed25519.Sign(h.signKey, []byte(signingInput))
	jws := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	// Now wrap the JWS as JWE.
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.RSA_OAEP_256,
			Key:       &h.encKey.PublicKey,
			KeyID:     jweEncKid,
		},
		(&jose.EncrypterOptions{}).WithType("oauth-authz-req+jwt"),
	)
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	obj, err := encrypter.Encrypt([]byte(jws))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	jwe, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	return jwe
}

func (h *jweHarness) loginJWE(t *testing.T, request string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  jweClient,
		"credential": map[string]string{"username": jweUser, "password": jwePassword},
		"request":    request,
	})
	resp, err := http.Post(h.srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func validJWEClaims() map[string]any {
	now := time.Now().Unix()
	return map[string]any{
		"iss":                   jweClient,
		"aud":                   jweASIssuer,
		"iat":                   now,
		"exp":                   now + 60,
		"client_id":             jweClient,
		"response_type":         "code",
		"redirect_uri":          "https://app.example.com/cb",
		"scope":                 "read",
		"state":                 "state-in-jwe",
		"code_challenge":        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789012",
		"code_challenge_method": "plain",
	}
}

// TestJWEJAR_HappyPath — a JAR JWS wrapped in JWE is decrypted by the
// AS, the inner JWS is signature-verified by the standard JAR pipeline,
// and /auth/login mints an auth_code with the merged claims.
func TestJWEJAR_HappyPath(t *testing.T) {
	h := newJWEHarness(t, true)
	jwe := h.signJWE(t, validJWEClaims())
	status, body := h.loginJWE(t, jwe)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["code"] == nil || body["code"] == "" {
		t.Errorf("missing code in JWE-driven code-flow response: %v", body)
	}
	if body["state"] != "state-in-jwe" {
		t.Errorf("state = %v want %q (echoed from inner JWS)", body["state"], "state-in-jwe")
	}
}

// TestJWEJAR_NoDecrypterWired_FailsClosed — same JWE payload, but the
// server has no WithJARDecrypter. Must reject with invalid_request_object
// so the RP knows to fall back to plain JAR.
func TestJWEJAR_NoDecrypterWired_FailsClosed(t *testing.T) {
	// We still need an encryption keypair to build the JWE; just wire
	// the server WITHOUT a decrypter. The encryption itself isn't the
	// AS's concern in this branch.
	h := newJWEHarness(t, false)
	jwe := h.signJWE(t, validJWEClaims())
	status, body := h.loginJWE(t, jwe)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v want 400", status, body)
	}
	if body["error"] != "invalid_request_object" {
		t.Errorf("error = %v want invalid_request_object", body["error"])
	}
}

// TestJWEJAR_DiscoveryAdvertisesAlgEnc — when the decrypter is wired,
// /.well-known/openid-configuration advertises the alg + enc lists.
// Without it, the fields are absent (the omitempty serialization
// hides them — RPs branch on presence).
func TestJWEJAR_DiscoveryAdvertisesAlgEnc(t *testing.T) {
	h := newJWEHarness(t, true)
	resp, err := http.Get(h.srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	doc := map[string]any{}
	_ = json.Unmarshal(raw, &doc)
	algs, _ := doc["request_object_encryption_alg_values_supported"].([]any)
	if len(algs) == 0 || algs[0] != "RSA-OAEP-256" {
		t.Errorf("algs = %v want [RSA-OAEP-256]", algs)
	}
	encs, _ := doc["request_object_encryption_enc_values_supported"].([]any)
	if len(encs) == 0 || encs[0] != "A256GCM" {
		t.Errorf("encs = %v want [A256GCM]", encs)
	}

	// Sanity: without the decrypter, the fields are absent.
	h2 := newJWEHarness(t, false)
	resp2, err := http.Get(h2.srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery (no dec): %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	raw2, _ := io.ReadAll(resp2.Body)
	doc2 := map[string]any{}
	_ = json.Unmarshal(raw2, &doc2)
	if _, present := doc2["request_object_encryption_alg_values_supported"]; present {
		t.Errorf("alg field leaked without decrypter: %v", doc2["request_object_encryption_alg_values_supported"])
	}
}

// TestJWEJAR_JWKSExposesEncryptionKey — the public RSA key with use:"enc"
// appears in /.well-known/jwks.json alongside the issuer's signing keys.
// RPs introspect this to know which kid to encrypt to.
func TestJWEJAR_JWKSExposesEncryptionKey(t *testing.T) {
	h := newJWEHarness(t, true)
	resp, err := http.Get(h.srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	doc := map[string]any{}
	_ = json.Unmarshal(raw, &doc)
	keys, _ := doc["keys"].([]any)
	var seenEnc bool
	for _, k := range keys {
		m, _ := k.(map[string]any)
		if m["use"] == "enc" && m["kty"] == "RSA" && m["alg"] == "RSA-OAEP-256" {
			seenEnc = true
			if m["kid"] != jweEncKid {
				t.Errorf("enc key kid = %v want %q", m["kid"], jweEncKid)
			}
		}
	}
	if !seenEnc {
		t.Errorf("no use:enc RSA key in JWKS; keys=%v", keys)
	}
}

// TestJWEJAR_PlainJWSStillAccepted — a plain (3-segment) JAR JWS
// against a server that ALSO has the decrypter wired MUST still work.
// JWE is additive; it doesn't replace the unencrypted path.
func TestJWEJAR_PlainJWSStillAccepted(t *testing.T) {
	h := newJWEHarness(t, true)
	// Build the inner JWS without wrapping it in JWE — mimics what
	// jar_test.go's signJAR does.
	claims := validJWEClaims()
	header := map[string]any{
		"alg": "EdDSA",
		"typ": "oauth-authz-req+jwt",
		"kid": jweSigKid,
	}
	hraw, _ := json.Marshal(header)
	praw, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hraw) + "." + base64.RawURLEncoding.EncodeToString(praw)
	sig := ed25519.Sign(h.signKey, []byte(signingInput))
	jws := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	status, body := h.loginJWE(t, jws)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v want 200 (plain JWS should pass through the wrapper)", status, body)
	}
	if body["code"] == nil {
		t.Errorf("no code in plain-JWS response: %v", body)
	}
}
