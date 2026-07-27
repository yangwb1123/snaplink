package ssotest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// End-to-end interop tests for the widening of the RP-facing asymmetric
// verification from EdDSA-only to ES256/384/512 + RS256 + PS256 + EdDSA
// across all three paths: private_key_jwt client assertions (RFC 7523), JAR
// request objects (RFC 9101), and DPoP proofs (RFC 9449). Each runs against
// a full *sso.Server over HTTP and signs with a real asymmetric key.

const maAsIssuer = "https://sso.test"

var asymmetricTestAlgs = []string{"EdDSA", "ES256", "ES384", "ES512", "RS256", "PS256"}

// ---------- private_key_jwt ----------

func newClientAssertionHarness(t *testing.T, clientJWK sso.JWK) *httptest.Server {
	t.Helper()
	const clientID = "ma-jca-client"
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "u-ma"})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    clientID,
		Active:                true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		JWKS:                  []sso.JWK{clientJWK},
	})
	srv := sso.NewServer(
		sso.WithIssuer(maAsIssuer),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(maAsIssuer), defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithJTIReplayStore(defaultimpl.NewMemoryJTIReplayStore()),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func callTokenAssertion(t *testing.T, srv *httptest.Server, assertion string) (int, map[string]any) {
	t.Helper()
	form := "grant_type=client_credentials" +
		"&client_assertion_type=" + sso.ClientAssertionTypeJWTBearer +
		"&client_assertion=" + assertion
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", bytes.NewReader([]byte(form)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

func TestMultiAlg_PrivateKeyJWT_AcceptsEachAlg(t *testing.T) {
	const clientID = "ma-jca-client"
	for _, alg := range asymmetricTestAlgs {
		t.Run(alg, func(t *testing.T) {
			signer := newSignerForAlg(t, alg, "kid-"+alg)
			srv := newClientAssertionHarness(t, signer.publicJWK)
			now := time.Now().Unix()
			assertion := signer.signCompact(t,
				map[string]any{"typ": "JWT", "kid": "kid-" + alg},
				map[string]any{
					"iss": clientID, "sub": clientID, "aud": maAsIssuer,
					"exp": now + 60, "iat": now, "jti": "ma-jti-" + alg,
				})
			status, body := callTokenAssertion(t, srv, assertion)
			if status != http.StatusOK {
				t.Fatalf("alg=%s status=%d body=%v", alg, status, body)
			}
			if body["access_token"] == nil {
				t.Fatalf("alg=%s no access_token: %v", alg, body)
			}
		})
	}
}

func TestMultiAlg_PrivateKeyJWT_RejectsAlgNone(t *testing.T) {
	const clientID = "ma-jca-client"
	signer := newSignerForAlg(t, "ES256", "kid-es")
	srv := newClientAssertionHarness(t, signer.publicJWK)
	now := time.Now().Unix()
	// Forge an alg=none token (empty signature) — must be rejected
	// BEFORE any signature work.
	hdr, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT", "kid": "kid-es"})
	pld, _ := json.Marshal(map[string]any{
		"iss": clientID, "sub": clientID, "aud": maAsIssuer, "exp": now + 60, "iat": now,
	})
	assertion := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pld) + "."
	status, body := callTokenAssertion(t, srv, assertion)
	if status != http.StatusUnauthorized || body["error"] != sso.ErrInvalidClient {
		t.Fatalf("alg=none status=%d err=%v want 401 invalid_client", status, body["error"])
	}
}

func TestMultiAlg_PrivateKeyJWT_RejectsHS256WithPublicKeyAsSecret(t *testing.T) {
	// The classic RS/HS confusion: an attacker who only knows the
	// client's PUBLIC key tries to forge an HS256 assertion using that
	// public key as the HMAC secret. VerifyCompactJWS refuses every
	// symmetric alg, so this MUST fail invalid_client.
	const clientID = "ma-jca-client"
	rsaSigner := newSignerForAlg(t, "RS256", "kid-rsa")
	srv := newClientAssertionHarness(t, rsaSigner.publicJWK)
	now := time.Now().Unix()

	// Reconstruct the public-key bytes the attacker would use as the
	// HMAC secret (the JWK n||e is public).
	secret := []byte(rsaSigner.publicJWK.N + rsaSigner.publicJWK.E)
	hdr, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT", "kid": "kid-rsa"})
	pld, _ := json.Marshal(map[string]any{
		"iss": clientID, "sub": clientID, "aud": maAsIssuer, "exp": now + 60, "iat": now,
	})
	signingInput := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pld)
	mac := hmacSHA256(secret, []byte(signingInput))
	assertion := signingInput + "." + base64.RawURLEncoding.EncodeToString(mac)

	status, body := callTokenAssertion(t, srv, assertion)
	if status != http.StatusUnauthorized || body["error"] != sso.ErrInvalidClient {
		t.Fatalf("HS256-confusion status=%d err=%v want 401 invalid_client", status, body["error"])
	}
}

func TestMultiAlg_PrivateKeyJWT_RejectsAlgKtyMismatch(t *testing.T) {
	// Header claims ES256 but the kid points at an RSA key. The
	// kty<->alg consistency gate in VerifyCompactJWS must reject this
	// (an alg-confusion seam).
	const clientID = "ma-jca-client"
	rsaSigner := newSignerForAlg(t, "RS256", "kid-rsa")
	srv := newClientAssertionHarness(t, rsaSigner.publicJWK)
	now := time.Now().Unix()
	// Sign with the RSA key (RS256 bytes) but LIE in the header that
	// it's ES256. The signature won't match ES256 verification anyway,
	// and the kty (RSA) is inconsistent with ES256 (EC) — fail closed.
	hdr, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT", "kid": "kid-rsa"})
	pld, _ := json.Marshal(map[string]any{
		"iss": clientID, "sub": clientID, "aud": maAsIssuer, "exp": now + 60, "iat": now,
	})
	signingInput := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pld)
	sig := rsaSigner.sign([]byte(signingInput))
	assertion := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	status, body := callTokenAssertion(t, srv, assertion)
	if status != http.StatusUnauthorized || body["error"] != sso.ErrInvalidClient {
		t.Fatalf("alg/kty-mismatch status=%d err=%v want 401 invalid_client", status, body["error"])
	}
}

func TestMultiAlg_PrivateKeyJWT_RejectsBadSignature_ES256(t *testing.T) {
	const clientID = "ma-jca-client"
	signer := newSignerForAlg(t, "ES256", "kid-es")
	srv := newClientAssertionHarness(t, signer.publicJWK)
	now := time.Now().Unix()
	assertion := signer.signCompact(t,
		map[string]any{"typ": "JWT", "kid": "kid-es"},
		map[string]any{"iss": clientID, "sub": clientID, "aud": maAsIssuer, "exp": now + 60, "iat": now})
	parts := strings.Split(assertion, ".")
	parts[2] = strings.Repeat("A", len(parts[2]))
	status, body := callTokenAssertion(t, srv, strings.Join(parts, "."))
	if status != http.StatusUnauthorized || body["error"] != sso.ErrInvalidClient {
		t.Fatalf("bad-sig status=%d err=%v want 401 invalid_client", status, body["error"])
	}
}

func TestMultiAlg_PrivateKeyJWT_ClaimChecksStillEnforced_ES256(t *testing.T) {
	const clientID = "ma-jca-client"
	signer := newSignerForAlg(t, "ES256", "kid-es")
	srv := newClientAssertionHarness(t, signer.publicJWK)
	now := time.Now().Unix()

	// Wrong audience.
	wrongAud := signer.signCompact(t,
		map[string]any{"typ": "JWT", "kid": "kid-es"},
		map[string]any{"iss": clientID, "sub": clientID, "aud": "https://evil.example", "exp": now + 60, "iat": now})
	if status, _ := callTokenAssertion(t, srv, wrongAud); status != http.StatusUnauthorized {
		t.Fatalf("wrong-aud status=%d want 401", status)
	}

	// Expired.
	expired := signer.signCompact(t,
		map[string]any{"typ": "JWT", "kid": "kid-es"},
		map[string]any{"iss": clientID, "sub": clientID, "aud": maAsIssuer, "exp": now - 3600, "iat": now - 3700})
	if status, _ := callTokenAssertion(t, srv, expired); status != http.StatusUnauthorized {
		t.Fatalf("expired status=%d want 401", status)
	}

	// Replayed jti (ES256 happy then replay).
	replayed := signer.signCompact(t,
		map[string]any{"typ": "JWT", "kid": "kid-es"},
		map[string]any{"iss": clientID, "sub": clientID, "aud": maAsIssuer, "exp": now + 60, "iat": now, "jti": "ma-replay-es"})
	if status, _ := callTokenAssertion(t, srv, replayed); status != http.StatusOK {
		t.Fatalf("first-use status=%d want 200", status)
	}
	if status, _ := callTokenAssertion(t, srv, replayed); status != http.StatusUnauthorized {
		t.Fatalf("replay status=%d want 401", status)
	}
}

// ---------- JAR ----------

func newJARMultiAlgHarness(t *testing.T, clientJWK sso.JWK) *httptest.Server {
	t.Helper()
	const (
		clientID    = "ma-jar-client"
		redirectURI = "https://app.example/cb"
		userID      = "u-ma-jar"
	)
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: userID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: clientID, Secret: "s", Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{redirectURI},
		JWKS:                  []sso.JWK{clientJWK},
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == userID && p == "pw" {
				return &sso.AuthResult{UserID: userID}, nil
			}
			return nil, errors.New("bad")
		},
	))
	srv := sso.NewServer(
		sso.WithIssuer(maAsIssuer),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func loginJARMulti(t *testing.T, srv *httptest.Server, jar string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  "ma-jar-client",
		"credential": map[string]string{"username": "u-ma-jar", "password": "pw"},
		"request":    jar,
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func TestMultiAlg_JAR_AcceptsEachAlg(t *testing.T) {
	const (
		clientID    = "ma-jar-client"
		redirectURI = "https://app.example/cb"
	)
	for _, alg := range asymmetricTestAlgs {
		t.Run(alg, func(t *testing.T) {
			signer := newSignerForAlg(t, alg, "jar-kid-"+alg)
			srv := newJARMultiAlgHarness(t, signer.publicJWK)
			now := time.Now().Unix()
			jar := signer.signCompact(t,
				map[string]any{"typ": "oauth-authz-req+jwt", "kid": "jar-kid-" + alg},
				map[string]any{
					"iss": clientID, "aud": maAsIssuer, "iat": now, "exp": now + 60,
					"client_id": clientID, "response_type": "code", "redirect_uri": redirectURI,
					"code_challenge":        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789012",
					"code_challenge_method": "plain",
				})
			status, body := loginJARMulti(t, srv, jar)
			if status != http.StatusOK {
				t.Fatalf("alg=%s status=%d body=%v", alg, status, body)
			}
			if body["code"] == nil || body["code"] == "" {
				t.Fatalf("alg=%s no code: %v", alg, body)
			}
		})
	}
}

func TestMultiAlg_JAR_RejectsAlgNone(t *testing.T) {
	const (
		clientID    = "ma-jar-client"
		redirectURI = "https://app.example/cb"
	)
	signer := newSignerForAlg(t, "ES256", "jar-kid-es")
	srv := newJARMultiAlgHarness(t, signer.publicJWK)
	now := time.Now().Unix()
	hdr, _ := json.Marshal(map[string]any{"alg": "none", "typ": "oauth-authz-req+jwt", "kid": "jar-kid-es"})
	pld, _ := json.Marshal(map[string]any{
		"iss": clientID, "aud": maAsIssuer, "iat": now, "exp": now + 60,
		"client_id": clientID, "response_type": "code", "redirect_uri": redirectURI,
	})
	jar := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pld) + "."
	status, body := loginJARMulti(t, srv, jar)
	if status != http.StatusBadRequest || body["error"] != "invalid_request_object" {
		t.Fatalf("alg=none status=%d err=%v want 400 invalid_request_object", status, body["error"])
	}
}

func TestMultiAlg_JAR_RejectsAlgKtyMismatch(t *testing.T) {
	const (
		clientID    = "ma-jar-client"
		redirectURI = "https://app.example/cb"
	)
	rsaSigner := newSignerForAlg(t, "RS256", "jar-kid-rsa")
	srv := newJARMultiAlgHarness(t, rsaSigner.publicJWK)
	now := time.Now().Unix()
	hdr, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt", "kid": "jar-kid-rsa"})
	pld, _ := json.Marshal(map[string]any{
		"iss": clientID, "aud": maAsIssuer, "iat": now, "exp": now + 60,
		"client_id": clientID, "response_type": "code", "redirect_uri": redirectURI,
	})
	si := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pld)
	jar := si + "." + base64.RawURLEncoding.EncodeToString(rsaSigner.sign([]byte(si)))
	status, body := loginJARMulti(t, srv, jar)
	if status != http.StatusBadRequest || body["error"] != "invalid_request_object" {
		t.Fatalf("alg/kty-mismatch status=%d err=%v want 400 invalid_request_object", status, body["error"])
	}
}

func TestMultiAlg_JAR_RejectsWrongKey_RS256(t *testing.T) {
	const (
		clientID    = "ma-jar-client"
		redirectURI = "https://app.example/cb"
	)
	registered := newSignerForAlg(t, "RS256", "jar-kid-rsa")
	srv := newJARMultiAlgHarness(t, registered.publicJWK)
	// Sign with a DIFFERENT RSA key but claim the registered kid.
	attacker := newSignerForAlg(t, "RS256", "jar-kid-rsa")
	now := time.Now().Unix()
	jar := attacker.signCompact(t,
		map[string]any{"typ": "oauth-authz-req+jwt", "kid": "jar-kid-rsa"},
		map[string]any{
			"iss": clientID, "aud": maAsIssuer, "iat": now, "exp": now + 60,
			"client_id": clientID, "response_type": "code", "redirect_uri": redirectURI,
		})
	status, body := loginJARMulti(t, srv, jar)
	if status != http.StatusBadRequest || body["error"] != "invalid_request_object" {
		t.Fatalf("wrong-key status=%d err=%v want 400 invalid_request_object", status, body["error"])
	}
}

// ---------- DPoP ----------

func newDPoPMultiAlgHarness(t *testing.T) *httptest.Server {
	t.Helper()
	const clientID = "ma-dpop-client"
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: clientID, Secret: "dpop-secret", Active: true,
		TokenStrategy: "jwt",
	})
	srv := sso.NewServer(
		sso.WithIssuer(maAsIssuer),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(maAsIssuer), defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// signDPoPMultiAlg builds a DPoP proof with the signer's public JWK embedded
// in the header (the ephemeral key DPoP binds to). dpop has no kid.
func signDPoPMultiAlg(t *testing.T, signer *multiAlgSigner, method, url string, mutate func(map[string]any)) string {
	t.Helper()
	jwk := map[string]any{"kty": signer.publicJWK.Kty}
	switch signer.publicJWK.Kty {
	case "OKP":
		jwk["crv"] = signer.publicJWK.Crv
		jwk["x"] = signer.publicJWK.X
	case "EC":
		jwk["crv"] = signer.publicJWK.Crv
		jwk["x"] = signer.publicJWK.X
		jwk["y"] = signer.publicJWK.Y
	case "RSA":
		jwk["n"] = signer.publicJWK.N
		jwk["e"] = signer.publicJWK.E
	}
	payload := map[string]any{
		"htm": method,
		"htu": url,
		"iat": time.Now().Unix(),
		"jti": "ma-dpop-" + signer.alg + "-" + randHex(),
	}
	if mutate != nil {
		mutate(payload)
	}
	return signer.signCompact(t, map[string]any{"typ": "dpop+jwt", "jwk": jwk}, payload)
}

func randHex() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func callTokenDPoPMulti(t *testing.T, srv *httptest.Server, proof string) (int, map[string]any) {
	t.Helper()
	form := "grant_type=client_credentials&client_id=ma-dpop-client&client_secret=dpop-secret&scope=openid"
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

func TestMultiAlg_DPoP_AcceptsEachAlg_AndBindsThumbprint(t *testing.T) {
	for _, alg := range asymmetricTestAlgs {
		t.Run(alg, func(t *testing.T) {
			srv := newDPoPMultiAlgHarness(t)
			signer := newSignerForAlg(t, alg, "")
			proof := signDPoPMultiAlg(t, signer, "POST", srv.URL+"/token", nil)
			status, body := callTokenDPoPMulti(t, srv, proof)
			if status != http.StatusOK {
				t.Fatalf("alg=%s status=%d body=%v", alg, status, body)
			}
			if body["token_type"] != "DPoP" {
				t.Errorf("alg=%s token_type=%v want DPoP", alg, body["token_type"])
			}
			access, _ := body["access_token"].(string)
			payload := decodeAccessTokenPayload(t, access)
			cnf, ok := payload["cnf"].(map[string]any)
			if !ok {
				t.Fatalf("alg=%s cnf missing: %v", alg, payload)
			}
			jkt, _ := cnf["jkt"].(string)
			if jkt == "" {
				t.Fatalf("alg=%s cnf.jkt missing: %v", alg, cnf)
			}
			// The bound thumbprint MUST equal the RFC 7638 thumbprint of
			// the proof's public JWK, recomputed independently per kty.
			want := expectedJKT(t, signer.publicJWK)
			if jkt != want {
				t.Errorf("alg=%s cnf.jkt=%q want %q (RFC 7638 mismatch = binding bypass)", alg, jkt, want)
			}
		})
	}
}

func TestMultiAlg_DPoP_RejectsAlgNone(t *testing.T) {
	srv := newDPoPMultiAlgHarness(t)
	signer := newSignerForAlg(t, "ES256", "")
	// Build header with alg=none but a real EC jwk + empty signature.
	jwk := map[string]any{"kty": "EC", "crv": signer.publicJWK.Crv, "x": signer.publicJWK.X, "y": signer.publicJWK.Y}
	hdr, _ := json.Marshal(map[string]any{"alg": "none", "typ": "dpop+jwt", "jwk": jwk})
	pld, _ := json.Marshal(map[string]any{"htm": "POST", "htu": srv.URL + "/token", "iat": time.Now().Unix(), "jti": "none-jti"})
	proof := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pld) + "."
	status, body := callTokenDPoPMulti(t, srv, proof)
	if status != http.StatusBadRequest || body["error"] != sso.ErrInvalidDPoPProof {
		t.Fatalf("alg=none status=%d err=%v want 400 invalid_dpop_proof", status, body["error"])
	}
}

func TestMultiAlg_DPoP_RejectsSymmetric(t *testing.T) {
	srv := newDPoPMultiAlgHarness(t)
	jwk := map[string]any{"kty": "oct", "k": "AAAA"}
	hdr, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "dpop+jwt", "jwk": jwk})
	pld, _ := json.Marshal(map[string]any{"htm": "POST", "htu": srv.URL + "/token", "iat": time.Now().Unix(), "jti": "hs-jti"})
	si := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pld)
	mac := hmacSHA256([]byte("secret"), []byte(si))
	proof := si + "." + base64.RawURLEncoding.EncodeToString(mac)
	status, body := callTokenDPoPMulti(t, srv, proof)
	if status != http.StatusBadRequest || body["error"] != sso.ErrInvalidDPoPProof {
		t.Fatalf("HS256 status=%d err=%v want 400 invalid_dpop_proof", status, body["error"])
	}
}

func TestMultiAlg_DPoP_DifferentKeyFailsResourceBinding_ES256(t *testing.T) {
	srv := newDPoPMultiAlgHarness(t)
	signer := newSignerForAlg(t, "ES256", "")
	// Mint a DPoP-bound token with the EC key.
	proof := signDPoPMultiAlg(t, signer, "POST", srv.URL+"/token", nil)
	status, body := callTokenDPoPMulti(t, srv, proof)
	if status != http.StatusOK {
		t.Fatalf("mint status=%d body=%v", status, body)
	}
	access, _ := body["access_token"].(string)

	// Present /userinfo with a DPoP proof signed by a DIFFERENT EC key:
	// the thumbprint won't match cnf.jkt → 401 invalid_token.
	other := newSignerForAlg(t, "ES256", "")
	otherProof := signDPoPMultiAlg(t, other, "GET", srv.URL+"/userinfo", nil)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "DPoP "+access)
	req.Header.Set("DPoP", otherProof)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		rb, _ := io.ReadAll(resp.Body)
		t.Fatalf("mismatched-key /userinfo status=%d want 401 body=%s", resp.StatusCode, rb)
	}
}

func TestMultiAlg_DPoP_ChecksStillEnforced_ES256(t *testing.T) {
	srv := newDPoPMultiAlgHarness(t)
	signer := newSignerForAlg(t, "ES256", "")
	// Wrong htm.
	if status, _ := callTokenDPoPMulti(t, srv, signDPoPMultiAlg(t, signer, "GET", srv.URL+"/token", nil)); status != http.StatusBadRequest {
		t.Fatalf("wrong-htm status=%d want 400", status)
	}
	// Wrong htu.
	if status, _ := callTokenDPoPMulti(t, srv, signDPoPMultiAlg(t, signer, "POST", "https://evil.example/token", nil)); status != http.StatusBadRequest {
		t.Fatalf("wrong-htu status=%d want 400", status)
	}
	// Stale iat.
	stale := signDPoPMultiAlg(t, signer, "POST", srv.URL+"/token", func(p map[string]any) {
		p["iat"] = time.Now().Add(-10 * time.Minute).Unix()
	})
	if status, _ := callTokenDPoPMulti(t, srv, stale); status != http.StatusBadRequest {
		t.Fatalf("stale-iat status=%d want 400", status)
	}
}

// ---------- federation-shaped RSA/ECDSA RP, full auth_code + private_key_jwt ----------

// An OpenID Federation RP's chain-vouched key may be RSA or ECDSA. Such an RP
// is, to the token endpoint, a Client whose registered JWKS holds that key.
// Before this change private_key_jwt rejected any alg != EdDSA, so an RSA/EC
// federation RP could authenticate the auth-code exchange ONLY with an Ed25519
// key. This test proves the lifted limitation end-to-end: a client with an
// RSA (and an ECDSA) JWKS logs in, gets an authorization_code, and exchanges
// it at /token via private_key_jwt signed with that same key. (The dedicated
// federation auto-registration E2E in federation_registration_test.go drives
// the trust-chain resolution itself with an Ed25519 RP key; here the key type
// is the variable under test.)
func TestMultiAlg_FederationShapedRP_AuthCodeExchange(t *testing.T) {
	const (
		clientID    = "ma-fed-rp"
		redirectURI = "https://rp.fed.example/cb"
		userID      = "u-ma-fed"
		password    = "pw"
	)
	for _, alg := range []string{"RS256", "ES256"} {
		t.Run(alg, func(t *testing.T) {
			signer := newSignerForAlg(t, alg, "fed-kid-"+alg)
			users := defaultimpl.NewMemoryUserProvider()
			_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: userID})
			clients := defaultimpl.NewMemoryClientStore()
			clients.AddSeed(&sso.Client{
				ID: clientID, Active: true,
				AllowedAuthenticators: []string{"password"},
				TokenStrategy:         "jwt",
				RedirectURIs:          []string{redirectURI},
				JWKS:                  []sso.JWK{signer.publicJWK}, // chain-vouched key
			})
			pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
				func(_ context.Context, u, p string) (*sso.AuthResult, error) {
					if u == userID && p == password {
						return &sso.AuthResult{UserID: userID}, nil
					}
					return nil, errors.New("bad")
				},
			))
			srv := sso.NewServer(
				sso.WithIssuer(maAsIssuer),
				sso.WithUserProvider(users),
				sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
				sso.WithClientStore(clients),
				sso.WithAuthenticator(pw),
				sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(maAsIssuer), defaultimpl.WithEd25519TokenTTL(time.Minute))),
				sso.WithDefaultTokenStrategy("jwt"),
				sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
			)
			httpSrv := httptest.NewServer(srv.Handler())
			t.Cleanup(httpSrv.Close)

			// 1. Login → authorization_code.
			loginBody, _ := json.Marshal(map[string]any{
				"provider":      "password",
				"client_id":     clientID,
				"credential":    map[string]string{"username": userID, "password": password},
				"response_type": "code",
				"redirect_uri":  redirectURI,
				"scope":         []string{"openid"},
			})
			lresp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(loginBody))
			if err != nil {
				t.Fatal(err)
			}
			lraw, _ := io.ReadAll(lresp.Body)
			_ = lresp.Body.Close()
			var lout map[string]any
			_ = json.Unmarshal(lraw, &lout)
			code, _ := lout["code"].(string)
			if code == "" {
				t.Fatalf("alg=%s no auth code: %s", alg, lraw)
			}

			// 2. Exchange the code at /token authenticating via
			// private_key_jwt signed with the RSA/EC chain-vouched key.
			now := time.Now().Unix()
			assertion := signer.signCompact(t,
				map[string]any{"typ": "JWT", "kid": "fed-kid-" + alg},
				map[string]any{
					"iss": clientID, "sub": clientID, "aud": maAsIssuer,
					"exp": now + 60, "iat": now, "jti": "fed-exch-" + alg,
				})
			form := "grant_type=authorization_code&code=" + code +
				"&redirect_uri=" + redirectURI +
				"&client_id=" + clientID +
				"&client_assertion_type=" + sso.ClientAssertionTypeJWTBearer +
				"&client_assertion=" + assertion
			tresp, err := http.Post(httpSrv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form))
			if err != nil {
				t.Fatal(err)
			}
			traw, _ := io.ReadAll(tresp.Body)
			_ = tresp.Body.Close()
			var tout map[string]any
			_ = json.Unmarshal(traw, &tout)
			if tresp.StatusCode != http.StatusOK {
				t.Fatalf("alg=%s token exchange status=%d body=%s (RSA/EC federation RP must complete private_key_jwt)", alg, tresp.StatusCode, traw)
			}
			if tout["access_token"] == nil {
				t.Fatalf("alg=%s no access_token: %v", alg, tout)
			}
		})
	}
}

// EdDSA regression: the historical OKP path must be byte-identical in
// behavior (still accepted, still binds the same thumbprint the old
// OKP-only code produced).
func TestMultiAlg_DPoP_EdDSARegression(t *testing.T) {
	srv := newDPoPMultiAlgHarness(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	x := base64.RawURLEncoding.EncodeToString(pub)
	header := map[string]any{
		"alg": "EdDSA", "typ": "dpop+jwt",
		"jwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": x},
	}
	hraw, _ := json.Marshal(header)
	payload := map[string]any{"htm": "POST", "htu": srv.URL + "/token", "iat": time.Now().Unix(), "jti": "eddsa-reg"}
	praw, _ := json.Marshal(payload)
	si := base64.RawURLEncoding.EncodeToString(hraw) + "." + base64.RawURLEncoding.EncodeToString(praw)
	proof := si + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(si)))
	status, body := callTokenDPoPMulti(t, srv, proof)
	if status != http.StatusOK || body["token_type"] != "DPoP" {
		t.Fatalf("eddsa status=%d token_type=%v want 200 DPoP", status, body["token_type"])
	}
	access, _ := body["access_token"].(string)
	cnf := decodeAccessTokenPayload(t, access)["cnf"].(map[string]any)
	// The OKP canonical form is {"crv":"Ed25519","kty":"OKP","x":...}.
	want := expectedJKT(t, sso.JWK{Kty: "OKP", Crv: "Ed25519", X: x})
	if cnf["jkt"] != want {
		t.Errorf("EdDSA jkt=%v want %q (OKP thumbprint must be unchanged)", cnf["jkt"], want)
	}
}
