package rs_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
)

// dpopKey is an ephemeral EdDSA DPoP proof key for tests.
type dpopKey struct {
	priv ed25519.PrivateKey
	pubX string
}

func newDPoPKey(t *testing.T) dpopKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return dpopKey{priv: priv, pubX: base64.RawURLEncoding.EncodeToString(pub)}
}

// thumbprint reproduces the RFC 7638 OKP canonical form independently of the
// package-internal helper, so the test pins the wire format rather than
// tautologically calling the same code under test.
func (k dpopKey) thumbprint() string {
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + k.pubX + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// proof mints a DPoP proof JWT bound to htm/htu/accessToken with the given
// iat/jti, signed by k.
func (k dpopKey) proof(t *testing.T, htm, htu, accessToken string, iat int64, jti string) string {
	t.Helper()
	header := map[string]any{
		"alg": "EdDSA",
		"typ": "dpop+jwt",
		"jwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": k.pubX},
	}
	sum := sha256.Sum256([]byte(accessToken))
	payload := map[string]any{
		"htm": htm,
		"htu": htu,
		"iat": iat,
		"jti": jti,
		"ath": base64.RawURLEncoding.EncodeToString(sum[:]),
	}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sig := ed25519.Sign(k.priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

const (
	testHTM = "GET"
	testHTU = "https://api.example.com/orders"
)

func TestValidateTokenWithDPoP_HappyPath(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	key := newDPoPKey(t)
	tok, err := iss.MintAccessToken(map[string]any{
		"sub": "user-1",
		"cnf": map[string]any{"jkt": key.thumbprint()},
	})
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	cfg := newTestConfig(t, iss, "")
	cfg.DPoPVerifier = rs.NewDPoPVerifier()
	proof := key.proof(t, testHTM, testHTU, tok, time.Now().Unix(), "jti-1")

	claims, err := rs.ValidateTokenWithDPoP(context.Background(), tok, proof, testHTM, testHTU, cfg)
	if err != nil {
		t.Fatalf("ValidateTokenWithDPoP: %v", err)
	}
	if claims.CnfJKT != key.thumbprint() {
		t.Errorf("CnfJKT = %q, want %q", claims.CnfJKT, key.thumbprint())
	}
}

func TestValidateTokenWithDPoP_ThumbprintMismatch(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	boundKey := newDPoPKey(t)
	attackerKey := newDPoPKey(t)
	tok, err := iss.MintAccessToken(map[string]any{
		"sub": "user-1",
		"cnf": map[string]any{"jkt": boundKey.thumbprint()},
	})
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	cfg := newTestConfig(t, iss, "")
	cfg.DPoPVerifier = rs.NewDPoPVerifier()
	// Proof is validly signed by a DIFFERENT key than the token is bound to —
	// the classic stolen-bearer-token-plus-own-key replay this binding exists
	// to stop.
	proof := attackerKey.proof(t, testHTM, testHTU, tok, time.Now().Unix(), "jti-1")

	_, err = rs.ValidateTokenWithDPoP(context.Background(), tok, proof, testHTM, testHTU, cfg)
	if !errors.Is(err, rs.ErrDPoPInvalid) {
		t.Fatalf("err = %v, want ErrDPoPInvalid", err)
	}
}

func TestValidateTokenWithDPoP_MissingCnfRejected(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	key := newDPoPKey(t)
	// A plain bearer token — no cnf.jkt at all — must never be accepted via
	// the DPoP path; that would silently downgrade sender-constraint.
	tok, err := iss.MintAccessToken(map[string]any{"sub": "user-1"})
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	cfg := newTestConfig(t, iss, "")
	proof := key.proof(t, testHTM, testHTU, tok, time.Now().Unix(), "jti-1")

	_, err = rs.ValidateTokenWithDPoP(context.Background(), tok, proof, testHTM, testHTU, cfg)
	if !errors.Is(err, rs.ErrDPoPInvalid) {
		t.Fatalf("err = %v, want ErrDPoPInvalid", err)
	}
}

func TestValidateTokenWithDPoP_ReplayRejected(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	key := newDPoPKey(t)
	tok, err := iss.MintAccessToken(map[string]any{
		"sub": "user-1",
		"cnf": map[string]any{"jkt": key.thumbprint()},
	})
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	cfg := newTestConfig(t, iss, "")
	cfg.DPoPVerifier = rs.NewDPoPVerifier()
	proof := key.proof(t, testHTM, testHTU, tok, time.Now().Unix(), "jti-replay-me")

	if _, err := rs.ValidateTokenWithDPoP(context.Background(), tok, proof, testHTM, testHTU, cfg); err != nil {
		t.Fatalf("first use: %v", err)
	}
	_, err = rs.ValidateTokenWithDPoP(context.Background(), tok, proof, testHTM, testHTU, cfg)
	if !errors.Is(err, rs.ErrDPoPReplayed) {
		t.Fatalf("second use err = %v, want ErrDPoPReplayed", err)
	}
}

func TestValidateTokenWithDPoP_HTMMismatch(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	key := newDPoPKey(t)
	tok, err := iss.MintAccessToken(map[string]any{
		"sub": "user-1",
		"cnf": map[string]any{"jkt": key.thumbprint()},
	})
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	cfg := newTestConfig(t, iss, "")
	cfg.DPoPVerifier = rs.NewDPoPVerifier()
	// Proof is bound to POST, but the request being served is a GET.
	proof := key.proof(t, "POST", testHTU, tok, time.Now().Unix(), "jti-1")

	_, err = rs.ValidateTokenWithDPoP(context.Background(), tok, proof, testHTM, testHTU, cfg)
	if !errors.Is(err, rs.ErrDPoPInvalid) {
		t.Fatalf("err = %v, want ErrDPoPInvalid", err)
	}
}
