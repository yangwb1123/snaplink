package ssotest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security/securityverify"
)

// TestJWTAlgNoneRejection verifies that alg=none is rejected across all
// verification paths (AGENTS.md M-BM-§0.2: "alg=none banned; algorithm checked
// BEFORE signature verify").
func TestJWTAlgNoneRejection(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	b64 := func(data []byte) string {
		return base64.RawURLEncoding.EncodeToString(data)
	}

	// Create a valid JWT first
	header := map[string]string{"alg": "EdDSA", "typ": "JWT"}
	payload := map[string]any{"sub": "test", "iss": "https://sso.test"}

	hJSON, _ := json.Marshal(header)
	pJSON, _ := json.Marshal(payload)

	signingInput := b64(hJSON) + "." + b64(pJSON)
	sig := ed25519.Sign(priv, []byte(signingInput))
	validToken := signingInput + "." + b64(sig)

	// Create an alg=none token
	noneHeader := map[string]string{"alg": "none", "typ": "JWT"}
	nhJSON, _ := json.Marshal(noneHeader)
	noneInput := b64(nhJSON) + "." + b64(pJSON)
	noneToken := noneInput + "."

	_, pubJWK := ed25519PubKeyToJWK(priv.Public().(ed25519.PublicKey))
	jwks := []core.JWK{pubJWK}

	edAlgs := map[string]struct{}{"EdDSA": {}, "ES256": {}}
	esOnly := map[string]struct{}{"ES256": {}}
	emptyAlgs := map[string]struct{}{}

	// Test 1: VerifyCompactJWS should reject alg=none
	t.Run("VerifyCompactJWS_rejects_alg_none", func(t *testing.T) {
		_, err := securityverify.VerifyCompactJWS(noneToken, jwks, edAlgs)
		if err == nil {
			t.Error("expected error for alg=none token")
		} else {
			t.Logf("alg=none correctly rejected: %v", err)
		}
	})

	// Test 2: Valid EdDSA token should still pass
	t.Run("VerifyCompactJWS_accepts_EdDSA", func(t *testing.T) {
		_, err := securityverify.VerifyCompactJWS(validToken, jwks, edAlgs)
		if err != nil {
			t.Errorf("expected valid EdDSA token to pass, got: %v", err)
		}
	})

	// Test 3: alg mismatch should be rejected
	t.Run("VerifyCompactJWS_rejects_alg_mismatch", func(t *testing.T) {
		_, err := securityverify.VerifyCompactJWS(validToken, jwks, esOnly)
		if err == nil {
			t.Error("expected error for alg mismatch")
		} else {
			t.Logf("alg mismatch correctly rejected: %v", err)
		}
	})

	// Test 4: empty allowed algs should reject
	t.Run("VerifyCompactJWS_rejects_empty_algs", func(t *testing.T) {
		_, err := securityverify.VerifyCompactJWS(validToken, jwks, emptyAlgs)
		if err == nil {
			t.Error("expected error for empty allowed algs")
		}
	})
}

// ed25519PubKeyToJWK converts an Ed25519 public key to a core.JWK.
func ed25519PubKeyToJWK(pub ed25519.PublicKey) ([]byte, core.JWK) {
	return nil, core.JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}
}

// TestJWTAlgNoneIdentityToken verifies that alg=none is rejected when
// presented as a fake access token.
func TestJWTAlgNoneIdentityToken(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	header := map[string]string{"alg": "none", "typ": "at+jwt"}
	payload := map[string]any{
		"iss": "https://sso.test",
		"sub": "test-user",
		"exp": 9999999999,
	}
	hJSON, _ := json.Marshal(header)
	pJSON, _ := json.Marshal(payload)
	token := base64.RawURLEncoding.EncodeToString(hJSON) + "." +
		base64.RawURLEncoding.EncodeToString(pJSON) + "."

	_, pubJWK := ed25519PubKeyToJWK(priv.Public().(ed25519.PublicKey))
	edAlgs := map[string]struct{}{"EdDSA": {}}

	_, err = securityverify.VerifyCompactJWS(token, []core.JWK{pubJWK}, edAlgs)
	if err == nil {
		t.Error("expected alg=none token to be rejected")
	} else if strings.Contains(err.Error(), "none") || strings.Contains(err.Error(), "alg") {
		t.Logf("alg=none correctly rejected with: %v", err)
	} else {
		t.Logf("alg=none rejected: %v", err)
	}
}
