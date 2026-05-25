package defaultimpl_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/oidc"
)

func rsaAlgs() []string { return []string{"RS256", "PS256"} }

func TestRSAJWT_RoundTrip_BothAlgs(t *testing.T) {
	for _, alg := range rsaAlgs() {
		t.Run(alg, func(t *testing.T) {
			iss := defaultimpl.NewRSAJWTIssuer(
				defaultimpl.WithRSAIssuer("test-iss"),
				defaultimpl.WithRSAAlg(alg),
				defaultimpl.WithRSATokenTTL(5*time.Minute),
			)
			tok, err := iss.Issue(context.Background(), &sso.Subject{
				ID: "user-1", ClientID: "client-1",
				Claims: map[string]string{"email": "u@example.com"},
			}, []string{"read", "write"})
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			if got := strings.Count(tok.AccessToken, "."); got != 2 {
				t.Fatalf("expected 3 JWT segments, got %d", got+1)
			}
			// Header alg must equal the configured alg.
			hb, _ := base64.RawURLEncoding.DecodeString(strings.SplitN(tok.AccessToken, ".", 2)[0])
			var hdr map[string]any
			_ = json.Unmarshal(hb, &hdr)
			if hdr["alg"] != alg {
				t.Errorf("header alg = %v, want %s", hdr["alg"], alg)
			}
			if hdr["typ"] != "at+jwt" {
				t.Errorf("typ = %v, want at+jwt", hdr["typ"])
			}

			claims, err := iss.Validate(context.Background(), tok.AccessToken)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if claims.Subject != "user-1" || claims.ClientID != "client-1" {
				t.Errorf("claims mismatch: %+v", claims)
			}
			if claims.JTI == "" {
				t.Error("RFC 9068 §2.2 requires jti")
			}
			if claims.Extra["email"] != "u@example.com" {
				t.Errorf("Extra lost: %v", claims.Extra)
			}
		})
	}
}

func TestRSAJWT_JWKS(t *testing.T) {
	iss := defaultimpl.NewRSAJWTIssuer(defaultimpl.WithRSAAlg("PS256"))
	keys, err := iss.JWKS(context.Background())
	if err != nil || len(keys) != 1 {
		t.Fatalf("JWKS: err=%v len=%d", err, len(keys))
	}
	k := keys[0]
	if k.Kty != "RSA" || k.N == "" || k.E == "" {
		t.Errorf("RSA JWK malformed: %+v", k)
	}
	if k.Alg != "PS256" || k.Use != "sig" {
		t.Errorf("JWK alg/use = %s/%s, want PS256/sig", k.Alg, k.Use)
	}
	if k.Kid != iss.KeyID() {
		t.Errorf("JWK kid %q != issuer kid %q", k.Kid, iss.KeyID())
	}
}

// TestRSAJWT_AlgConfusion proves the strict per-issuer alg gate: an RS256
// issuer rejects a PS256-signed token and vice versa, plus alg=none and a
// tampered alg header — all before signature verification.
func TestRSAJWT_AlgConfusion(t *testing.T) {
	rs := defaultimpl.NewRSAJWTIssuer(defaultimpl.WithRSAAlg("RS256"))
	ps := defaultimpl.NewRSAJWTIssuer(defaultimpl.WithRSAAlg("PS256"))

	rsTok, _ := rs.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, nil)
	psTok, _ := ps.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, nil)

	if _, err := ps.Validate(context.Background(), rsTok.AccessToken); err == nil {
		t.Error("PS256 issuer must reject an RS256 token")
	}
	if _, err := rs.Validate(context.Background(), psTok.AccessToken); err == nil {
		t.Error("RS256 issuer must reject a PS256 token")
	}

	// alg=none forgery: re-header the RS256 token with alg:none, empty sig.
	parts := strings.Split(rsTok.AccessToken, ".")
	noneHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt"}`))
	forged := noneHdr + "." + parts[1] + "."
	if _, err := rs.Validate(context.Background(), forged); err == nil {
		t.Error("alg=none token must be rejected")
	}
}

func TestRSAJWT_RotationOverlap(t *testing.T) {
	iss := defaultimpl.NewRSAJWTIssuer(defaultimpl.WithRSAAlg("RS256"), defaultimpl.WithRSATokenTTL(time.Hour))
	oldKID := iss.KeyID()
	tok, _ := iss.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, nil)

	newKID, err := iss.RotateKey(nil)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if newKID == oldKID {
		t.Fatal("rotation must produce a new kid")
	}
	// Pre-rotation token still validates (old key is verify-only).
	if _, err := iss.Validate(context.Background(), tok.AccessToken); err != nil {
		t.Errorf("pre-rotation token must stay valid during grace: %v", err)
	}
	// JWKS now carries both keys.
	keys, _ := iss.JWKS(context.Background())
	if len(keys) != 2 {
		t.Errorf("JWKS after rotation = %d keys, want 2", len(keys))
	}
	// Retire the old key → its tokens stop validating, can't retire active.
	if err := iss.RetireKey(newKID); err == nil {
		t.Error("must refuse to retire the active key")
	}
	if err := iss.RetireKey(oldKID); err != nil {
		t.Fatalf("RetireKey(old): %v", err)
	}
	if _, err := iss.Validate(context.Background(), tok.AccessToken); err == nil {
		t.Error("token signed by a retired key must stop validating")
	}
}

func TestRSAJWT_IDTokenAndMetadata(t *testing.T) {
	iss := defaultimpl.NewRSAJWTIssuer(defaultimpl.WithRSAIssuer("idp"), defaultimpl.WithRSAAlg("RS256"))
	idt, err := iss.IssueIDToken(context.Background(), &oidc.IDTokenRequest{
		Subject: "sub-1", Audience: "client-1", Nonce: "n", AMR: []string{"pwd"},
	})
	if err != nil || strings.Count(idt, ".") != 2 {
		t.Fatalf("IssueIDToken: err=%v tok=%q", err, idt)
	}
	jws, err := iss.SignMetadata(context.Background(), map[string]any{"issuer": "idp"})
	if err != nil || jws == "" {
		t.Fatalf("SignMetadata: err=%v", err)
	}
}

func TestRSAJWT_RejectsSmallKey(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewRSAJWTIssuer must panic on a sub-2048-bit key")
		}
	}()
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	defaultimpl.NewRSAJWTIssuer(defaultimpl.WithRSAKey(small))
}

func TestRSAJWT_RejectsUnsupportedAlg(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewRSAJWTIssuer must panic on an unsupported alg")
		}
	}()
	defaultimpl.NewRSAJWTIssuer(defaultimpl.WithRSAAlg("RS512"))
}
