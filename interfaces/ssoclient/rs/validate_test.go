package rs_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/interfaces/ssoclient/rs"
	"github.com/snaplink/sso/interfaces/ssoclient/rstest"
)

// newTestIssuer starts a fixture issuer + JWKS server and registers cleanup.
func newTestIssuer(t *testing.T) *rstest.Issuer {
	t.Helper()
	iss, err := rstest.NewIssuer()
	if err != nil {
		t.Fatalf("rstest.NewIssuer: %v", err)
	}
	t.Cleanup(iss.Close)
	return iss
}

// newTestConfig wires a Config against iss with a fresh JWKS cache.
func newTestConfig(t *testing.T, iss *rstest.Issuer, expectedAud string) rs.Config {
	t.Helper()
	cache := rs.NewJWKSCache(iss.JWKSURL())
	t.Cleanup(cache.Close)
	return rs.Config{
		Issuer:      iss.URL(),
		JWKSCache:   cache,
		ExpectedAud: expectedAud,
	}
}

func TestValidateToken_HappyPath(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	tok, err := iss.MintAccessToken(map[string]any{
		"sub":       "user-1",
		"aud":       "api://orders",
		"client_id": "client-1",
		"scope":     "orders:read orders:write",
	})
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	cfg := newTestConfig(t, iss, "api://orders")

	claims, err := rs.ValidateToken(context.Background(), tok, cfg)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", claims.Subject)
	}
	if !claims.HasAudience("api://orders") {
		t.Errorf("HasAudience(api://orders) = false, aud = %v", claims.Audience)
	}
	if got := claims.Scopes(); len(got) != 2 || got[0] != "orders:read" || got[1] != "orders:write" {
		t.Errorf("Scopes() = %v, want [orders:read orders:write]", got)
	}
}

func TestValidateToken_Expired(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	past := time.Now().Add(-time.Hour)
	tok, err := iss.MintAccessToken(map[string]any{
		"sub": "user-1",
		"iat": past.Unix(),
		"exp": past.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	cfg := newTestConfig(t, iss, "")

	_, err = rs.ValidateToken(context.Background(), tok, cfg)
	if !errors.Is(err, rs.ErrTokenExpired) {
		t.Fatalf("err = %v, want ErrTokenExpired", err)
	}
}

func TestValidateToken_WrongAudience(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	tok, err := iss.MintAccessToken(map[string]any{
		"sub": "user-1",
		"aud": "api://billing",
	})
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	cfg := newTestConfig(t, iss, "api://orders")

	_, err = rs.ValidateToken(context.Background(), tok, cfg)
	if !errors.Is(err, rs.ErrAudienceMismatch) {
		t.Fatalf("err = %v, want ErrAudienceMismatch", err)
	}
}

func TestValidateToken_WrongIssuer(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	tok, err := iss.MintAccessToken(map[string]any{"sub": "user-1"})
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	cfg := newTestConfig(t, iss, "")
	cfg.Issuer = "https://not-the-issuer.example"

	_, err = rs.ValidateToken(context.Background(), tok, cfg)
	if !errors.Is(err, rs.ErrIssuerMismatch) {
		t.Fatalf("err = %v, want ErrIssuerMismatch", err)
	}
}

func TestValidateToken_MissingConfig(t *testing.T) {
	t.Parallel()
	if _, err := rs.ValidateToken(context.Background(), "x.y.z", rs.Config{}); !errors.Is(err, rs.ErrConfig) {
		t.Fatalf("missing Issuer: err = %v, want ErrConfig", err)
	}
	if _, err := rs.ValidateToken(context.Background(), "x.y.z", rs.Config{Issuer: "https://as.test"}); !errors.Is(err, rs.ErrConfig) {
		t.Fatalf("missing JWKSCache: err = %v, want ErrConfig", err)
	}
}

// craftCompactJWS assembles a 3-segment JWS from raw header/payload maps and
// an arbitrary (not necessarily valid) signature — for exercising gates that
// must fire BEFORE any signature verification happens.
func craftCompactJWS(t *testing.T, header, payload map[string]any, sig []byte) string {
	t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// TestValidateToken_AlgNoneRejected proves the alg allowlist gate fires
// before any signature work: a header naming the real published kid but
// alg=none (an "unsigned JWT") must never validate, even though the kid
// resolves to a real key.
func TestValidateToken_AlgNoneRejected(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	// A legitimately minted token to recover a real, published kid.
	real, err := iss.MintAccessToken(map[string]any{"sub": "user-1"})
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	realHeader := real[:strings.IndexByte(real, '.')]
	hb, err := base64.RawURLEncoding.DecodeString(realHeader)
	if err != nil {
		t.Fatal(err)
	}
	var h struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &h); err != nil {
		t.Fatal(err)
	}

	forged := craftCompactJWS(t,
		map[string]any{"alg": "none", "typ": "at+jwt", "kid": h.Kid},
		map[string]any{"sub": "attacker", "iss": iss.URL(), "exp": time.Now().Add(time.Hour).Unix()},
		[]byte("x"),
	)
	cfg := newTestConfig(t, iss, "")

	_, err = rs.ValidateToken(context.Background(), forged, cfg)
	if !errors.Is(err, rs.ErrSignatureInvalid) {
		t.Fatalf("alg=none err = %v, want ErrSignatureInvalid", err)
	}
}

// TestValidateToken_WrongTypRejected proves a structurally valid JWT with a
// non-access-token typ (e.g. an id token) is rejected before signature work.
func TestValidateToken_WrongTypRejected(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	idToken, err := iss.JWT.SignJWT(context.Background(), "JWT", map[string]any{
		"iss": iss.URL(),
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	cfg := newTestConfig(t, iss, "")

	_, err = rs.ValidateToken(context.Background(), idToken, cfg)
	if !errors.Is(err, rs.ErrTokenTypeMismatch) {
		t.Fatalf("err = %v, want ErrTokenTypeMismatch", err)
	}
}
