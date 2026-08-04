package rs_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rstest"
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

// TestValidateToken_ServingRegionGate is the decision-3 local-mode matrix:
// configured allowlist + in-set token passes; out-of-set OR missing claim
// fails closed with ErrServingRegionMismatch; empty config skips the gate
// (byte-identical). The typed projection (Claims.ServingRegion +
// HasServingRegion) is pinned here too.
func TestValidateToken_ServingRegionGate(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	mint := func(region string) string {
		t.Helper()
		claims := map[string]any{"sub": "user-1", "aud": "api://orders"}
		if region != "" {
			claims["serving_region"] = region
		}
		tok, err := iss.MintAccessToken(claims)
		if err != nil {
			t.Fatalf("MintAccessToken: %v", err)
		}
		return tok
	}
	cfg := newTestConfig(t, iss, "api://orders")

	// In-set region + configured allowlist -> valid, typed claim populated.
	inSet := cfg
	inSet.AllowedServingRegions = []string{"eu-west-1", "us-east-1"}
	claims, err := rs.ValidateToken(context.Background(), mint("eu-west-1"), inSet)
	if err != nil {
		t.Fatalf("ValidateToken(in-set): %v", err)
	}
	if claims.ServingRegion != "eu-west-1" || !claims.HasServingRegion() {
		t.Errorf("ServingRegion = %q, HasServingRegion = %v", claims.ServingRegion, claims.HasServingRegion())
	}

	// Out-of-set region -> governance sentinel.
	outOfSet := cfg
	outOfSet.AllowedServingRegions = []string{"eu-west-1"}
	_, err = rs.ValidateToken(context.Background(), mint("us-east-1"), outOfSet)
	if !errors.Is(err, rs.ErrServingRegionMismatch) {
		t.Fatalf("err = %v, want ErrServingRegionMismatch (out-of-set)", err)
	}

	// Missing claim + configured allowlist -> FAIL CLOSED (no verifiable
	// provenance in a region-pinned deployment).
	_, err = rs.ValidateToken(context.Background(), mint(""), outOfSet)
	if !errors.Is(err, rs.ErrServingRegionMismatch) {
		t.Fatalf("err = %v, want ErrServingRegionMismatch (missing claim)", err)
	}

	// Empty config -> gate skipped; both in-set and claim-less tokens pass.
	claims, err = rs.ValidateToken(context.Background(), mint("us-east-1"), cfg)
	if err != nil {
		t.Fatalf("ValidateToken(unconfigured, with claim): %v", err)
	}
	if claims.ServingRegion != "us-east-1" {
		t.Errorf("ServingRegion = %q, want us-east-1", claims.ServingRegion)
	}
	if _, err = rs.ValidateToken(context.Background(), mint(""), cfg); err != nil {
		t.Fatalf("ValidateToken(unconfigured, no claim): %v", err)
	}
	// HasServingRegionIn never reports a claim-less token in the set.
	if claims.HasServingRegionIn([]string{"eu-west-1"}) {
		t.Errorf("HasServingRegionIn(eu-west-1) = true for a us-east-1 token")
	}
}

// TestValidateToken_ServingRegionGateRunsLast pins the gate order: a
// garbage/expired token still reports its higher-priority sentinel, so the
// region gate can never be probed with an invalid token.
func TestValidateToken_ServingRegionGateRunsLast(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	past := time.Now().Add(-time.Hour)
	tok, err := iss.MintAccessToken(map[string]any{
		"sub":            "user-1",
		"exp":            past.Add(time.Minute).Unix(),
		"serving_region": "eu-west-1",
	})
	if err != nil {
		t.Fatalf("MintAccessToken: %v", err)
	}
	cfg := newTestConfig(t, iss, "")
	cfg.AllowedServingRegions = []string{"us-east-1"}

	_, err = rs.ValidateToken(context.Background(), tok, cfg)
	if !errors.Is(err, rs.ErrTokenExpired) {
		t.Fatalf("err = %v, want ErrTokenExpired (expiry outranks region gate)", err)
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
