package remote_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/remote"
	"github.com/yangwb1123/snaplink/shared/core"
)

// jwtIssuer is the slice of the three default JWT issuers the multi-alg
// round-trip exercises: mint a token, and publish the matching JWKS.
type jwtIssuer interface {
	Issue(ctx context.Context, subject *sso.Subject, scopes []string) (*sso.Token, error)
	JWKS(ctx context.Context) ([]core.JWK, error)
}

// jwksServerForIssuer serves the issuer's REAL published JWKS (the same bytes
// the SSO server's /.well-known/jwks.json emits), so the cache parses the
// actual EC/RSA/OKP JWK fields rather than a hand-rolled fixture.
func jwksServerForIssuer(t *testing.T, iss jwtIssuer) (string, func()) {
	t.Helper()
	keys, err := iss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	body, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	srv := httptest.NewServer(mux)
	return srv.URL + "/.well-known/jwks.json", srv.Close
}

// TestRemoteAuth_RoundtripPerAlg proves the remote client verifies a token
// minted by EACH default issuer alg, not just EdDSA — ES256 (the FAPI choice)
// and RS256 must validate, since AWS/Azure-KMS keys cannot be Ed25519 at all.
func TestRemoteAuth_RoundtripPerAlg(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		iss  jwtIssuer
	}{
		{"EdDSA", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(5*time.Minute), defaultimpl.WithEd25519Issuer("remote-test"))},
		{"ES256", defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSATokenTTL(5*time.Minute), defaultimpl.WithECDSAIssuer("remote-test"))},
		{"RS256", defaultimpl.NewRSAJWTIssuer(defaultimpl.WithRSATokenTTL(5*time.Minute), defaultimpl.WithRSAIssuer("remote-test"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url, stop := jwksServerForIssuer(t, tc.iss)
			defer stop()

			cache := remote.NewJWKSCache(url, remote.WithJWKSRefreshInterval(time.Hour))
			defer cache.Close()
			client := remote.NewAuthClient(cache, remote.WithIssuer("remote-test"))

			tok, err := tc.iss.Issue(context.Background(), &sso.Subject{
				ID:     "user-1",
				Claims: map[string]string{"email": "u@example.com"},
			}, []string{"read", "write"})
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}

			subj, err := client.ValidateToken(context.Background(), tok.AccessToken)
			if err != nil {
				t.Fatalf("ValidateToken: %v", err)
			}
			if subj.ID != "user-1" {
				t.Errorf("Subject.ID = %q, want user-1", subj.ID)
			}
			if subj.Attrs["email"] != "u@example.com" {
				t.Errorf("attrs lost: %+v", subj.Attrs)
			}
			if len(subj.Scopes) != 2 {
				t.Errorf("scopes = %v, want 2", subj.Scopes)
			}
		})
	}
}

// TestRemoteAuth_RejectsAlgNone proves an unsigned (alg=none) token is
// rejected — the alg allowlist in security.VerifyCompactJWS never contains
// "none", so it fails before any signature work.
func TestRemoteAuth_RejectsAlgNone(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSATokenTTL(5 * time.Minute))
	url, stop := jwksServerForIssuer(t, iss)
	defer stop()
	cache := remote.NewJWKSCache(url, remote.WithJWKSRefreshInterval(time.Hour))
	defer cache.Close()
	client := remote.NewAuthClient(cache)

	keys, _ := iss.JWKS(context.Background())
	kid := keys[0].Kid

	// Forge an alg=none token carrying the same kid (so the cache resolves a
	// real key) but no signature segment content.
	header := b64urlString(`{"alg":"none","typ":"JWT","kid":"` + kid + `"}`)
	payload := b64urlString(`{"sub":"attacker","exp":` + farFuture() + `}`)
	forged := header + "." + payload + "."

	if _, err := client.ValidateToken(context.Background(), forged); err == nil {
		t.Fatal("alg=none token must be rejected")
	}
}

// TestRemoteAuth_RejectsHS256 proves a symmetric HS256 token is rejected —
// the public-key-as-HMAC-secret confusion attack. The allowlist is
// asymmetric-only, so HS256 never reaches signature verification.
func TestRemoteAuth_RejectsHS256(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewRSAJWTIssuer(defaultimpl.WithRSATokenTTL(5 * time.Minute))
	url, stop := jwksServerForIssuer(t, iss)
	defer stop()
	cache := remote.NewJWKSCache(url, remote.WithJWKSRefreshInterval(time.Hour))
	defer cache.Close()
	client := remote.NewAuthClient(cache)

	keys, _ := iss.JWKS(context.Background())
	kid := keys[0].Kid

	header := b64urlString(`{"alg":"HS256","typ":"JWT","kid":"` + kid + `"}`)
	payload := b64urlString(`{"sub":"attacker","exp":` + farFuture() + `}`)
	// A bogus-but-well-formed signature segment; it never gets verified
	// because the alg gate rejects HS256 first.
	forged := header + "." + payload + "." + strings.Repeat("A", 43)

	if _, err := client.ValidateToken(context.Background(), forged); err == nil {
		t.Fatal("HS256 token must be rejected")
	}
}

// TestRemoteAuth_RejectsWrongKey proves a token signed by one issuer does NOT
// validate against a DIFFERENT issuer's published key of the SAME alg (kid
// matches but the key bytes differ) — the signature check fails.
func TestRemoteAuth_RejectsWrongKey(t *testing.T) {
	t.Parallel()
	// Both issuers are ES256; pin them to the SAME kid so the cache resolves a
	// key for the token, but it is the WRONG (signer-A vs published-B) key.
	signer := defaultimpl.NewECDSAJWTIssuer(
		defaultimpl.WithECDSAKeyID("shared-kid"),
		defaultimpl.WithECDSATokenTTL(5*time.Minute),
	)
	published := defaultimpl.NewECDSAJWTIssuer(
		defaultimpl.WithECDSAKeyID("shared-kid"),
		defaultimpl.WithECDSATokenTTL(5*time.Minute),
	)
	url, stop := jwksServerForIssuer(t, published)
	defer stop()
	cache := remote.NewJWKSCache(url, remote.WithJWKSRefreshInterval(time.Hour))
	defer cache.Close()
	client := remote.NewAuthClient(cache)

	tok, err := signer.Issue(context.Background(), &sso.Subject{ID: "u"}, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := client.ValidateToken(context.Background(), tok.AccessToken); err == nil {
		t.Fatal("token signed by a different key must be rejected")
	}
}

// b64urlString base64url-encodes (no padding) a string segment.
func b64urlString(s string) string { return b64url([]byte(s)) }

// farFuture returns a unix timestamp comfortably in the future, so the only
// reason a forged token fails is the alg gate, not expiry.
func farFuture() string {
	return strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
}
