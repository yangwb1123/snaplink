package defaultimpl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/protocols/oidc"
	"github.com/yangwb1123/snaplink/shared/core"
)

type tokenUseIssuer interface {
	oidc.IDTokenIssuer
	Issue(context.Context, *core.Subject, []string) (*core.Token, error)
	Validate(context.Context, string) (*core.TokenClaims, error)
}

// The canonical OpenID Connect Core 1.0 at_hash example: hashing this
// access_token with SHA-256 and base64url-encoding the left-most 128 bits
// yields atHashSHA256. The SHA-512 / left-most-256-bits form (EdDSA's
// hash) of the same token is atHashSHA512.
const (
	specAccessToken = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"
	atHashSHA256    = "77QmUPtjPfzWtF2AnpK9RQ"
	atHashSHA512    = "q7nS86GgvvFaZkzALLWqJYaJIKw2wCDAVfCAsm5CrBM"
)

// TestAccessTokenHash_KnownAnswers locks the helper to spec-derived
// vectors so a wrong hash, a wrong half, or std-vs-url base64 regresses
// visibly. ES256/RS256/PS256 all hash with SHA-256; EdDSA with SHA-512.
func TestAccessTokenHash_KnownAnswers(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		alg  string
		want string
	}{
		{jwtAlgES256, atHashSHA256},
		{jwtAlgRS256, atHashSHA256},
		{jwtAlgPS256, atHashSHA256},
		{jwtAlgEdDSA, atHashSHA512},
	} {
		if got := accessTokenHash(tc.alg, specAccessToken); got != tc.want {
			t.Errorf("accessTokenHash(%s) = %q, want %q", tc.alg, got, tc.want)
		}
	}
}

// TestAccessTokenHash_HalfLengths guards the "left-most half" rule: a
// SHA-256 digest halves to 16 bytes (22 base64url chars), SHA-512 to 32
// bytes (43 chars). A confusion between the two would change the length.
func TestAccessTokenHash_HalfLengths(t *testing.T) {
	t.Parallel()
	if l := len(accessTokenHash(jwtAlgES256, specAccessToken)); l != 22 {
		t.Errorf("SHA-256 at_hash length = %d, want 22 (16-byte half)", l)
	}
	if l := len(accessTokenHash(jwtAlgEdDSA, specAccessToken)); l != 43 {
		t.Errorf("SHA-512 at_hash length = %d, want 43 (32-byte half)", l)
	}
}

// TestAccessTokenHash_EmptyOmits: no access_token => empty string so the
// caller's omitempty drops the claim (at_hash is only REQUIRED alongside
// an access_token).
func TestAccessTokenHash_EmptyOmits(t *testing.T) {
	t.Parallel()
	if got := accessTokenHash(jwtAlgEdDSA, ""); got != "" {
		t.Errorf("empty access_token = %q, want \"\"", got)
	}
}

// TestIssueIDToken_AtHash verifies every default issuer stamps at_hash
// when an access_token is supplied (matched to its own signing alg) and
// omits the claim entirely when it is not — across Ed25519/ECDSA/RSA,
// which share one id_token payload type.
func TestIssueIDToken_AtHash(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		iss  tokenUseIssuer
		alg  string
	}{
		{"ed25519", NewEd25519JWTIssuer(), jwtAlgEdDSA},
		{"ecdsa", NewECDSAJWTIssuer(), jwtAlgES256},
		{"rsa", NewRSAJWTIssuer(), jwtAlgRS256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withAT, err := tc.iss.IssueIDToken(context.Background(), &oidc.IDTokenRequest{
				Subject: "sub", Audience: "aud", AccessToken: specAccessToken,
			})
			if err != nil {
				t.Fatalf("IssueIDToken: %v", err)
			}
			got, ok := idTokenClaims(t, withAT)["at_hash"].(string)
			if !ok || got == "" {
				t.Fatalf("at_hash missing from id_token claims")
			}
			if want := accessTokenHash(tc.alg, specAccessToken); got != want {
				t.Errorf("at_hash = %q, want %q (alg %s)", got, want, tc.alg)
			}
			idClaims, err := tc.iss.Validate(context.Background(), withAT)
			if err != nil || idClaims.TokenUse != core.TokenUseIDToken {
				t.Fatalf("validated ID token use = %q, err=%v", idClaims.TokenUse, err)
			}
			access, err := tc.iss.Issue(context.Background(), &core.Subject{ID: "sub", ClientID: "client"}, []string{"openid"})
			if err != nil {
				t.Fatal(err)
			}
			accessClaims, err := tc.iss.Validate(context.Background(), access.AccessToken)
			if err != nil || accessClaims.TokenUse != core.TokenUseAccessToken {
				t.Fatalf("validated access token use = %q, err=%v", accessClaims.TokenUse, err)
			}

			noAT, err := tc.iss.IssueIDToken(context.Background(), &oidc.IDTokenRequest{
				Subject: "sub", Audience: "aud",
			})
			if err != nil {
				t.Fatalf("IssueIDToken (no access token): %v", err)
			}
			if _, present := idTokenClaims(t, noAT)["at_hash"]; present {
				t.Error("at_hash present though no access_token was supplied")
			}
		})
	}
}

func TestIssueIDToken_BindsSilentRenewalGrant(t *testing.T) {
	t.Parallel()
	details := json.RawMessage(`[{"type":"payment","limit":10}]`)
	for _, tc := range []struct {
		name string
		iss  oidc.IDTokenIssuer
	}{
		{"ed25519", NewEd25519JWTIssuer()},
		{"ecdsa", NewECDSAJWTIssuer()},
		{"rsa", NewRSAJWTIssuer()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := tc.iss.IssueIDToken(context.Background(), &oidc.IDTokenRequest{
				Subject: "sub", Audience: "client", GrantedScopes: []string{"openid", "profile"},
				GrantedResources: []string{"https://api.example"}, AuthorizationDetails: details,
			})
			if err != nil {
				t.Fatal(err)
			}
			claims := idTokenClaims(t, tok)
			if claims["scope"] != "openid profile" {
				t.Fatalf("scope=%v", claims["scope"])
			}
			resources, _ := claims["_resources"].([]any)
			if len(resources) != 1 || resources[0] != "https://api.example" {
				t.Fatalf("resources=%v", claims["_resources"])
			}
			if claims["authorization_details"] == nil {
				t.Fatal("authorization_details missing")
			}
		})
	}
}

func idTokenClaims(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed JWT: %d segments", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}
