package defaultimpl_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oidc"
)

// servingRegionIssuer is the subset of issuer behavior the serving-region
// tests exercise uniformly across Ed25519 / ECDSA / RSA.
type servingRegionIssuer interface {
	oidc.IDTokenIssuer
	Issue(context.Context, *sso.Subject, []string) (*sso.Token, error)
	Validate(context.Context, string) (*sso.TokenClaims, error)
}

// servingRegionIssuers returns one of each signer so the serving_region
// claim projection is pinned for every issuer — the three ID-issuer
// literals are per-issuer drift points, so a test must pin all three.
func servingRegionIssuers(t *testing.T) map[string]servingRegionIssuer {
	t.Helper()
	return map[string]servingRegionIssuer{
		"ed25519": defaultimpl.NewEd25519JWTIssuer(
			defaultimpl.WithEd25519Issuer("test-iss"),
			defaultimpl.WithEd25519TokenTTL(5*time.Minute),
		),
		"ecdsa": defaultimpl.NewECDSAJWTIssuer(
			defaultimpl.WithECDSAIssuer("test-iss"),
			defaultimpl.WithECDSATokenTTL(5*time.Minute),
		),
		"rsa": defaultimpl.NewRSAJWTIssuer(
			defaultimpl.WithRSAIssuer("test-iss"),
			defaultimpl.WithRSATokenTTL(5*time.Minute),
		),
	}
}

// decodePayload returns the decoded JSON payload of a compact JWS.
func decodePayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a 3-segment JWS: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload decode: %v", err)
	}
	var pl map[string]any
	if err := json.Unmarshal(raw, &pl); err != nil {
		t.Fatalf("payload parse: %v", err)
	}
	return pl
}

// TestServingRegion_AccessTokenClaim pins decision 1 for every signer:
// a Subject.ServingRegion is stamped as the wire `serving_region` claim and
// round-trips through Validate into TokenClaims.ServingRegion; empty input
// omits the claim entirely (byte-identical to pre-region builds).
func TestServingRegion_AccessTokenClaim(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for name, iss := range servingRegionIssuers(t) {
		t.Run(name, func(t *testing.T) {
			tok, err := iss.Issue(ctx, &sso.Subject{
				ID: "user-1", ClientID: "client-1",
				ServingRegion: "eu-west-1",
			}, []string{"read"})
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			if got := decodePayload(t, tok.AccessToken)["serving_region"]; got != "eu-west-1" {
				t.Errorf("serving_region = %v, want eu-west-1", got)
			}
			claims, err := iss.Validate(ctx, tok.AccessToken)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if claims.ServingRegion != "eu-west-1" {
				t.Errorf("TokenClaims.ServingRegion = %q, want eu-west-1", claims.ServingRegion)
			}

			// Empty input -> claim omitted on the wire AND in the validated view.
			tokEmpty, err := iss.Issue(ctx, &sso.Subject{ID: "user-1", ClientID: "client-1"}, []string{"read"})
			if err != nil {
				t.Fatalf("Issue(empty region): %v", err)
			}
			if _, present := decodePayload(t, tokEmpty.AccessToken)["serving_region"]; present {
				t.Error("serving_region present despite empty Subject.ServingRegion")
			}
			claimsEmpty, err := iss.Validate(ctx, tokEmpty.AccessToken)
			if err != nil {
				t.Fatalf("Validate(empty region): %v", err)
			}
			if claimsEmpty.ServingRegion != "" {
				t.Errorf("TokenClaims.ServingRegion = %q, want empty", claimsEmpty.ServingRegion)
			}
		})
	}
}

// TestServingRegion_IDTokenClaim pins the OIDC side for every signer: the
// ID-token payload struct carries the first-class field (never an `ext`
// entry), so OIDC §5.5 projection can never drop it.
func TestServingRegion_IDTokenClaim(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for name, iss := range servingRegionIssuers(t) {
		t.Run(name, func(t *testing.T) {
			tok, err := iss.IssueIDToken(ctx, &oidc.IDTokenRequest{
				Subject:       "user-1",
				Audience:      "client-1",
				ServingRegion: "eu-west-1",
			})
			if err != nil {
				t.Fatalf("IssueIDToken: %v", err)
			}
			if got := decodePayload(t, tok)["serving_region"]; got != "eu-west-1" {
				t.Errorf("id_token serving_region = %v, want eu-west-1", got)
			}

			tokEmpty, err := iss.IssueIDToken(ctx, &oidc.IDTokenRequest{Subject: "user-1", Audience: "client-1"})
			if err != nil {
				t.Fatalf("IssueIDToken(empty region): %v", err)
			}
			if _, present := decodePayload(t, tokEmpty)["serving_region"]; present {
				t.Error("id_token serving_region present despite empty request field")
			}
		})
	}
}
