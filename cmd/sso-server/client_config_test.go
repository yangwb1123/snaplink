package main

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildstore"
	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// TestBuildApp_ClientYAMLPropagatesAllFields covers the regression
// where cmd's ClientConfig used to mirror only ~9 of the ~25 SDK
// Client fields, silently dropping SDK features (RFC 8707 resource
// allowlist, RFC 9101 JAR JWKS, OIDC pairwise sub, FAPI 2.0
// require_par / require_signed_request_object, OIDC FCL, per-client
// TTLs) when operators configured them via YAML.
func TestBuildApp_ClientYAMLPropagatesAllFields(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Clients = []config.ClientConfig{
		{
			ID:                               "wide-client",
			Secret:                           "s3cret",
			Name:                             "Wide Client",
			RedirectURIs:                     []string{"https://rp.example/cb"},
			AllowedScopes:                    []string{"openid", "profile"},
			AllowedAuthenticators:            []string{"password", "webauthn"},
			LoginPageURI:                     "https://login.example/authorize",
			TokenStrategy:                    "jwt",
			Active:                           true,
			TenantID:                         "acme",
			RequirePKCE:                      true,
			AllowedResources:                 []string{"https://api.example/v1"},
			PostLogoutRedirectURIs:           []string{"https://rp.example/logout"},
			AllowedAuthorizationDetailsTypes: []string{"payment_initiation"},
			RefreshTokenTTL:                  24 * time.Hour,
			AccessTokenTTL:                   15 * time.Minute,
			AllowedPKCEMethods:               []string{"S256"},
			RequireSignedRequestObject:       true,
			RequirePAR:                       true,
			AllowedRequestURIs:               []string{"https://rp.example/jar"},
			DeviceCodeTTL:                    30 * time.Minute,
			DeviceCodePollInterval:           5 * time.Second,
			UserinfoSignedResponseAlg:        "EdDSA",
			BackchannelLogoutURI:             "https://rp.example/bcl",
			SubjectType:                      "pairwise",
			SectorIdentifierURI:              "https://sector.example",
			FrontchannelLogoutURI:            "https://rp.example/fcl",
			JWKS: []config.ClientJWK{
				{Kty: "OKP", Crv: "Ed25519", Kid: "rp-1", X: "PUB-X-VAL"},
			},
			SkipConsent:            true,
			ConsentRefreshInterval: 90 * 24 * time.Hour,
		},
	}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()

	got, err := a.clientStore.Get(context.Background(), "wide-client")
	if err != nil {
		t.Fatalf("clientStore.Get: %v", err)
	}

	checks := []struct {
		name string
		ok   bool
	}{
		{"RequirePKCE", got.RequirePKCE == true},
		{"LoginPageURI", got.LoginPageURI == "https://login.example/authorize"},
		{"AllowedResources len", len(got.AllowedResources) == 1 && got.AllowedResources[0] == "https://api.example/v1"},
		{"PostLogoutRedirectURIs", len(got.PostLogoutRedirectURIs) == 1},
		{"AllowedAuthorizationDetailsTypes", len(got.AllowedAuthorizationDetailsTypes) == 1},
		{"RefreshTokenTTL", got.RefreshTokenTTL == 24*time.Hour},
		{"AccessTokenTTL", got.AccessTokenTTL == 15*time.Minute},
		{"AllowedPKCEMethods", len(got.AllowedPKCEMethods) == 1 && got.AllowedPKCEMethods[0] == "S256"},
		{"RequireSignedRequestObject", got.RequireSignedRequestObject == true},
		{"RequirePAR", got.RequirePAR == true},
		{"AllowedRequestURIs", len(got.AllowedRequestURIs) == 1},
		{"DeviceCodeTTL", got.DeviceCodeTTL == 30*time.Minute},
		{"DeviceCodePollInterval", got.DeviceCodePollInterval == 5*time.Second},
		{"UserinfoSignedResponseAlg", got.UserinfoSignedResponseAlg == "EdDSA"},
		{"BackchannelLogoutURI", got.BackchannelLogoutURI == "https://rp.example/bcl"},
		{"SubjectType", got.SubjectType == "pairwise"},
		{"SectorIdentifierURI", got.SectorIdentifierURI == "https://sector.example"},
		{"FrontchannelLogoutURI", got.FrontchannelLogoutURI == "https://rp.example/fcl"},
		{"JWKS len", len(got.JWKS) == 1},
		{"JWKS Kid", len(got.JWKS) == 1 && got.JWKS[0].Kid == "rp-1"},
		{"JWKS X", len(got.JWKS) == 1 && got.JWKS[0].X == "PUB-X-VAL"},
		{"SkipConsent", got.SkipConsent == true},
		{"ConsentRefreshInterval", got.ConsentRefreshInterval == 90*24*time.Hour},
	}
	for _, c := range checks {
		if !c.ok {
			t.Errorf("client field %s did not propagate from YAML", c.name)
		}
	}
}

func TestConvertClientJWKs_PreservesEveryField(t *testing.T) {
	t.Parallel()
	in := []config.ClientJWK{
		{Kty: "RSA", Kid: "rsa-1", Use: "sig", Alg: "RS256", N: "MOD", E: "EXP"},
		{Kty: "OKP", Kid: "ed-1", Use: "sig", Alg: "EdDSA", Crv: "Ed25519", X: "PUB"},
	}
	out := serverbuildstore.ConvertClientJWKs(in)
	if len(out) != 2 {
		t.Fatalf("len = %d want 2", len(out))
	}

	wantRSA := sso.JWK{Kty: "RSA", Kid: "rsa-1", Use: "sig", Alg: "RS256", N: "MOD", E: "EXP"}
	if out[0] != wantRSA {
		t.Fatalf("RSA round-trip mismatch:\n got %+v\nwant %+v", out[0], wantRSA)
	}
	wantOKP := sso.JWK{Kty: "OKP", Kid: "ed-1", Use: "sig", Alg: "EdDSA", Crv: "Ed25519", X: "PUB"}
	if out[1] != wantOKP {
		t.Fatalf("OKP round-trip mismatch:\n got %+v\nwant %+v", out[1], wantOKP)
	}
}

func TestConvertClientJWKs_EmptyReturnsNil(t *testing.T) {
	t.Parallel()
	if got := serverbuildstore.ConvertClientJWKs(nil); got != nil {
		t.Fatalf("nil input: got %v want nil", got)
	}
	if got := serverbuildstore.ConvertClientJWKs([]config.ClientJWK{}); got != nil {
		t.Fatalf("empty input: got %v want nil", got)
	}
}
