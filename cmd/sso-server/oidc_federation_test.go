package main

import (
	"testing"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/authenticators"
)

func TestBuildAuthenticators_OIDCFederationWiresProviderByName(t *testing.T) {
	cfg := &config.Config{}
	cfg.Authenticators.OIDCFederation = []*config.OIDCFederationAuthConfig{
		{
			Name:                  "google",
			AuthorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
			TokenEndpoint:         "https://oauth2.googleapis.com/token",
			UserinfoEndpoint:      "https://openidconnect.googleapis.com/v1/userinfo",
			ClientID:              "google-client",
			ClientSecret:          "google-secret",
			RedirectURI:           "https://as.example/callback",
			Scopes:                []string{"openid", "profile", "email"},
		},
		{
			Name:                  "github",
			AuthorizationEndpoint: "https://github.com/login/oauth/authorize",
			TokenEndpoint:         "https://github.com/login/oauth/access_token",
			UserinfoEndpoint:      "https://api.github.com/user",
			ClientID:              "github-client",
			ClientSecret:          "github-secret",
			RedirectURI:           "https://as.example/callback",
			SubjectFieldOverride:  "id",
		},
	}

	auths, _, _, _, _ := buildAuthenticators(cfg, quietLogger(), nil, nil)

	seen := map[string]bool{}
	for _, a := range auths {
		if _, ok := a.(*authenticators.OIDCFederationAuthenticator); ok {
			seen[a.Name()] = true
		}
	}
	if !seen["google"] || !seen["github"] {
		t.Fatalf("expected both google + github wired, got %v", seen)
	}
}

func TestBuildAuthenticators_OIDCFederationSkipsInvalidEntries(t *testing.T) {
	cfg := &config.Config{}
	cfg.Authenticators.OIDCFederation = []*config.OIDCFederationAuthConfig{
		{
			Name: "missing-everything-else",
		},
		{
			Name:                  "valid",
			AuthorizationEndpoint: "https://idp.example/authorize",
			TokenEndpoint:         "https://idp.example/token",
			ClientID:              "x",
			ClientSecret:          "y",
			RedirectURI:           "https://as.example/cb",
		},
		nil, // defensive: nil entry must not panic.
	}

	auths, _, _, _, _ := buildAuthenticators(cfg, quietLogger(), nil, nil)

	seen := map[string]bool{}
	for _, a := range auths {
		if _, ok := a.(*authenticators.OIDCFederationAuthenticator); ok {
			seen[a.Name()] = true
		}
	}
	if seen["missing-everything-else"] {
		t.Fatal("invalid entry should have been skipped")
	}
	if !seen["valid"] {
		t.Fatal("valid entry must have been wired")
	}
}
