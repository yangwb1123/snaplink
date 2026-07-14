package authenticators

import (
	"context"
	"testing"

	"github.com/snaplink/sso/domains/authenticators/acrmap"
	"github.com/snaplink/sso/interfaces/sso"
)

// var _ compile-time-asserts that the reference acrmap.PatternACRMapper
// satisfies ACRMapper structurally — acrmap deliberately imports nothing from
// this package (see its doc), so this is the one place that checks the shapes
// actually line up.
var _ ACRMapper = (*acrmap.PatternACRMapper)(nil)

// fakeACRMapper is a real (non-mock) test double — MapACR is one line, so a
// hand-written implementation is simpler than a generated mock (AGENTS.md: no
// mocks where a real implementation is simple).
type fakeACRMapper struct {
	gotUpstream string
	out         string
}

func (f *fakeACRMapper) MapACR(upstreamACR string) string {
	f.gotUpstream = upstreamACR
	return f.out
}

func TestOIDCFederation_NilACRMapperIsByteIdenticalToNoMapper(t *testing.T) {
	t.Parallel()
	idp := newFakeIdP(t)
	// No WithACRMapper option passed at all — AchievedACR must stay unset,
	// exactly like before ACRMapper existed.
	auth := newOIDCFedForTest(t, idp)

	result, err := auth.Callback(context.Background(), &sso.CallbackState{
		Code:  idp.expectedCode,
		State: "s",
	})
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if result.AchievedACR != "" {
		t.Fatalf("nil ACRMapper must leave AchievedACR unset, got %q", result.AchievedACR)
	}
}

func TestOIDCFederation_WiredACRMapperMapsUpstreamClaim(t *testing.T) {
	t.Parallel()
	idp := newFakeIdP(t)
	idp.userinfoResponse = map[string]any{
		"sub": "alice@example.com",
		"acr": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
	}
	mapper := &fakeACRMapper{out: "urn:mace:incommon:iap:silver"}
	auth, err := NewOIDCFederationAuthenticator(OIDCFederationConfig{
		Name:                  "test-idp",
		AuthorizationEndpoint: idp.srv.URL + "/authorize",
		TokenEndpoint:         idp.srv.URL + "/token",
		UserinfoEndpoint:      idp.srv.URL + "/userinfo",
		ClientID:              idp.expectedClient,
		ClientSecret:          idp.expectedSecret,
		RedirectURI:           "https://as.example/callback",
	}, WithACRMapper(mapper))
	if err != nil {
		t.Fatalf("NewOIDCFederationAuthenticator: %v", err)
	}

	result, err := auth.Callback(context.Background(), &sso.CallbackState{
		Code:  idp.expectedCode,
		State: "s",
	})
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if result.AchievedACR != "urn:mace:incommon:iap:silver" {
		t.Fatalf("AchievedACR = %q, want mapper output", result.AchievedACR)
	}
	if mapper.gotUpstream != "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" {
		t.Fatalf("mapper called with %q, want the raw upstream acr claim", mapper.gotUpstream)
	}
}

func TestOIDCFederation_WiredACRMapperUnmappedWithNoDefaultIsEmptyNotError(t *testing.T) {
	t.Parallel()
	idp := newFakeIdP(t)
	idp.userinfoResponse = map[string]any{
		"sub": "alice@example.com",
		"acr": "urn:some:unrecognized:value",
	}
	// fakeACRMapper.out defaults to "" — simulates a cascade with no matching
	// rule and no configured default.
	mapper := &fakeACRMapper{}
	auth, err := NewOIDCFederationAuthenticator(OIDCFederationConfig{
		Name:                  "test-idp",
		AuthorizationEndpoint: idp.srv.URL + "/authorize",
		TokenEndpoint:         idp.srv.URL + "/token",
		UserinfoEndpoint:      idp.srv.URL + "/userinfo",
		ClientID:              idp.expectedClient,
		ClientSecret:          idp.expectedSecret,
		RedirectURI:           "https://as.example/callback",
	}, WithACRMapper(mapper))
	if err != nil {
		t.Fatalf("NewOIDCFederationAuthenticator: %v", err)
	}

	result, err := auth.Callback(context.Background(), &sso.CallbackState{
		Code:  idp.expectedCode,
		State: "s",
	})
	if err != nil {
		t.Fatalf("unmapped acr with no default must NOT fail Callback: %v", err)
	}
	if result.AchievedACR != "" {
		t.Fatalf("AchievedACR = %q, want \"\" (unmapped, no default)", result.AchievedACR)
	}
}

func TestOIDCFederation_WiredACRMapperNoUpstreamClaimMapsEmptyString(t *testing.T) {
	t.Parallel()
	idp := newFakeIdP(t)
	// Default userinfoResponse (sub/email/name/email_verified) carries no
	// "acr" entry at all.
	mapper := &fakeACRMapper{out: "should-not-be-returned"}
	auth, err := NewOIDCFederationAuthenticator(OIDCFederationConfig{
		Name:                  "test-idp",
		AuthorizationEndpoint: idp.srv.URL + "/authorize",
		TokenEndpoint:         idp.srv.URL + "/token",
		UserinfoEndpoint:      idp.srv.URL + "/userinfo",
		ClientID:              idp.expectedClient,
		ClientSecret:          idp.expectedSecret,
		RedirectURI:           "https://as.example/callback",
	}, WithACRMapper(mapper))
	if err != nil {
		t.Fatalf("NewOIDCFederationAuthenticator: %v", err)
	}

	_, err = auth.Callback(context.Background(), &sso.CallbackState{
		Code:  idp.expectedCode,
		State: "s",
	})
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if mapper.gotUpstream != "" {
		t.Fatalf("mapper.MapACR called with %q, want \"\" (no acr claim present)", mapper.gotUpstream)
	}
}
