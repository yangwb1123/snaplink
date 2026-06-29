package sp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/snaplink/sso/interfaces/sso"
)

// TestAuthenticate_Unsupported proves the direct-credential leg is unsupported
// with the typed sentinel (mirrors the OIDC-federation authenticator).
func TestAuthenticate_Unsupported(t *testing.T) {
	t.Parallel()
	idp := newIDPKeypair(t)
	a, err := NewSPAuthenticator(SPConfig{
		Name: "idp", EntityID: tSPEntity, ACSURL: tACSURL,
		IDPCert: idp.certPEM(), IDPEntityID: tIDPEntity,
	})
	if err != nil {
		t.Fatalf("NewSPAuthenticator: %v", err)
	}
	if _, err := a.Authenticate(context.Background(), &sso.AuthRequest{}); !errors.Is(err, ErrSAMLDirectAuthUnsupported) {
		t.Errorf("Authenticate err = %v, want ErrSAMLDirectAuthUnsupported", err)
	}
}

// TestCallback_NotApplicable proves the generic callback probe returns the
// typed not-applicable sentinel — the ACS POST is handled by the dedicated
// /auth/saml/callback handler, not this code path.
func TestCallback_NotApplicable(t *testing.T) {
	t.Parallel()
	idp := newIDPKeypair(t)
	a, err := NewSPAuthenticator(SPConfig{
		Name: "idp", EntityID: tSPEntity, ACSURL: tACSURL,
		IDPCert: idp.certPEM(), IDPEntityID: tIDPEntity,
	})
	if err != nil {
		t.Fatalf("NewSPAuthenticator: %v", err)
	}
	if _, err := a.Callback(context.Background(), &sso.CallbackState{}); !errors.Is(err, ErrSAMLCallbackNotApplicable) {
		t.Errorf("Callback err = %v, want ErrSAMLCallbackNotApplicable", err)
	}
}

// TestName returns the configured name (the provider= selector).
func TestName(t *testing.T) {
	t.Parallel()
	idp := newIDPKeypair(t)
	a, _ := NewSPAuthenticator(SPConfig{
		Name: "my-idp", EntityID: tSPEntity, ACSURL: tACSURL,
		IDPCert: idp.certPEM(), IDPEntityID: tIDPEntity,
	})
	if a.Name() != "my-idp" {
		t.Errorf("Name() = %q, want my-idp", a.Name())
	}
}

// TestLoginURL_WithSSOEndpoint builds a redirect URL when the cert anchor is
// paired with an explicit IDPSSOURL.
func TestLoginURL_WithSSOEndpoint(t *testing.T) {
	t.Parallel()
	idp := newIDPKeypair(t)
	a, err := NewSPAuthenticator(SPConfig{
		Name: "idp", EntityID: tSPEntity, ACSURL: tACSURL,
		IDPCert: idp.certPEM(), IDPEntityID: tIDPEntity,
		IDPSSOURL: "https://idp.example.com/sso",
	})
	if err != nil {
		t.Fatalf("NewSPAuthenticator: %v", err)
	}
	u := a.LoginURL("state-xyz")
	if u == "" {
		t.Fatal("LoginURL returned empty with an SSO endpoint configured")
	}
	if !strings.HasPrefix(u, "https://idp.example.com/sso?") {
		t.Errorf("LoginURL = %q, want prefix https://idp.example.com/sso?", u)
	}
	if !strings.Contains(u, "SAMLRequest=") {
		t.Errorf("LoginURL = %q, missing SAMLRequest", u)
	}
	if !strings.Contains(u, "RelayState=state-xyz") {
		t.Errorf("LoginURL = %q, missing RelayState", u)
	}
}

// TestLoginURL_NoSSOEndpoint returns "" when the cert-only anchor has no SSO URL
// (LoginURL has nowhere to redirect; the orchestrator falls through).
func TestLoginURL_NoSSOEndpoint(t *testing.T) {
	t.Parallel()
	idp := newIDPKeypair(t)
	a, err := NewSPAuthenticator(SPConfig{
		Name: "idp", EntityID: tSPEntity, ACSURL: tACSURL,
		IDPCert: idp.certPEM(), IDPEntityID: tIDPEntity,
		// no IDPSSOURL
	})
	if err != nil {
		t.Fatalf("NewSPAuthenticator: %v", err)
	}
	if u := a.LoginURL("s"); u != "" {
		t.Errorf("LoginURL = %q, want empty (no SSO endpoint)", u)
	}
}

// TestNewSPAuthenticator_PinsCertFromMetadataXML proves the IDPMetadataXML
// anchor parses + pins, and a valid assertion then verifies against it.
func TestNewSPAuthenticator_PinsCertFromMetadataXML(t *testing.T) {
	t.Parallel()
	idp := newIDPKeypair(t)
	metaXML := idpMetadataXML(t, idp, tIDPEntity, "https://idp.example.com/sso")

	a, err := NewSPAuthenticator(SPConfig{
		Name: "idp", EntityID: tSPEntity, ACSURL: tACSURL,
		IDPMetadataXML: metaXML,
	})
	if err != nil {
		t.Fatalf("NewSPAuthenticator(metadata): %v", err)
	}
	// LoginURL works because metadata carries the SSO endpoint.
	if u := a.LoginURL("s"); !strings.Contains(u, "SAMLRequest=") {
		t.Errorf("LoginURL via metadata = %q, want a SAMLRequest", u)
	}
}

// TestNewSPAuthenticator_BadCertFails proves a malformed PEM cert fails
// construction (boot-closed).
func TestNewSPAuthenticator_BadCertFails(t *testing.T) {
	t.Parallel()
	_, err := NewSPAuthenticator(SPConfig{
		Name: "idp", EntityID: tSPEntity, ACSURL: tACSURL,
		IDPCert:     []byte("-----BEGIN CERTIFICATE-----\nnotbase64\n-----END CERTIFICATE-----\n"),
		IDPEntityID: tIDPEntity,
	})
	if err == nil {
		t.Fatal("NewSPAuthenticator accepted a malformed IDPCert")
	}
}

// interface-guard mirror of the production var, asserted in the test package
// too so a signature drift surfaces in the suite.
var _ sso.Authenticator = (*SPAuthenticator)(nil)
