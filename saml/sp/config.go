// Package sp implements the SAML 2.0 Service Provider (SP) side: this SSO
// server CONSUMES an upstream SAML Identity Provider's (IdP) assertion to
// authenticate a user, the mirror image of authenticators/oidc_federation.go
// (which consumes an upstream OAuth/OIDC provider). The SP never signs an
// assertion — it VALIDATES one the IdP signed (it may optionally sign its own
// AuthnRequest). All assertion validation runs through crewjam/saml's
// XML-signature-wrapping (XSW) resistant ParseResponse against an IdP signing
// certificate PINNED at boot.
package sp

import (
	"errors"
	"fmt"
	"time"
)

// DefaultReplayStoreSize bounds the in-memory AssertionID replay cache when
// SPConfig.ReplayStoreSize is unset. 10k entries at one assertion-lifetime
// each is plenty for a single replica's dedup window without unbounded growth.
const DefaultReplayStoreSize = 10000

// DefaultTimeout caps the IdP-metadata fetch performed at construction when
// SPConfig.Timeout is unset.
const DefaultTimeout = 10 * time.Second

// SPConfig describes one upstream SAML IdP this server federates to. One
// SPConfig yields one SPAuthenticator; an operator may wire several (one per
// upstream IdP), selected at /auth/login by Name.
type SPConfig struct {
	// Name is the authenticator name + the value clients pass in
	// provider=<name> to choose this IdP at /auth/login. Also the RelayState
	// provider hint the ACS callback uses to dispatch a POSTed assertion back
	// to the right SPAuthenticator. REQUIRED.
	Name string

	// EntityID is THIS SP's SAML entity identifier — the audience the IdP must
	// stamp into the assertion's AudienceRestriction. A mismatch is one of the
	// validation failures collapsed to a single error (an assertion minted for
	// a different SP must not authenticate here). REQUIRED.
	EntityID string

	// ACSURL is THIS SP's Assertion Consumer Service URL — where the IdP POSTs
	// the SAML Response. The IdP must stamp it into
	// SubjectConfirmationData.Recipient; a mismatch is rejected. It is also the
	// Recipient/Destination crewjam checks. REQUIRED.
	ACSURL string

	// IDP TRUST ANCHOR. Exactly ONE of the three forms below supplies the
	// pinned IdP signing certificate(s) used to verify the assertion XML-DSig.
	// The certificate NEVER comes from the assertion itself (that is the XSW
	// attack); it is pinned here at boot. At least one form is REQUIRED.
	//
	//   IDPMetadataURL  — fetched once at construction (SAML metadata XML);
	//                     carries the signing cert(s) AND the SSO endpoint
	//                     LoginURL redirects to.
	//   IDPMetadataXML  — the same metadata inline (air-gapped / pre-fetched).
	//   IDPCert         — a bare PEM signing certificate. Validation-only:
	//                     without metadata there is no SSO endpoint, so
	//                     LoginURL needs IDPSSOURL set explicitly.
	IDPMetadataURL string
	IDPMetadataXML []byte
	IDPCert        []byte // PEM-encoded X.509 IdP signing certificate

	// IDPSSOURL is the IdP's HTTP-Redirect SSO endpoint. Only consulted when
	// the IdP trust anchor is IDPCert (metadata already carries the endpoint).
	// Empty with IDPCert ⇒ LoginURL returns an error (no place to redirect).
	IDPSSOURL string

	// IDPEntityID is the IdP's SAML entity identifier, the value the IdP stamps
	// as the assertion Issuer. Only needed (and REQUIRED) when the trust anchor
	// is IDPCert — the metadata forms carry it. crewjam checks the assertion
	// Issuer against this, so a mismatch is rejected.
	IDPEntityID string

	// SPPrivateKey, when set (PEM RSA/EC), signs THIS SP's AuthnRequest and
	// decrypts EncryptedAssertions the IdP encrypts to the SP. OPTIONAL — most
	// IdPs accept unsigned AuthnRequests and return plaintext (TLS-protected)
	// assertions.
	SPPrivateKey []byte

	// SPCert is the X.509 certificate (PEM) matching SPPrivateKey, published in
	// SP metadata + used as the signing/decryption cert. Required only when
	// SPPrivateKey is set.
	SPCert []byte

	// SignAuthnRequests, when true (and SPPrivateKey is set), signs the
	// outbound AuthnRequest (RFC: WantAuthnRequestsSigned IdPs). Default false.
	SignAuthnRequests bool

	// SPSLOURL is THIS SP's own Single Logout Service URL — where the upstream
	// IdP redirects/POSTs a LogoutRequest to log this server out, and the
	// Issuer/Destination context crewjam stamps when this SP builds an outbound
	// LogoutRequest/LogoutResponse. OPTIONAL: empty disables the SLO helpers
	// (LogoutURL / BuildLogoutResponse return ""/error). Set it to participate
	// in Single Logout.
	SPSLOURL string

	// IDPSLOURL is the UPSTREAM IdP's Single Logout Service endpoint (HTTP-
	// Redirect), where SP-initiated LogoutRequests and the LogoutResponse this
	// SP returns are sent. When the IdP trust anchor is metadata that already
	// advertises a SingleLogoutService, that endpoint is used and this may be
	// left empty; with the bare-cert anchor (or metadata lacking an SLO
	// endpoint) it MUST be set for SP-initiated logout. The IdP signing cert
	// pinned for assertions is REUSED to validate inbound IdP LogoutRequests —
	// SLO adds no second trust anchor.
	IDPSLOURL string

	// NameIDFormat is the requested NameIDPolicy format on the AuthnRequest
	// (e.g. urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress). Empty =
	// let the IdP choose.
	NameIDFormat string

	// AttributeMapping renames inbound assertion attributes onto the
	// AuthResult.Attributes keys this server uses. Key = the SAML Attribute
	// Name (or FriendlyName) as the IdP emits it; value = the local attribute
	// key. Unmapped attributes pass through under their SAML Name. Empty = pass
	// every attribute through verbatim.
	AttributeMapping map[string]string

	// AllowIDPInitiated permits IdP-initiated SSO (an unsolicited response with
	// an empty InResponseTo). The ACS is stateless (it keeps no AuthnRequest-ID
	// store), so this knob controls the strongest correlation a stateless ACS
	// can enforce, NOT an exact request-ID match:
	//
	//   false (default, safer) → the response MUST carry a non-empty
	//          InResponseTo; an unsolicited (IdP-initiated) response is
	//          rejected. This ties acceptance to the SP having issued *some*
	//          request, without matching the exact ID.
	//   true                   → unsolicited responses are accepted (for IdPs
	//          that genuinely push assertions).
	//
	// In BOTH modes the signature (pinned cert), audience, recipient, expiry,
	// single-assertion, and replay checks apply. An operator needing exact
	// InResponseTo correlation supplies a request-ID-tracking front end (out of
	// scope for this stateless build).
	AllowIDPInitiated bool

	// ReplayStoreSize bounds the in-memory AssertionID dedup cache. Zero ⇒
	// DefaultReplayStoreSize.
	ReplayStoreSize int

	// Timeout caps the IDPMetadataURL fetch at construction. Zero ⇒
	// DefaultTimeout. Ignored for the inline / cert trust-anchor forms.
	Timeout time.Duration
}

// Validate checks the required fields + the trust-anchor invariant (exactly
// one IdP cert source, and the IDPCert form needs its companion fields). It
// does NOT perform the metadata fetch — NewSPAuthenticator does that.
func (c *SPConfig) Validate() error {
	if c.Name == "" {
		return errors.New("saml/sp: Name required")
	}
	if c.EntityID == "" {
		return errors.New("saml/sp: EntityID required")
	}
	if c.ACSURL == "" {
		return errors.New("saml/sp: ACSURL required")
	}

	sources := 0
	if c.IDPMetadataURL != "" {
		sources++
	}
	if len(c.IDPMetadataXML) > 0 {
		sources++
	}
	if len(c.IDPCert) > 0 {
		sources++
	}
	switch {
	case sources == 0:
		return errors.New("saml/sp: an IdP trust anchor is required (IDPMetadataURL, IDPMetadataXML, or IDPCert)")
	case sources > 1:
		// More than one anchor is ambiguous about which cert is pinned — refuse
		// rather than silently pick one (a misconfiguration could pin the wrong
		// trust root, defeating the whole gate).
		return errors.New("saml/sp: exactly one IdP trust anchor allowed (set only one of IDPMetadataURL, IDPMetadataXML, IDPCert)")
	}

	if len(c.IDPCert) > 0 && c.IDPEntityID == "" {
		// crewjam validates the assertion Issuer against the IdP entity ID; with
		// the bare-cert anchor there is no metadata to supply it, so the
		// operator must.
		return errors.New("saml/sp: IDPEntityID required when the trust anchor is IDPCert")
	}

	if c.SignAuthnRequests && len(c.SPPrivateKey) == 0 {
		return errors.New("saml/sp: SignAuthnRequests requires SPPrivateKey")
	}
	if len(c.SPPrivateKey) > 0 && len(c.SPCert) == 0 {
		return fmt.Errorf("saml/sp: SPCert required alongside SPPrivateKey for %q", c.Name)
	}
	return nil
}
