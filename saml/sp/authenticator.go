package sp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"

	"github.com/snaplink/sso"
)

// SPAuthenticator authenticates a user by consuming an assertion from one
// upstream SAML IdP. It implements sso.Authenticator and mirrors
// authenticators/oidc_federation.go:
//
//  1. LoginURL builds the IdP's HTTP-Redirect SSO URL (SAMLRequest deflated +
//     base64 + urlencoded, RelayState=state) — the SDK redirects the
//     user-agent there.
//  2. The IdP authenticates the user and POSTs a signed SAML Response back to
//     this SP's ACS endpoint (/auth/saml/callback), NOT the generic
//     /auth/callback (see Callback below for why).
//  3. The ACS handler hands the Response to ProcessAssertion, which validates
//     it via crewjam's XSW-resistant ParseResponse against the PINNED IdP
//     signing certificate and maps the result onto an sso.AuthResult.
//
// The crewjam ServiceProvider is built once at construction with the IdP cert
// pinned; the signing cert is NEVER taken from the assertion itself.
type SPAuthenticator struct {
	cfg     SPConfig
	sp      *saml.ServiceProvider
	replay  *replayStore
	attrMap map[string]string
	// now is the clock seam; nil ⇒ time.Now. Lets tests pin time deterministically.
	now func() time.Time
}

// NewSPAuthenticator validates cfg, loads + PINS the upstream IdP signing
// certificate (fetching metadata over HTTP when IDPMetadataURL is set), and
// returns the authenticator. A construction error fails the operator's boot
// closed — a SAML SP with an unresolved trust anchor must not start.
func NewSPAuthenticator(cfg SPConfig) (*SPAuthenticator, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	acsURL, err := url.Parse(cfg.ACSURL)
	if err != nil {
		return nil, fmt.Errorf("saml/sp: parse ACSURL: %w", err)
	}

	idpMeta, err := loadIDPMetadata(cfg)
	if err != nil {
		return nil, err
	}

	sp := &saml.ServiceProvider{
		EntityID:    cfg.EntityID,
		AcsURL:      *acsURL,
		IDPMetadata: idpMeta,
		// AuthnNameIDFormat shapes the NameIDPolicy on the outbound
		// AuthnRequest. Empty leaves it unset (IdP chooses).
		AuthnNameIDFormat: saml.NameIDFormat(cfg.NameIDFormat),

		// crewjam's InResponseTo correlation needs the exact AuthnRequest IDs
		// the SP issued. This ACS is intentionally STATELESS (it keeps no
		// per-request ID store — correlation rides on RelayState + the content
		// checks), so we cannot supply those IDs. Running crewjam with
		// AllowIDPInitiated=true makes it SKIP the two InResponseTo checks (the
		// response-level validateRequestID and the un-hookable assertion-level
		// SubjectConfirmation check) that would otherwise hard-fail on an empty
		// ID list. We re-impose the operator's intent via ValidateRequestID
		// below — the one correlation hook crewjam exposes — so the
		// SP-initiated-only posture is still enforced as far as a stateless ACS
		// can: it rejects an unsolicited (empty-InResponseTo) response.
		AllowIDPInitiated: true,
		ValidateRequestID: requestIDValidator(cfg.AllowIDPInitiated),
	}

	// Optional SP key: signs AuthnRequests + decrypts EncryptedAssertions. We
	// deliberately do NOT set IDPCertificateFingerprint — that crewjam code
	// path would resolve the signing cert from the assertion-embedded
	// certificate (the XSW hole). Leaving it unset forces verification against
	// the pinned IDPMetadata signing certs only.
	if len(cfg.SPPrivateKey) > 0 {
		key, err := parsePrivateKey(cfg.SPPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("saml/sp: parse SPPrivateKey: %w", err)
		}
		spCert, err := parseCertificatePEM(cfg.SPCert)
		if err != nil {
			return nil, fmt.Errorf("saml/sp: parse SPCert: %w", err)
		}
		sp.Key = key
		sp.Certificate = spCert
		if cfg.SignAuthnRequests {
			// crewjam signs AuthnRequests iff SignatureMethod is non-empty.
			// RSA-SHA256 is the modern baseline; EC keys would need an ECDSA
			// method, but RSA SP keys are by far the common case.
			sp.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
		}
	}

	return &SPAuthenticator{
		cfg:     cfg,
		sp:      sp,
		replay:  newReplayStore(cfg.ReplayStoreSize),
		attrMap: cfg.AttributeMapping,
	}, nil
}

func (a *SPAuthenticator) Name() string { return a.cfg.Name }

// LoginURL builds the IdP's HTTP-Redirect SSO URL carrying a deflated, base64,
// urlencoded SAMLRequest with RelayState=state. The SDK's /auth/login
// orchestrator redirects the user-agent there (the same non-empty-LoginURL
// path the OIDC-federation authenticator uses).
//
// state threads through verbatim as RelayState — the SDK's outer layer owns
// state CSRF defense and correlating the eventual ACS POST back to the original
// /auth/login. crewjam's MakeRedirectAuthenticationRequest also stamps a fresh
// request ID into the SAMLRequest; in SP-initiated mode that ID would normally
// be checked against the assertion's InResponseTo, but since LoginURL and the
// stateless ACS handler don't share a request-ID store, correlation relies on
// RelayState (and, defense-in-depth, on every assertion-content check). The
// per-request ID is still useful: it makes each AuthnRequest unique at the IdP.
//
// On any failure (e.g. an IDPCert-only config with no SSO endpoint) LoginURL
// returns "" — the orchestrator then treats this as "no redirect" and falls
// through, which surfaces to the caller rather than redirecting nowhere.
func (a *SPAuthenticator) LoginURL(state string) string {
	// Guard: crewjam's MakeRedirectAuthenticationRequest does NOT error when the
	// IdP metadata carries no HTTP-Redirect SSO endpoint — it builds a bogus
	// relative URL with an empty Destination. Detect that up front (a cert-only
	// anchor without IDPSSOURL) and return "" so the orchestrator treats this as
	// "no redirect" rather than redirecting nowhere.
	if a.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding) == "" {
		return ""
	}
	u, err := a.sp.MakeRedirectAuthenticationRequest(state)
	if err != nil {
		return ""
	}
	return u.String()
}

// Authenticate is not supported — SAML SP federation completes via the IdP
// redirect → ACS POST → ProcessAssertion path. A client cannot log into an
// upstream IdP by POSTing credentials to /auth/login. Returns a typed error so
// callers distinguish "wrong authenticator for this flow" from "bad
// credentials" (mirrors ErrOIDCFederationDirectAuthUnsupported).
func (a *SPAuthenticator) Authenticate(_ context.Context, _ *sso.AuthRequest) (*sso.AuthResult, error) {
	return nil, ErrSAMLDirectAuthUnsupported
}

// Callback is intentionally NOT the assertion-consumer entry point.
//
// The generic sso.Authenticator.Callback is wired to /auth/callback, which the
// SDK models as an OAuth/OIDC code-exchange probe (CallbackState{Code, State,
// ...}). A SAML assertion is neither a code nor URL query state — it arrives as
// a base64 SAMLResponse in a POST body to the SP's dedicated Assertion Consumer
// Service. Routing it through the code-probe shape would force a lossy
// adaptation and muddle the oracle-safe error contract. So the ACS lives in a
// dedicated POST /auth/saml/callback handler (built in saml.Build), and this
// Callback returns a typed not-applicable error if the generic probe ever
// reaches it.
func (a *SPAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, ErrSAMLCallbackNotApplicable
}

// ErrSAMLDirectAuthUnsupported is returned by Authenticate: SAML SP federation
// has no direct-credential leg; it completes via redirect → ACS POST.
var ErrSAMLDirectAuthUnsupported = errors.New("saml/sp: direct authentication not supported — use redirect + ACS assertion flow")

// ErrSAMLCallbackNotApplicable is returned by Callback: the SAML assertion is
// consumed by the dedicated /auth/saml/callback ACS handler, not the generic
// /auth/callback code probe.
var ErrSAMLCallbackNotApplicable = errors.New("saml/sp: assertion consumed by the dedicated /auth/saml/callback handler, not the generic callback probe")

// requestIDValidator returns the crewjam ServiceProvider.ValidateRequestID hook
// implementing this SP's IdP-initiated posture for a STATELESS ACS (no request
// ID store). Because we run crewjam with AllowIDPInitiated=true (to skip the
// ID-list checks that can't succeed without the IDs), this hook is where the
// operator's intent is re-imposed:
//
//   - allowIDPInitiated == true  → accept any response (solicited or not).
//   - allowIDPInitiated == false → require a non-empty InResponseTo, rejecting
//     an UNSOLICITED (IdP-initiated) response. This is the strongest assurance
//     a stateless ACS can give that the assertion answers a request this SP
//     made — it can't match the exact ID, but it refuses one that answers no
//     request at all. (A front end that tracks request IDs can tighten this to
//     an exact match; that is out of scope for the stateless build.)
//
// The signature (pinned cert), audience, recipient, expiry, single-assertion,
// and replay checks apply in BOTH modes regardless.
func requestIDValidator(allowIDPInitiated bool) func(response saml.Response, possibleRequestIDs []string) error {
	return func(response saml.Response, _ []string) error {
		if allowIDPInitiated {
			return nil
		}
		if response.InResponseTo == "" {
			return errors.New("saml/sp: unsolicited response rejected (SP-initiated only; set AllowIDPInitiated to permit)")
		}
		return nil
	}
}

// loadIDPMetadata resolves the pinned IdP trust anchor into a crewjam
// EntityDescriptor, by whichever of the three mutually-exclusive forms cfg set
// (Validate already enforced exactly one). The returned descriptor's
// IDPSSODescriptors carry the signing cert crewjam pins for signature
// verification.
func loadIDPMetadata(cfg SPConfig) (*saml.EntityDescriptor, error) {
	switch {
	case cfg.IDPMetadataURL != "":
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = DefaultTimeout
		}
		metaURL, err := url.Parse(cfg.IDPMetadataURL)
		if err != nil {
			return nil, fmt.Errorf("saml/sp: parse IDPMetadataURL: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		meta, err := samlsp.FetchMetadata(ctx, &http.Client{Timeout: timeout}, *metaURL)
		if err != nil {
			return nil, fmt.Errorf("saml/sp: fetch IdP metadata: %w", err)
		}
		return meta, nil

	case len(cfg.IDPMetadataXML) > 0:
		meta, err := samlsp.ParseMetadata(cfg.IDPMetadataXML)
		if err != nil {
			return nil, fmt.Errorf("saml/sp: parse IDPMetadataXML: %w", err)
		}
		return meta, nil

	default: // IDPCert
		return metadataFromCert(cfg)
	}
}

// metadataFromCert synthesizes a minimal EntityDescriptor from a bare PEM IdP
// signing certificate. crewjam's getIDPSigningCerts reads the cert from the
// IDPSSODescriptor's signing KeyDescriptor, so we place it there; the synthetic
// SingleSignOnService (present only when IDPSSOURL is set) lets LoginURL build
// a redirect.
func metadataFromCert(cfg SPConfig) (*saml.EntityDescriptor, error) {
	cert, err := parseCertificatePEM(cfg.IDPCert)
	if err != nil {
		return nil, fmt.Errorf("saml/sp: parse IDPCert: %w", err)
	}
	keyDesc := saml.KeyDescriptor{
		Use: "signing",
		KeyInfo: saml.KeyInfo{
			X509Data: saml.X509Data{
				X509Certificates: []saml.X509Certificate{
					{Data: base64.StdEncoding.EncodeToString(cert.Raw)},
				},
			},
		},
	}
	idpDesc := saml.IDPSSODescriptor{}
	idpDesc.KeyDescriptors = []saml.KeyDescriptor{keyDesc}
	if cfg.IDPSSOURL != "" {
		idpDesc.SingleSignOnServices = []saml.Endpoint{{
			Binding:  saml.HTTPRedirectBinding,
			Location: cfg.IDPSSOURL,
		}}
	}
	return &saml.EntityDescriptor{
		EntityID:          cfg.IDPEntityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{idpDesc},
	}, nil
}

// parseCertificatePEM decodes a single PEM CERTIFICATE block.
func parseCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM CERTIFICATE block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// parsePrivateKey decodes a PEM RSA/EC/PKCS8 private key into a crypto.Signer
// (the type crewjam's ServiceProvider.Key wants).
func parsePrivateKey(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM private-key block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("unsupported private-key format (want PKCS1, EC, or PKCS8)")
	}
	switch k := keyAny.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported PKCS8 key type %T", keyAny)
	}
}

var _ sso.Authenticator = (*SPAuthenticator)(nil)
