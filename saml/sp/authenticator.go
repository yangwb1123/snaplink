package sp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	dsig "github.com/russellhaering/goxmldsig"

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

	// logoutReplay dedups inbound IdP-initiated LogoutRequest IDs within the
	// freshness window (Fix 2). SEPARATE from the assertion replay store so the
	// two distinct ID spaces (AssertionID vs LogoutRequest ID) never collide. A
	// captured, validly-signed LogoutRequest replays here → rejected.
	logoutReplay *replayStore

	// sloSigner / sloSigMethod are the SP signing key + XML-DSig method used to
	// sign SP-initiated LogoutRequests + the LogoutResponse this SP returns to
	// the IdP. Set only when SPPrivateKey is configured (SLO signing is
	// mandatory — an unsigned logout is meaningless). Kept SEPARATE from
	// crewjam's sp.SignatureMethod so enabling SLO signing does NOT silently
	// start signing AuthnRequests (that stays gated by cfg.SignAuthnRequests).
	sloSigner    crypto.Signer
	sloSigCert   *x509.Certificate
	sloSigMethod string
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

	// SPSLOURL (this SP's own SLO endpoint) is optional; when set it parses into
	// the crewjam SloURL crewjam stamps as the LogoutRequest/Response Destination
	// context and validates inbound LogoutResponses against.
	var sloURL url.URL
	if cfg.SPSLOURL != "" {
		u, err := url.Parse(cfg.SPSLOURL)
		if err != nil {
			return nil, fmt.Errorf("saml/sp: parse SPSLOURL: %w", err)
		}
		sloURL = *u
	}

	idpMeta, err := loadIDPMetadata(cfg)
	if err != nil {
		return nil, err
	}

	// Inject the upstream IdP's SLO endpoint into the pinned metadata so
	// crewjam's GetSLOBindingLocation can build SP-initiated LogoutRequests and
	// the LogoutResponse destination. This NEVER touches the pinned SIGNING cert
	// (the trust anchor) — it only adds an endpoint location. When the metadata
	// already advertises one and IDPSLOURL is empty, the existing endpoint
	// stands.
	if cfg.IDPSLOURL != "" && idpMeta != nil {
		ensureIDPSLOEndpoint(idpMeta, cfg.IDPSLOURL)
	}

	sp := &saml.ServiceProvider{
		EntityID:    cfg.EntityID,
		AcsURL:      *acsURL,
		SloURL:      sloURL,
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

	a := &SPAuthenticator{}

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

		// XML-DSig method by SP key type: RSA-SHA256 (RSA keys) or ECDSA-SHA256
		// (P-256 EC keys). Used for SLO signing (always, when a key is present)
		// and AuthnRequest signing (only when cfg.SignAuthnRequests).
		sigMethod, err := xmlSigMethodForKey(key)
		if err != nil {
			return nil, fmt.Errorf("saml/sp: SP signing key: %w", err)
		}
		a.sloSigner = key
		a.sloSigCert = spCert
		a.sloSigMethod = sigMethod

		if cfg.SignAuthnRequests {
			// crewjam signs AuthnRequests iff SignatureMethod is non-empty.
			sp.SignatureMethod = sigMethod
		}
	}

	a.cfg = cfg
	a.sp = sp
	a.replay = newReplayStore(cfg.ReplayStoreSize)
	a.logoutReplay = newReplayStore(cfg.ReplayStoreSize)
	a.attrMap = cfg.AttributeMapping
	return a, nil
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

// ensureIDPSLOEndpoint makes the IdP metadata advertise an HTTP-Redirect
// SingleLogoutService at sloURL (so crewjam's GetSLOBindingLocation resolves
// it), without disturbing the pinned signing certs. It is idempotent: if a
// redirect SLO endpoint is already present it leaves it untouched (metadata is
// authoritative when it carries one). Only the FIRST IDPSSODescriptor is
// adjusted (crewjam reads SLO from the descriptors in order).
func ensureIDPSLOEndpoint(meta *saml.EntityDescriptor, sloURL string) {
	if len(meta.IDPSSODescriptors) == 0 {
		meta.IDPSSODescriptors = []saml.IDPSSODescriptor{{}}
	}
	for i := range meta.IDPSSODescriptors {
		for _, ep := range meta.IDPSSODescriptors[i].SingleLogoutServices {
			if ep.Binding == saml.HTTPRedirectBinding {
				return // metadata already advertises a redirect SLO endpoint
			}
		}
	}
	d := &meta.IDPSSODescriptors[0]
	d.SingleLogoutServices = append(d.SingleLogoutServices, saml.Endpoint{
		Binding:  saml.HTTPRedirectBinding,
		Location: sloURL,
	})
}

// parseCertificatePEM decodes a single PEM CERTIFICATE block.
func parseCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM CERTIFICATE block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// xmlSigMethodForKey returns the goxmldsig XML signature-method identifier for
// an SP signing key: RSA-SHA256 for *rsa.PrivateKey, ECDSA-SHA256 for a P-256
// *ecdsa.PrivateKey. Other key types (including non-P256 curves and Ed25519 —
// goxmldsig has no EdDSA method) are rejected, mirroring the IdP-side
// AssertionSigner classification so SP-initiated SLO signing stays consistent.
func xmlSigMethodForKey(key crypto.Signer) (string, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return dsig.RSASHA256SignatureMethod, nil
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return "", fmt.Errorf("unsupported ECDSA curve %s (need P-256)", k.Curve.Params().Name)
		}
		return dsig.ECDSASHA256SignatureMethod, nil
	default:
		return "", fmt.Errorf("unsupported SP key type %T (need RSA or ECDSA P-256)", key)
	}
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
