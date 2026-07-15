package saml

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/snaplink/sso/internal/handler/tokengrant"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// GrantTypeSAML2Bearer is the URN for RFC 7522 SAML 2.0 Bearer
// Assertion grant type.
const GrantTypeSAML2Bearer = "urn:ietf:params:oauth:grant-type:saml2-bearer"

// BearerAssertionValidatorConfig configures a BearerAssertionValidator.
type BearerAssertionValidatorConfig struct {
	// Logger receives validation log messages.
	Logger spi.Logger

	// TrustedCertificates pins the PEM-encoded X.509 certificate(s) whose
	// key(s) may sign a bearer assertion. Every assertion's enveloped
	// XML-DSig signature is verified against THESE roots -- NEVER a
	// certificate embedded in the assertion's own KeyInfo, which is exactly
	// the forgery this field closes: without a pinned trust anchor, anyone
	// who can reach /token can self-sign (or not sign at all) an assertion
	// for any subject. REQUIRED: NewBearerAssertionValidator rejects an
	// empty list (fail-closed -- RFC 7522 assertions MUST be signed).
	TrustedCertificates [][]byte

	// Audience is this authorization server's RFC 7522 section 3 audience value
	// (conventionally the /token endpoint URL) that the assertion's
	// Conditions/AudienceRestriction must name. REQUIRED: an assertion with
	// no AudienceRestriction naming this value is rejected -- mirroring
	// saml/sp's audienceContains, an unrestricted assertion must never
	// authenticate here.
	Audience string

	// AllowedIssuers restricts which SAML assertion issuers are
	// accepted. Empty = accept any (not recommended for production).
	AllowedIssuers []string

	// MaxAssertionAge is the maximum allowed wall-clock age of the
	// SAML assertion's Conditions.NotOnOrAfter. 0 = default 5 minutes.
	// Also used as the replay-dedup fallback window (see bearerReplayExpiry)
	// for the rare assertion whose Conditions/SubjectConfirmationData carry
	// no NotOnOrAfter at all.
	MaxAssertionAge time.Duration

	// ReplayStoreSize bounds the in-memory AssertionID replay-dedup cache
	// (see bearerReplayStore). Zero ⇒ DefaultBearerReplayStoreSize. Without
	// this dedup a single captured, validly-signed assertion could be
	// redeemed for an UNBOUNDED number of access tokens within its validity
	// window -- RFC 7522 assertions are bearer credentials, and every other
	// SAML entry point in this module (saml/idp, saml/sp) already dedups its
	// own replay token; the bearer grant needs the same treatment.
	ReplayStoreSize int
}

// BearerAssertionValidator validates RFC 7522 SAML 2.0 bearer
// assertions. It implements [tokengrant.SAMLAssertionValidator],
// decoding the base64 XML, verifying its enveloped XML-DSig signature
// against the pinned TrustedCertificates, and validating its structure
// (SubjectConfirmation method=Bearer, Conditions, AudienceRestriction,
// Issuer allowlist).
//
// Use NewBearerAssertionValidator to construct one, then pass it
// to [sso.WithSAML2BearerGrant] on the server.
type BearerAssertionValidator struct {
	cfg          BearerAssertionValidatorConfig
	trustedCerts []*x509.Certificate

	// replay dedups assertion IDs so the SAME signed assertion cannot be
	// redeemed for more than one access token within its validity window
	// (see bearerReplayStore / checkBearerReplay).
	replay *bearerReplayStore
}

// NewBearerAssertionValidator constructs a new SAML 2.0 Bearer
// assertion validator. The returned value implements
// [tokengrant.SAMLAssertionValidator] and can be wired via
// [sso.WithSAML2BearerGrant].
//
// Returns an error when TrustedCertificates or Audience is unset/malformed:
// both are REQUIRED trust-boundary configuration, so construction fails
// closed rather than silently producing a validator that either can't
// verify a signature or can't check an audience.
func NewBearerAssertionValidator(cfg BearerAssertionValidatorConfig) (*BearerAssertionValidator, error) {
	if cfg.MaxAssertionAge <= 0 {
		cfg.MaxAssertionAge = 5 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = spi.NopLogger{} // no logging when not configured
	}
	if len(cfg.TrustedCertificates) == 0 {
		return nil, errors.New("saml: BearerAssertionValidator: TrustedCertificates required (RFC 7522 assertions must be signature-verified against a pinned trust anchor)")
	}
	if cfg.Audience == "" {
		return nil, errors.New("saml: BearerAssertionValidator: Audience required (RFC 7522 assertions must be restricted to this server's audience)")
	}
	certs, err := parseTrustedCertificates(cfg.TrustedCertificates)
	if err != nil {
		return nil, fmt.Errorf("saml: BearerAssertionValidator: %w", err)
	}
	return &BearerAssertionValidator{
		cfg:          cfg,
		trustedCerts: certs,
		replay:       newBearerReplayStore(cfg.ReplayStoreSize),
	}, nil
}

// parseTrustedCertificates decodes each PEM-encoded certificate in pemCerts.
func parseTrustedCertificates(pemCerts [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, len(pemCerts))
	for _, raw := range pemCerts {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, errors.New("invalid PEM block in TrustedCertificates")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// ValidateAssertion implements tokengrant.SAMLAssertionValidator.
// It decodes the base64-encoded SAML 2.0 assertion, verifies its XML-DSig
// signature against the pinned trust anchor, validates its structure
// (SubjectConfirmation method=Bearer, Conditions time constraints,
// AudienceRestriction, Issuer allowlist, NotOnOrAfter age limit), and
// returns the subject NameID on success. Every failure collapses
// to an opaque error for oracle-leak hardening.
func (v *BearerAssertionValidator) ValidateAssertion(ctx core.HandlerContext, assertionB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(assertionB64)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	assertion, err := parseAndValidateRaw(ctx.Request().Context(), raw, &v.cfg, v.trustedCerts, v.replay)
	if err != nil {
		return "", err // already wrapped
	}

	if assertion.Subject == nil || assertion.Subject.NameID == nil {
		return "", errors.New("missing subject nameid")
	}
	return assertion.Subject.NameID.Value, nil
}

// parseAndValidateRaw verifies the raw SAML 2.0 assertion's XML-DSig
// signature FIRST, then validates the (now-trusted) assertion structure
// against the rules in cfg. Nothing below the signature check is allowed to
// influence the result until the signature has been confirmed against
// trustedCerts -- an unsigned or forged assertion never reaches the
// structural checks. replay is consulted LAST (after every other check
// passed) -- see checkBearerReplay's doc: a captured, validly-signed
// assertion must be usable for at most ONE access token, not replayed
// indefinitely within its validity window.
//
// now is read once here and threaded through every time-bound check so they
// all share one consistent timestamp (mirrors saml/sp's ProcessAssertion /
// saml/idp's checkLogoutFreshnessAndReplay).
func parseAndValidateRaw(ctx context.Context, raw []byte, cfg *BearerAssertionValidatorConfig, trustedCerts []*x509.Certificate, replay *bearerReplayStore) (*saml.Assertion, error) {
	verifiedXML, err := verifyAssertionSignature(raw, trustedCerts)
	if err != nil {
		return nil, fmt.Errorf("signature verification: %w", err)
	}

	// Parse from the VALIDATED element's own serialization (not the raw
	// input) so every field below is read from exactly what the signature
	// covered.
	assertion := &saml.Assertion{}
	if err := xml.Unmarshal(verifiedXML, assertion); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	now := time.Now()

	if assertion.Subject == nil || assertion.Subject.NameID == nil || assertion.Subject.NameID.Value == "" {
		return nil, errors.New("missing subject nameid")
	}
	if !hasBearerSubjectConfirmation(assertion, now) {
		return nil, errors.New("subject confirmation must be bearer and unexpired")
	}
	if err := checkConditions(assertion, cfg, now); err != nil {
		return nil, err
	}
	if !audienceMatches(assertion, cfg.Audience) {
		return nil, errors.New("assertion audience mismatch")
	}
	if err := checkIssuerAllowed(assertion, cfg); err != nil {
		return nil, err
	}
	if err := checkBearerReplay(assertion, cfg, replay, now); err != nil {
		return nil, err
	}

	return assertion, nil
}

// verifyAssertionSignature parses raw as XML and verifies its enveloped
// XML-DSig signature against trustedCerts using goxmldsig -- the SAME engine
// saml/idp and saml/sp verify AuthnRequest/LogoutRequest/Response signatures
// with (see idp/sso_handler.go verifyAuthnRequestSignature and
// idp/slo_handler.go verifyLogoutRequestSignature). It returns the
// byte-serialized VALIDATED element so the caller parses every downstream
// field from exactly what the signature covered, never the raw input.
//
// An assertion with no Signature element, one signed by a certificate not in
// trustedCerts, or one whose content no longer matches its signature all
// return a non-nil error here (fail-closed): this is the gate the pre-fix
// implementation never applied, and RFC 7522 requires every bearer assertion
// to be signed.
func verifyAssertionSignature(raw []byte, trustedCerts []*x509.Certificate) ([]byte, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, fmt.Errorf("parse xml: %w", err)
	}
	root := doc.Root()
	if root == nil {
		return nil, errors.New("empty document")
	}

	store := &dsig.MemoryX509CertificateStore{Roots: trustedCerts}
	valCtx := dsig.NewDefaultValidationContext(store)
	// goxmldsig resolves the signed element by its DSig Reference URI,
	// verifies the signature against a root in the store, and refuses a cert
	// not in the store -- so an attacker can't swap in their own KeyInfo
	// cert, and ErrMissingSignature rejects an unsigned assertion outright.
	validated, err := valCtx.Validate(root)
	if err != nil {
		return nil, err
	}

	verifiedDoc := etree.NewDocument()
	verifiedDoc.SetRoot(validated)
	out, err := verifiedDoc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("serialize verified element: %w", err)
	}
	return out, nil
}

// checkConditions validates NotBefore, NotOnOrAfter, and the max-age bound.
// A nil Conditions is not rejected here -- hasBearerSubjectConfirmation
// independently checks the mandatory Bearer SubjectConfirmationData's own
// NotBefore/NotOnOrAfter, so an assertion with no Conditions element still
// gets a real time-bound check via its required Bearer confirmation (an
// assertion with NEITHER carrying a NotOnOrAfter has no possible expiry check
// at all, which is why hasBearerSubjectConfirmation is not optional).
func checkConditions(assertion *saml.Assertion, cfg *BearerAssertionValidatorConfig, now time.Time) error {
	if assertion.Conditions == nil {
		return nil
	}
	c := assertion.Conditions
	if !c.NotBefore.IsZero() && now.Before(c.NotBefore) {
		return errors.New("assertion not yet valid (NotBefore)")
	}
	if !c.NotOnOrAfter.IsZero() && now.After(c.NotOnOrAfter) {
		return errors.New("assertion expired (NotOnOrAfter)")
	}
	if !c.NotOnOrAfter.IsZero() && cfg.MaxAssertionAge > 0 {
		if age := now.Sub(c.NotOnOrAfter); age > cfg.MaxAssertionAge {
			return fmt.Errorf("assertion age %v exceeds max %v", age, cfg.MaxAssertionAge)
		}
	}
	return nil
}

// audienceMatches reports whether the assertion's Conditions carry an
// AudienceRestriction naming audience. Mirrors saml/sp's audienceContains: an
// assertion with NO AudienceRestriction is treated as NOT matching -- an
// unrestricted assertion must never authenticate at this token endpoint.
func audienceMatches(assertion *saml.Assertion, audience string) bool {
	if assertion.Conditions == nil || len(assertion.Conditions.AudienceRestrictions) == 0 {
		return false
	}
	for _, ar := range assertion.Conditions.AudienceRestrictions {
		if ar.Audience.Value == audience {
			return true
		}
	}
	return false
}

// checkIssuerAllowed enforces cfg.AllowedIssuers when configured.
func checkIssuerAllowed(assertion *saml.Assertion, cfg *BearerAssertionValidatorConfig) error {
	if len(cfg.AllowedIssuers) == 0 {
		return nil
	}
	for _, ai := range cfg.AllowedIssuers {
		if ai == assertion.Issuer.Value {
			return nil
		}
	}
	return fmt.Errorf("issuer %q not in allowed list", assertion.Issuer.Value)
}

// hasBearerSubjectConfirmation checks that the assertion has at least one
// SubjectConfirmation with Method=Bearer AND, when that confirmation carries
// a SubjectConfirmationData, that now falls inside its NotBefore/NotOnOrAfter
// window. Mirrors saml/sp/validator.go's expired() bearer-confirmation loop:
// every bearer confirmation present is checked (not just the first), and one
// outside its window is disqualifying -- fail-closed, not merely skipped.
//
// THIS is the check checkConditions's doc references for a nil-Conditions
// assertion: SubjectConfirmationData is where RFC 7522 bearer assertions
// conventionally carry their validity window when the assertion has no (or
// an incomplete) <Conditions> element, so this is not optional
// defense-in-depth -- for such an assertion it is the ONLY expiry gate in the
// whole pipeline. (An assertion with a bearer confirmation carrying no
// SubjectConfirmationData at all, and no Conditions either, has no time bound
// this validator can enforce and is accepted on that axis alone; the
// replay-dedup check below still bounds its usable lifetime to
// cfg.MaxAssertionAge.)
func hasBearerSubjectConfirmation(a *saml.Assertion, now time.Time) bool {
	if a.Subject == nil {
		return false
	}
	found := false
	for _, sc := range a.Subject.SubjectConfirmations {
		if sc.Method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
			continue
		}
		found = true
		if sc.SubjectConfirmationData == nil {
			continue
		}
		scd := sc.SubjectConfirmationData
		if !scd.NotBefore.IsZero() && now.Before(scd.NotBefore) {
			return false
		}
		if !scd.NotOnOrAfter.IsZero() && !now.Before(scd.NotOnOrAfter) {
			return false
		}
	}
	return found
}

// checkBearerReplay enforces single-use redemption of a bearer assertion:
// every earlier check in this pipeline (signature, subject, conditions,
// audience, issuer) passes again identically if the EXACT SAME assertion
// bytes are replayed, because none of them consult any prior-sighting state
// -- unlike saml/idp's LogoutReplayStore / saml/sp's ReplayStore, which dedup
// their own protocol's replay token by ID. Without this, a captured,
// validly-signed RFC 7522 assertion could be redeemed for an UNBOUNDED number
// of access tokens within its validity window. An assertion with no ID
// cannot be keyed on and is rejected outright (SAML core requires Assertion
// ID; goxmldsig's enveloped-signature Reference is normally over "#<ID>", so
// a conformant signed assertion always carries one).
func checkBearerReplay(assertion *saml.Assertion, cfg *BearerAssertionValidatorConfig, replay *bearerReplayStore, now time.Time) error {
	if assertion.ID == "" {
		return errors.New("assertion missing ID")
	}
	if fresh := replay.CheckAndRemember(assertion.ID, bearerReplayExpiry(assertion, cfg, now), now); !fresh {
		return errors.New("assertion replayed")
	}
	return nil
}

// bearerReplayExpiry picks the time after which the assertion can no longer
// possibly be valid -- the earliest of its Conditions NotOnOrAfter and every
// bearer SubjectConfirmationData NotOnOrAfter -- so the replay store prunes
// the assertion ID at that point (mirrors saml/sp/validator.go's
// replayExpiry). Neither is guaranteed present (see hasBearerSubjectConfirmation's
// doc); when both are absent, cfg.MaxAssertionAge bounds the dedup entry's
// life instead, reusing the SAME window that already bounds such an
// assertion's overall acceptance.
func bearerReplayExpiry(assertion *saml.Assertion, cfg *BearerAssertionValidatorConfig, now time.Time) time.Time {
	var exp time.Time
	consider := func(t time.Time) {
		if t.IsZero() {
			return
		}
		if exp.IsZero() || t.Before(exp) {
			exp = t
		}
	}
	if assertion.Conditions != nil {
		consider(assertion.Conditions.NotOnOrAfter)
	}
	if assertion.Subject != nil {
		for _, sc := range assertion.Subject.SubjectConfirmations {
			if sc.SubjectConfirmationData != nil {
				consider(sc.SubjectConfirmationData.NotOnOrAfter)
			}
		}
	}
	if exp.IsZero() {
		exp = now.Add(cfg.MaxAssertionAge)
	}
	return exp
}

// Compile-time interface check.
var _ tokengrant.SAMLAssertionValidator = (*BearerAssertionValidator)(nil)
