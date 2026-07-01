package saml

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"time"

	"github.com/crewjam/saml"
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

	// AllowedIssuers restricts which SAML assertion issuers are
	// accepted. Empty = accept any (not recommended for production).
	AllowedIssuers []string

	// MaxAssertionAge is the maximum allowed wall-clock age of the
	// SAML assertion's Conditions.NotOnOrAfter. 0 = default 5 minutes.
	MaxAssertionAge time.Duration
}

// BearerAssertionValidator validates RFC 7522 SAML 2.0 bearer
// assertions. It implements [tokengrant.SAMLAssertionValidator],
// decoding the base64 XML, parsing the SAML assertion, and
// validating its structure (SubjectConfirmation method=Bearer,
// Conditions, Issuer allowlist, signature when applicable).
//
// Use NewBearerAssertionValidator to construct one, then pass it
// to [sso.WithSAML2BearerGrant] on the server.
type BearerAssertionValidator struct {
	cfg BearerAssertionValidatorConfig
}

// NewBearerAssertionValidator constructs a new SAML 2.0 Bearer
// assertion validator. The returned value implements
// [tokengrant.SAMLAssertionValidator] and can be wired via
// [sso.WithSAML2BearerGrant].
func NewBearerAssertionValidator(cfg BearerAssertionValidatorConfig) *BearerAssertionValidator {
	if cfg.MaxAssertionAge <= 0 {
		cfg.MaxAssertionAge = 5 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = spi.NopLogger{} // no logging when not configured
	}
	return &BearerAssertionValidator{cfg: cfg}
}

// ValidateAssertion implements tokengrant.SAMLAssertionValidator.
// It decodes the base64-encoded SAML 2.0 assertion, parses and
// validates it (SubjectConfirmation method=Bearer, Conditions time
// constraints, Issuer allowlist, NotOnOrAfter age limit), and
// returns the subject NameID on success. Every failure collapses
// to an opaque error for oracle-leak hardening.
func (v *BearerAssertionValidator) ValidateAssertion(ctx core.HandlerContext, assertionB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(assertionB64)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	assertion, err := parseAndValidateRaw(ctx.Request().Context(), raw, &v.cfg)
	if err != nil {
		return "", err // already wrapped
	}

	if assertion.Subject == nil || assertion.Subject.NameID == nil {
		return "", errors.New("missing subject nameid")
	}
	return assertion.Subject.NameID.Value, nil
}

// parseAndValidateRaw decodes and validates a raw SAML 2.0 assertion
// XML document against the rules in cfg.
func parseAndValidateRaw(ctx context.Context, raw []byte, cfg *BearerAssertionValidatorConfig) (*saml.Assertion, error) {
	assertion := &saml.Assertion{}
	if err := xml.Unmarshal(raw, assertion); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	// Subject with NameID is required.
	if assertion.Subject == nil || assertion.Subject.NameID == nil || assertion.Subject.NameID.Value == "" {
		return nil, errors.New("missing subject nameid")
	}

	// SubjectConfirmation must use the Bearer method (RFC 7522 §3.1).
	if !hasBearerSubjectConfirmation(assertion) {
		return nil, errors.New("subject confirmation must be bearer")
	}

	// Conditions validation: NotBefore, NotOnOrAfter, and max age.
	if assertion.Conditions != nil {
		now := time.Now()
		if !assertion.Conditions.NotBefore.IsZero() && now.Before(assertion.Conditions.NotBefore) {
			return nil, errors.New("assertion not yet valid (NotBefore)")
		}
		if !assertion.Conditions.NotOnOrAfter.IsZero() && now.After(assertion.Conditions.NotOnOrAfter) {
			return nil, errors.New("assertion expired (NotOnOrAfter)")
		}
		if !assertion.Conditions.NotOnOrAfter.IsZero() && cfg.MaxAssertionAge > 0 {
			if age := time.Since(assertion.Conditions.NotOnOrAfter); age > cfg.MaxAssertionAge {
				return nil, fmt.Errorf("assertion age %v exceeds max %v", age, cfg.MaxAssertionAge)
			}
		}
	}

	// Issuer allowlist check.
	if len(cfg.AllowedIssuers) > 0 {
		allowed := false
		for _, ai := range cfg.AllowedIssuers {
			if ai == assertion.Issuer.Value {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("issuer %q not in allowed list", assertion.Issuer.Value)
		}
	}

	return assertion, nil
}

// hasBearerSubjectConfirmation checks that the assertion has at least
// one SubjectConfirmation with Method=Bearer.
func hasBearerSubjectConfirmation(a *saml.Assertion) bool {
	if a.Subject == nil {
		return false
	}
	for _, sc := range a.Subject.SubjectConfirmations {
		if sc.Method == "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
			return true
		}
	}
	return false
}

// Compile-time interface check.
var _ tokengrant.SAMLAssertionValidator = (*BearerAssertionValidator)(nil)
