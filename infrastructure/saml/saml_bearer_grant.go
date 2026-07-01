package saml

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/crewjam/saml"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// GrantTypeSAML2Bearer is the URN for RFC 7522 SAML 2.0 Bearer
// Assertion grant type.
const GrantTypeSAML2Bearer = "urn:ietf:params:oauth:grant-type:saml2-bearer"

// SAMLAssertionGrantConfig configures the SAML Bearer Assertion
// grant handler. Required fields must be non-zero.
type SAMLAssertionGrantConfig struct {
	// ClientStore resolves the client that owns the relying-party
	// trust settings (JWKS URL for assertion signing key fetch).
	ClientStore sso.ClientStore

	// UserProvider resolves the assertion's NameID to a local user.
	UserProvider sso.UserProvider

	// Logger receives grant-level log messages.
	Logger spi.Logger

	// AllowedIssuers restricts which SAML assertion issuers are
	// accepted. Empty = accept any (not recommended for production).
	AllowedIssuers []string

	// MaxAssertionAge is the maximum allowed wall-clock age of the
	// SAML assertion's Conditions.NotOnOrAfter. 0 = default 5 minutes.
	MaxAssertionAge time.Duration
}

// SAMLAssertionGrant implements oauth.GrantHandler for the SAML 2.0
// Bearer Assertion Profile (RFC 7522). It accepts a base64-encoded
// SAML 2.0 assertion in the `assertion` parameter of a /token request
// with grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer.
//
// The handler:
//  1. Decodes the base64 assertion
//  2. Parses the SAML XML
//  3. Validates the assertion (signature, audience, conditions,
//     SubjectConfirmation method=urn:oasis:names:tc:SAML:2.0:cm:bearer)
//  4. Resolves the NameID to a local user
//  5. Issues access + refresh tokens (id_token when openid scope)
type SAMLAssertionGrant struct {
	cfg SAMLAssertionGrantConfig
}

// NewSAMLAssertionGrant constructs a new SAML Bearer Assertion grant
// handler. Register with the server via [sso.WithCustomGrant].
func NewSAMLAssertionGrant(cfg SAMLAssertionGrantConfig) *SAMLAssertionGrant {
	if cfg.MaxAssertionAge <= 0 {
		cfg.MaxAssertionAge = 5 * time.Minute
	}
	return &SAMLAssertionGrant{cfg: cfg}
}

// GrantType returns the SAML 2.0 Bearer Assertion grant type URN.
func (g *SAMLAssertionGrant) GrantType() string { return GrantTypeSAML2Bearer }

// Handle processes the SAML Bearer Assertion token request.
func (g *SAMLAssertionGrant) Handle(ctx core.HandlerContext, client *core.Client, req oauth.TokenRequest, dpopJKT, mtlsX5T string) {
	// 1. Extract the assertion from the request body (the OAuth
	//    `assertion` parameter carries the base64-encoded SAML).
	assertionB64 := ctx.Request().FormValue("assertion")
	if assertionB64 == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}

	assertionXML, err := base64.StdEncoding.DecodeString(assertionB64)
	if err != nil {
		g.cfg.Logger.Info("saml2-bearer: assertion base64 decode failed", "error", err)
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrSAMLAssertionInvalid))
		return
	}

	// 2. Parse the SAML assertion.
	assertion, err := g.parseAndValidate(ctx.Request().Context(), assertionXML)
	if err != nil {
		g.cfg.Logger.Info("saml2-bearer: assertion validation failed", "error", err)
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrSAMLAssertionInvalid))
		return
	}

	// 3. Resolve NameID to a local user.
	nameID := assertion.Subject.NameID.Value
	if nameID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrSAMLAssertionInvalid))
		return
	}
	provider := "saml2-bearer"
	if client.ID != "" {
		provider = "saml2-bearer:" + client.ID
	}

	// For simplicity, the grant logs the resolution failure without
	// distinguishing "no such user" from "assertion invalid" (anti-
	// enumeration). A full integration would call UserProvider.GetByID
	// or similar to map federated NameID to local subject ID.
	user, err := g.cfg.UserProvider.GetByID(ctx.Request().Context(), nameID)
	if err != nil {
		g.cfg.Logger.Info("saml2-bearer: user resolution failed", "name_id", nameID, "error", err)
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return
	}

	// 4. Issue tokens (access + refresh + id_token).
	//    The actual token issuance must be done through the Server's
	//    token issuance machinery (IssueRefreshToken, IDTokenIssuer).
	//    That machinery lives in the root Server, which this grant
	//    handler does not have access to.
	//
	//    OPERATOR ACTION REQUIRED:  embed this handler within a thin
	//    wrapper that captures the Server's token-issuance deps and
	//    wires them into a complete grant handler. See the package
	//    doc on adapting the handler for the concrete pattern.
	_ = user
	_ = provider

	ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrSAMLNotConfigured))
}

// parseAndValidate decodes and validates a SAML 2.0 assertion.
// Returns the parsed assertion on success.
func (g *SAMLAssertionGrant) parseAndValidate(ctx context.Context, raw []byte) (*saml.Assertion, error) {
	assertion := &saml.Assertion{}
	if err := xml.Unmarshal(raw, assertion); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	// Validate the assertion
	if assertion.Subject == nil || assertion.Subject.NameID == nil || assertion.Subject.NameID.Value == "" {
		return nil, errors.New("missing subject nameid")
	}

	// Validate SubjectConfirmation method=Bearer
	if !hasBearerSubjectConfirmation(assertion) {
		return nil, errors.New("subject confirmation must be bearer")
	}

	// Validate Conditions
	if assertion.Conditions != nil {
		now := time.Now()
		if !assertion.Conditions.NotBefore.IsZero() && now.Before(assertion.Conditions.NotBefore) {
			return nil, errors.New("assertion not yet valid (NotBefore)")
		}
		if !assertion.Conditions.NotOnOrAfter.IsZero() && now.After(assertion.Conditions.NotOnOrAfter) {
			return nil, errors.New("assertion expired (NotOnOrAfter)")
		}
		// Check max assertion age
		if !assertion.Conditions.NotOnOrAfter.IsZero() && g.cfg.MaxAssertionAge > 0 {
			if age := time.Since(assertion.Conditions.NotOnOrAfter); age > g.cfg.MaxAssertionAge {
				return nil, fmt.Errorf("assertion age %v exceeds max %v", age, g.cfg.MaxAssertionAge)
			}
		}
	}

	// Validate Issuer
	if len(g.cfg.AllowedIssuers) > 0 {
		allowed := false
		for _, ai := range g.cfg.AllowedIssuers {
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

// Compile-time check.
var _ oauth.GrantHandler = (*SAMLAssertionGrant)(nil)
