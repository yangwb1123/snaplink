package authenticators

import (
	"context"
	"errors"

	"github.com/snaplink/sso"
)

// TOTPMFAProvider verifies TOTP codes as a SECOND factor — after the
// primary credential succeeded and the configured [sso.RiskScorer]
// returned [sso.DecisionRequireMFA]. The provider is a thin adapter
// over an existing [TOTPAuthenticator] so the same TOTPStore + skew
// configuration serves both roles (primary auth via Authenticator
// interface; step-up via [sso.MFAProvider] interface).
//
// Wire with [sso.WithMFAProvider]:
//
//	totpAuth := authenticators.NewTOTPAuthenticator(store)
//	srv := sso.New(
//	    sso.WithAuthenticator(passwordAuth),
//	    sso.WithRiskScorer(myScorer),       // may emit DecisionRequireMFA
//	    sso.WithMFAProvider(authenticators.NewTOTPMFAProvider(totpAuth)),
//	    sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), 0),
//	)
//
// Same secret store, two consumer roles.
type TOTPMFAProvider struct {
	auth *TOTPAuthenticator
}

// NewTOTPMFAProvider wraps an existing TOTPAuthenticator so its verify
// path can be reused as an MFA factor. Sharing the store keeps a
// single enrollment record per user — operators don't have to provision
// "this is your primary TOTP" + "this is your MFA TOTP" twice.
func NewTOTPMFAProvider(auth *TOTPAuthenticator) *TOTPMFAProvider {
	return &TOTPMFAProvider{auth: auth}
}

// SupportedMethods returns ["totp"]. Wire shape on /auth/login's
// mfa_methods response: ["totp"].
func (p *TOTPMFAProvider) SupportedMethods() []string {
	return []string{MethodTOTP}
}

// Verify checks the supplied code against the user's enrolled TOTP
// secret. Delegates to the wrapped TOTPAuthenticator so skew / step
// configuration stays single-source.
//
// Returns nil on success; ErrTOTPMFAUnsupportedMethod when method !=
// "totp"; ErrTOTPMFAMissingCode when params lacks "code"; the
// underlying authenticator error otherwise. handle_mfa.go collapses
// every non-nil to the same mfa_invalid wire response so probes can't
// distinguish the cases.
func (p *TOTPMFAProvider) Verify(ctx context.Context, subjectID, method string, params map[string]string) error {
	if method != MethodTOTP {
		return ErrTOTPMFAUnsupportedMethod
	}
	code := params["code"]
	if code == "" {
		return ErrTOTPMFAMissingCode
	}
	_, err := p.auth.Authenticate(ctx, &sso.AuthRequest{
		Credential: map[string]string{
			"username": subjectID,
			"code":     code,
		},
	})
	return err
}

// Sentinel errors. Operator-side observability only; the SSO server
// collapses all of them to mfa_invalid on the wire.
var (
	ErrTOTPMFAUnsupportedMethod = errors.New("totp_mfa: unsupported method")
	ErrTOTPMFAMissingCode       = errors.New("totp_mfa: missing code")
)
