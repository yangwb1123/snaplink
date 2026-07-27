package defaultmfa

import (
	"context"
	"errors"
	"strings"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// MethodRecovery is the wire method name for single-use MFA recovery
// codes. Surfaces in the mfa_required response's mfa_methods list once
// this provider is composed via NewMultiMFAProvider.
const MethodRecovery = "recovery"

// RecoveryMFAProvider verifies single-use MFA recovery codes as a
// second factor, delegating to a [core.RecoveryCodeStore] for the
// hashed lookup + single-use consume. It plugs into the SAME dispatch
// as TOTP/WebAuthn/Push via [NewMultiMFAProvider], so recovery inherits
// the per-subject MFA lockout, the mfa_failure/mfa_success audit, and
// the uniform mfa_invalid oracle collapse for free — no edits to the
// server_mfa.go hot path.
//
// It deliberately does NOT implement [spi.MFABeginner]: a recovery code
// is a static credential the user already holds, so there is no
// server-side per-ceremony state to pre-issue (unlike WebAuthn).
type RecoveryMFAProvider struct {
	store core.RecoveryCodeStore
}

// NewRecoveryMFAProvider wraps a RecoveryCodeStore. The nil-store guard
// keeps a mis-wired deployment from silently accepting every code (a
// nil store would panic on Consume, not fail open — but refusing at
// construction surfaces the mistake at startup, matching the other
// providers' fail-fast wiring).
func NewRecoveryMFAProvider(store core.RecoveryCodeStore) (*RecoveryMFAProvider, error) {
	if store == nil {
		return nil, errors.New("recovery_mfa: RecoveryCodeStore required")
	}
	return &RecoveryMFAProvider{store: store}, nil
}

// SupportedMethods returns ["recovery"].
func (p *RecoveryMFAProvider) SupportedMethods() []string {
	return []string{MethodRecovery}
}

// Verify normalizes the supplied code and consumes it single-use.
// Normalization (upper-case, strip spaces) is forgiving of how a user
// transcribes a code; it is safe because Generate emits canonical
// upper-case, separator-free codes, so the store still only ever sees
// (and hashes) the canonical form — the store itself is never mutated.
// Every failure is a sentinel the server collapses to one mfa_invalid
// wire response (anti-enumeration).
func (p *RecoveryMFAProvider) Verify(ctx context.Context, subjectID, method string, params map[string]string) error {
	if method != MethodRecovery {
		return ErrRecoveryUnsupportedMethod
	}
	code := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(params["code"]), " ", ""))
	if code == "" {
		return ErrRecoveryMissingCode
	}
	ok, err := p.store.Consume(ctx, subjectID, code)
	if err != nil {
		return err
	}
	if !ok {
		return ErrRecoveryCodeInvalid
	}
	return nil
}

// Sentinel errors. Operator-side observability only; the SSO server
// collapses all of them to mfa_invalid on the wire.
var (
	ErrRecoveryUnsupportedMethod = errors.New("recovery_mfa: unsupported method")
	ErrRecoveryMissingCode       = errors.New("recovery_mfa: missing code")
	ErrRecoveryCodeInvalid       = errors.New("recovery_mfa: invalid code")
)

// Interface guard. Recovery is a single-call factor, so it MUST NOT
// satisfy spi.MFABeginner.
var _ spi.MFAProvider = (*RecoveryMFAProvider)(nil)
