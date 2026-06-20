package defaultimpl

import "github.com/snaplink/sso/shared/spi"

import (
	"context"
	"errors"
	"fmt"
)

// MultiMFAProvider composes several [spi.MFAProvider] impls into a
// single dispatcher so a deployment can offer multiple step-up
// factors concurrently (e.g. TOTP for users without WebAuthn
// authenticators + WebAuthn for users with them). SupportedMethods
// aggregates across every wired provider in declaration order;
// Verify routes by method name. Begin (when a provider implements
// [spi.MFABeginner]) is forwarded only to providers whose
// SupportedMethods include the requested method, so non-Beginner
// providers don't accidentally absorb Begin calls.
//
// Method-name conflicts (two providers both claiming the same
// method) are rejected at construction with [ErrMFAMethodConflict]
// — silent winner-by-order semantics would surprise operators
// expecting NewMultiMFAProvider to be commutative for diagnostic
// purposes.
//
// Wire shape preserved exactly: the SSO server still holds a single
// MFAProvider via WithMFAProvider; the multiplexer is invisible to
// /auth/login and /auth/mfa beyond the aggregated method list.
type MultiMFAProvider struct {
	providers []spi.MFAProvider
	byMethod  map[string]spi.MFAProvider
	methods   []string
}

// NewMultiMFAProvider validates + returns a composite over providers.
// Every provider must declare at least one method via
// SupportedMethods; methods conflicting across providers fail
// construction. Empty providers slice → ErrMFANoProviders (refuse
// to wire a no-op dispatcher).
func NewMultiMFAProvider(providers ...spi.MFAProvider) (*MultiMFAProvider, error) {
	if len(providers) == 0 {
		return nil, ErrMFANoProviders
	}
	byMethod := make(map[string]spi.MFAProvider)
	methods := make([]string, 0)
	for i, p := range providers {
		if p == nil {
			return nil, fmt.Errorf("multi_mfa: providers[%d] is nil", i)
		}
		supported := p.SupportedMethods()
		if len(supported) == 0 {
			return nil, fmt.Errorf("multi_mfa: providers[%d] declares no methods", i)
		}
		for _, m := range supported {
			if m == "" {
				return nil, fmt.Errorf("multi_mfa: providers[%d] declares empty method name", i)
			}
			if existing, dup := byMethod[m]; dup && existing != p {
				return nil, fmt.Errorf("%w: method %q claimed by multiple providers", ErrMFAMethodConflict, m)
			}
			if _, dup := byMethod[m]; !dup {
				methods = append(methods, m)
			}
			byMethod[m] = p
		}
	}
	return &MultiMFAProvider{
		providers: providers,
		byMethod:  byMethod,
		methods:   methods,
	}, nil
}

// SupportedMethods returns the union of every wired provider's
// methods, in the order they were declared (first provider's
// methods first, then the next, etc). Stable across calls.
func (m *MultiMFAProvider) SupportedMethods() []string {
	out := make([]string, len(m.methods))
	copy(out, m.methods)
	return out
}

// Verify dispatches to the provider that claims method. Unknown
// method → ErrMFAUnknownMethod (the SSO server collapses to
// mfa_invalid on the wire, same anti-enumeration as every other
// MFA failure surface).
func (m *MultiMFAProvider) Verify(ctx context.Context, subjectID, method string, params map[string]string) error {
	p, ok := m.byMethod[method]
	if !ok {
		return ErrMFAUnknownMethod
	}
	return p.Verify(ctx, subjectID, method, params)
}

// Begin routes Begin calls to the right provider iff that provider
// implements [spi.MFABeginner]. Providers that don't need server-
// side setup (TOTP) return (nil, nil) here — the SSO server
// interprets that as "no per-method data" and omits the method's
// entry from the mfa_required response's mfa_method_data bucket.
//
// Implementing MFABeginner on the composite lets the SSO server's
// type assertion succeed even when ONLY ONE inner provider needs
// Begin — the others get the nil-data fall-through naturally.
func (m *MultiMFAProvider) Begin(ctx context.Context, subjectID, method string) (map[string]string, error) {
	p, ok := m.byMethod[method]
	if !ok {
		return nil, ErrMFAUnknownMethod
	}
	if b, ok := p.(spi.MFABeginner); ok {
		return b.Begin(ctx, subjectID, method)
	}
	return nil, nil
}

// Sentinel errors. ErrMFANoProviders + ErrMFAMethodConflict surface
// at construction time so operators see them at startup; the rest
// surface from runtime Verify/Begin paths but get collapsed to
// mfa_invalid on the wire.
var (
	ErrMFANoProviders    = errors.New("multi_mfa: at least one provider required")
	ErrMFAMethodConflict = errors.New("multi_mfa: method-name conflict")
	ErrMFAUnknownMethod  = errors.New("multi_mfa: unknown method")
)

// Interface guards. The MFABeginner assertion is what makes the
// composite useful for mixed single-call / two-call factor sets.
var (
	_ spi.MFAProvider = (*MultiMFAProvider)(nil)
	_ spi.MFABeginner = (*MultiMFAProvider)(nil)
)
