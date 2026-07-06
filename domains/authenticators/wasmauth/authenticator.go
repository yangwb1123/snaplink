package wasmauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/snaplink/sso/shared/core"
)

// errRejected is the SINGLE error every rejected-login cause collapses to
// — a guest-reported authenticated=false, a guest trap, a malformed
// response, a timeout, or an authenticated=true Result missing a
// subject_id all look identical from the caller's side. Mirrors this
// SDK's anti-enumeration doctrine (AGENTS.md §3): the wire never reveals
// WHICH of those happened, only that the login failed.
var errRejected = errors.New("wasmauth: authentication rejected")

// Authenticator implements core.Authenticator, verifying a credential by
// calling into a hosted WASM module. Name is required (an operator
// running more than one WASM-verified scheme registers each under its
// own distinct name — e.g. "custom-hw-token", "legacy-bridge" — the same
// way every other pluggable Authenticator in this codebase is named).
type Authenticator struct {
	name   string
	engine *Engine
}

// New returns an Authenticator named name, backed by engine. Neither may
// be empty/nil.
func New(name string, engine *Engine) (*Authenticator, error) {
	if name == "" {
		return nil, errors.New("wasmauth: name required")
	}
	if engine == nil {
		return nil, errors.New("wasmauth: engine required")
	}
	return &Authenticator{name: name, engine: engine}, nil
}

func (a *Authenticator) Name() string { return a.name }

// Authenticate calls into the hosted WASM module with req.Credential and
// maps a successful [Result] onto a core.AuthResult. See the package
// doc's "Fail-closed" section: every rejection cause — guest trap,
// malformed response, timeout, authenticated=false, or a missing
// subject_id — returns the SAME errRejected, never a distinguishable
// error, and NEVER a *core.AuthResult on any failure path.
func (a *Authenticator) Authenticate(ctx context.Context, req *core.AuthRequest) (*core.AuthResult, error) {
	res, err := a.engine.authenticate(ctx, Request{Credential: req.Credential})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errRejected, err)
	}
	if !res.Authenticated || res.SubjectID == "" {
		return nil, errRejected
	}
	return &core.AuthResult{
		UserID:      res.SubjectID,
		ExternalID:  res.SubjectID,
		Provider:    a.name,
		Attributes:  res.Claims,
		AuthMethods: []string{a.name},
	}, nil
}

// Callback is not supported — a WASM-verified credential is a single-step
// exchange (verbatim credential in, decision out), not a redirect-based
// external IdP flow.
func (a *Authenticator) Callback(_ context.Context, _ *core.CallbackState) (*core.AuthResult, error) {
	return nil, errors.New("wasmauth: callback not supported")
}

// LoginURL returns "" — this authenticator has no redirect-based login
// step; the credential is supplied directly to Authenticate.
func (a *Authenticator) LoginURL(_ string) string { return "" }

var _ core.Authenticator = (*Authenticator)(nil)
