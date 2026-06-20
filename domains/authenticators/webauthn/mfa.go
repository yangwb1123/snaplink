package webauthn

import "github.com/snaplink/sso/shared/spi"

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// MethodWebAuthn is the canonical wire name for the WebAuthn factor
// in the mfa_methods array + /auth/mfa request body. Stable across
// versions so SPAs branch on this constant.
const MethodWebAuthn = "webauthn"

// WebAuthnMFAProvider adapts the [Helper] login ceremony to the
// SSO server's [spi.MFAProvider] / [spi.MFABeginner] SPI. Step-up
// shares the same WebAuthn enrollment a primary
// /webauthn/login/{begin,finish} ceremony would use — one user
// record, two consumer roles (primary auth + MFA factor).
//
// Wire shape:
//
//   - /auth/login response (mfa_required):
//     mfa_method_data["webauthn"] = {
//     "options": "<credential assertion options JSON>",
//     "session": "<opaque ceremony id>",
//     }
//     The "options" string is the same JSON the standalone
//     /webauthn/login/begin endpoint would have returned — clients
//     pass it to navigator.credentials.get unchanged.
//
//   - /auth/mfa request body params:
//     {"session": "<echo of session>", "assertion": "<signed assertion JSON>"}
//     The assertion JSON is the navigator.credentials.get response
//     body the WebAuthn library expects to parse from an HTTP
//     request — Verify reconstructs a synthetic *http.Request to
//     feed it.
//
// Subject binding: the user resolved from the ceremony's session
// MUST match the SubjectID passed by the SSO server (the user the
// primary credential authenticated). Mismatch surfaces as
// [ErrWebAuthnMFASubjectMismatch] — defense against a captured
// session id being used to claim a different identity in the
// step-up window.
type WebAuthnMFAProvider struct {
	helper *Helper
}

// NewWebAuthnMFAProvider wraps an existing Helper. The same Helper
// can back the standalone /webauthn/login ceremony AND step-up MFA
// — one UserStore + one SessionStore, two consumer roles. Returns
// nil + error when h is nil; otherwise nil never returned.
func NewWebAuthnMFAProvider(h *Helper) (*WebAuthnMFAProvider, error) {
	if h == nil {
		return nil, errors.New("webauthn_mfa: Helper required")
	}
	return &WebAuthnMFAProvider{helper: h}, nil
}

// SupportedMethods returns ["webauthn"]. Single-method by design;
// the WebAuthn ceremony covers every WebAuthn-compatible
// authenticator (TouchID, YubiKey, Windows Hello, …) so the method
// name doesn't fragment per authenticator type.
func (p *WebAuthnMFAProvider) SupportedMethods() []string {
	return []string{MethodWebAuthn}
}

// Begin issues a fresh assertion ceremony for subjectID. The Helper
// looks up the user's enrolled credentials, generates a per-ceremony
// challenge, and writes the verification state to its SessionStore
// keyed by the returned session id. Both the options JSON (which
// the client passes to navigator.credentials.get) and the session
// id flow back to the client via the mfa_required response's
// mfa_method_data["webauthn"] bucket.
//
// The ceremony ALWAYS requires user verification (PIN/biometric),
// independent of the Helper's primary-login RequireUserVerification
// setting: a step-up second factor must actually verify the user, not be
// satisfied by mere user-presence (a tap). go-webauthn enforces the UV bit
// at Verify time because the stored session.UserVerification is pinned to
// "required" here.
func (p *WebAuthnMFAProvider) Begin(ctx context.Context, subjectID, method string) (map[string]string, error) {
	if method != MethodWebAuthn {
		return nil, ErrWebAuthnMFAUnsupportedMethod
	}
	if subjectID == "" {
		return nil, ErrWebAuthnMFAMissingSubject
	}
	assertion, sessionID, err := p.helper.beginLogin(ctx, subjectID, true)
	if err != nil {
		return nil, fmt.Errorf("webauthn_mfa: begin login: %w", err)
	}
	optsJSON, err := json.Marshal(assertion)
	if err != nil {
		return nil, fmt.Errorf("webauthn_mfa: marshal options: %w", err)
	}
	return map[string]string{
		"options": string(optsJSON),
		"session": sessionID,
	}, nil
}

// Verify completes the assertion ceremony. The client echoes
// session (from the Begin response) and assertion (the JSON output
// of navigator.credentials.get) in the /auth/mfa params payload.
// The go-webauthn library parses the assertion from an *http.Request
// body — Verify synthesizes one so the underlying API stays in its
// native shape.
//
// Subject mismatch (resolved user ≠ supplied SubjectID) is rejected
// before the success path so a captured session id can't be used to
// claim a different identity. Returned errors are intentionally
// distinct so the cmd-side / SDK-side audit trail can distinguish
// "wrong identity" from "bad signature" — the wire response still
// collapses both to mfa_invalid per [spi.MFAProvider]'s contract.
func (p *WebAuthnMFAProvider) Verify(ctx context.Context, subjectID, method string, params map[string]string) error {
	if method != MethodWebAuthn {
		return ErrWebAuthnMFAUnsupportedMethod
	}
	if subjectID == "" {
		return ErrWebAuthnMFAMissingSubject
	}
	sessionID := params["session"]
	if sessionID == "" {
		return ErrWebAuthnMFAMissingSession
	}
	assertion := params["assertion"]
	if assertion == "" {
		return ErrWebAuthnMFAMissingAssertion
	}
	// Synthetic request to bridge the SDK-style params payload into
	// the *http.Request shape go-webauthn expects. Path doesn't
	// matter — the library only reads Body.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/", bytes.NewReader([]byte(assertion)))
	if err != nil {
		return fmt.Errorf("webauthn_mfa: build assertion request: %w", err)
	}
	user, _, err := p.helper.FinishLogin(ctx, sessionID, req)
	if err != nil {
		return fmt.Errorf("webauthn_mfa: finish login: %w", err)
	}
	if user.Name != subjectID {
		return ErrWebAuthnMFASubjectMismatch
	}
	return nil
}

// Sentinel errors. Operator-side observability only — the SSO server
// collapses every Verify failure to mfa_invalid on the wire (anti-
// enumeration). Begin failures surface as a missing mfa_method_data
// entry for the method, which the client handles by either retrying
// or picking a different factor.
var (
	ErrWebAuthnMFAUnsupportedMethod = errors.New("webauthn_mfa: unsupported method")
	ErrWebAuthnMFAMissingSubject    = errors.New("webauthn_mfa: missing subject")
	ErrWebAuthnMFAMissingSession    = errors.New("webauthn_mfa: missing session")
	ErrWebAuthnMFAMissingAssertion  = errors.New("webauthn_mfa: missing assertion")
	ErrWebAuthnMFASubjectMismatch   = errors.New("webauthn_mfa: subject mismatch")
)

// Interface guards. Live in this package per the project convention
// (the implementation package asserts conformance to interfaces it
// publishes against — keeps the root sso package free of import
// cycles).
var (
	_ spi.MFAProvider = (*WebAuthnMFAProvider)(nil)
	_ spi.MFABeginner = (*WebAuthnMFAProvider)(nil)
)
