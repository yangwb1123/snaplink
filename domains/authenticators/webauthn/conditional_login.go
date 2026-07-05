package webauthn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	gw "github.com/go-webauthn/webauthn/webauthn"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// BeginConditionalLogin starts an authentication ceremony with
// conditional mediation (passkey autofill). The browser must have
// autocomplete="username webauthn" on the input element. Returns the
// same CredentialAssertion as BeginLogin but with mediation:
// 'conditional' set, enabling the browser's conditional UI (passkey
// autofill dropdown) rather than a modal dialog.
func (h *Helper) BeginConditionalLogin(ctx context.Context, name string) (*protocol.CredentialAssertion, string, error) {
	return h.beginConditionalLogin(ctx, name, h.requireUserVerification)
}

// beginConditionalLogin is the shared entry point behind
// [Helper.BeginConditionalLogin]. requireUV pins the assertion's
// user-verification requirement to "required"; false leaves the
// library default. The mediation is set to 'conditional' so the
// browser offers passkey autofill in non-modal UI.
func (h *Helper) beginConditionalLogin(ctx context.Context, name string, requireUV bool) (*protocol.CredentialAssertion, string, error) {
	user, err := h.users.GetByName(ctx, name)
	if err != nil {
		return nil, "", err
	}
	var opts []gw.LoginOption
	if requireUV {
		opts = append(opts, gw.WithUserVerification(protocol.VerificationRequired))
	}
	if h.ceremonyTimeout > 0 {
		timeoutMs := int(h.ceremonyTimeout.Milliseconds())
		opts = append(opts, func(cco *protocol.PublicKeyCredentialRequestOptions) {
			cco.Timeout = timeoutMs
		})
	}
	assertion, session, err := h.core.BeginMediatedLogin(user, protocol.MediationConditional, opts...)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin conditional login: %w", err)
	}
	sessionID, err := h.persistSession(ctx, session)
	if err != nil {
		return nil, "", err
	}
	return assertion, sessionID, nil
}

// BeginLoginConditional starts a conditional-mediation (passkey autofill)
// authentication ceremony without a username — the authenticator resolves
// the credential via discoverable credentials (resident keys / passkeys).
// The returned CredentialAssertion carries mediation:"conditional" so the
// browser presents available passkeys in the autofill dropdown rather than
// a modal dialog.
//
// Pair with [Helper.FinishLoginConditional]; not [Helper.FinishLogin],
// because the session has no user identity until the authenticator's
// userHandle is resolved at finish time.
//
// Callers SHOULD check PublicKeyCredential.isConditionalMediationAvailable()
// before invoking — older browsers that don't support conditional mediation
// will reject the call.
func (h *Helper) BeginLoginConditional(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	var opts []gw.LoginOption
	if h.ceremonyTimeout > 0 {
		timeoutMs := int(h.ceremonyTimeout.Milliseconds())
		opts = append(opts, func(cco *protocol.PublicKeyCredentialRequestOptions) {
			cco.Timeout = timeoutMs
		})
	}
	assertion, session, err := h.core.BeginDiscoverableMediatedLogin(protocol.MediationConditional, opts...)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin conditional login: %w", err)
	}
	sessionID, err := h.persistSession(ctx, session)
	if err != nil {
		return nil, "", err
	}
	return assertion, sessionID, nil
}

// FinishLoginConditional completes a conditional-mediation (passkey autofill)
// ceremony started by [Helper.BeginLoginConditional]. The user is resolved from
// the authenticator's userHandle via the UserStore's optional handle-resolution
// capability ([handleResolver]). The UserStore MUST implement GetByHandle or
// this returns an error.
//
// Signature-counter regression detection (CloneWarning) is enforced the same
// way as [Helper.FinishLogin].
func (h *Helper) FinishLoginConditional(ctx context.Context, sessionID string, r *http.Request) (*User, *gw.Credential, error) {
	session, err := h.sessions.Take(ctx, sessionID)
	if err != nil {
		return nil, nil, err
	}
	resolver, ok := h.users.(handleResolver)
	if !ok {
		return nil, nil, fmt.Errorf("webauthn: user store %T does not support handle resolution (required for conditional/discoverable login)", h.users)
	}
	handler := func(rawID, userHandle []byte) (gw.User, error) {
		u, err := resolver.GetByHandle(ctx, userHandle)
		if err != nil {
			return nil, err
		}
		return u, nil
	}
	user, cred, err := h.core.FinishPasskeyLogin(handler, *session, r)
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn: finish conditional login: %w", err)
	}
	if cred.Authenticator.CloneWarning {
		return nil, nil, ErrClonedAuthenticator
	}
	webauthnUser := user.(*User)
	if err := h.users.UpdateCredential(ctx, webauthnUser.Name, cred); err != nil {
		return nil, nil, fmt.Errorf("webauthn: persist updated credential: %w", err)
	}
	return webauthnUser, cred, nil
}

// MethodWebAuthnPrimary is the canonical Authenticator.Name() / /auth/login
// `provider` value for passwordless passkey PRIMARY login. It happens to
// equal [MethodWebAuthn] ("webauthn"), but the two live in entirely separate
// registries — MethodWebAuthn tags an mfa_methods / /auth/mfa step-up factor
// (s.mfaProvider, keyed by SupportedMethods()); MethodWebAuthnPrimary names an
// entry in s.authenticators (keyed by Authenticator.Name()). A server can run
// WebAuthn as a step-up factor, as a primary authenticator, or (additively,
// the common case once passkey login is opted into) both at once, sharing one
// Helper / UserStore / SessionStore.
const MethodWebAuthnPrimary = "webauthn"

// WebAuthnPrimaryAuthenticator adapts the discoverable-credential (resident
// key / passkey) login ceremony to [core.Authenticator] so passwordless
// passkey login flows through the SAME /auth/login pipeline (lockout, ACR,
// risk-scoring, consent, PKCE/code flow, tenant/residency gates, audit) every
// other authenticator uses — no parallel login pathway, no bespoke token
// minting.
//
// WebAuthn's ceremony is inherently two-call (begin issues a challenge;
// finish verifies the signed assertion) while Authenticate is single-call.
// The split is bridged the SAME way [WebAuthnMFAProvider] bridges MFA
// step-up: the UNAUTHENTICATED standalone endpoint
// (POST /webauthn/login/conditional/begin — already mounted; no changes
// needed) issues the challenge; the caller then relays its "session_id" and
// the browser's navigator.credentials.get() response ("assertion", the raw
// JSON body) through AuthRequest.Credential to THIS Authenticate, which
// performs the finish/verify step and resolves the signed-in identity from
// the discoverable credential's userHandle — the user never types a
// username.
//
// Wire shape (POST /auth/login):
//
//	{"provider": "webauthn", "client_id": "...",
//	 "credential": {"session_id": "<from begin>", "assertion": "<credentials.get() JSON>"}}
type WebAuthnPrimaryAuthenticator struct {
	helper *Helper
	logger spi.Logger // optional; nil = silent
}

// WebAuthnPrimaryOption configures a WebAuthnPrimaryAuthenticator at construction.
type WebAuthnPrimaryOption func(*WebAuthnPrimaryAuthenticator)

// WithWebAuthnPrimaryLogger attaches an optional logger for ceremony-failure
// diagnostics. Never changes the login outcome (the wire response stays
// oracle-safe regardless of whether a logger is wired); a nil logger — or
// simply not passing this option — keeps the authenticator silent.
func WithWebAuthnPrimaryLogger(l spi.Logger) WebAuthnPrimaryOption {
	return func(a *WebAuthnPrimaryAuthenticator) { a.logger = l }
}

// NewWebAuthnPrimaryAuthenticator wraps an existing Helper as a primary,
// passwordless core.Authenticator. Pass the SAME Helper backing the
// standalone /webauthn/* ceremony routes and (optionally) step-up MFA — one
// UserStore + one SessionStore shared across every consumer role, so a
// passkey registered once works everywhere. Returns an error when h is nil.
func NewWebAuthnPrimaryAuthenticator(h *Helper, opts ...WebAuthnPrimaryOption) (*WebAuthnPrimaryAuthenticator, error) {
	if h == nil {
		return nil, errors.New("webauthn_primary: Helper required")
	}
	a := &WebAuthnPrimaryAuthenticator{helper: h}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// Name returns "webauthn" — the /auth/login `provider` value a client
// selects to drive passwordless passkey login.
func (a *WebAuthnPrimaryAuthenticator) Name() string { return MethodWebAuthnPrimary }

// Authenticate completes the discoverable-credential assertion ceremony
// started by POST /webauthn/login/conditional/begin. It requires
// Credential["session_id"] (the begin response's session id) and
// Credential["assertion"] (the raw JSON body navigator.credentials.get()
// produced) — missing either is a plain validation error, collapsed to the
// generic invalid_credentials response like any other authenticator's
// malformed-input case (no session lookup has happened yet, so nothing to
// leak by distinguishing this case).
//
// A session/identity-resolution failure (unknown or expired session, or the
// resolved userHandle no longer mapping to a user) is wrapped in
// [core.ErrCeremonySessionInvalid] so /auth/login's generic failure path
// renders the SAME oracle-safe 404 session_invalid the standalone ceremony
// endpoints use (see [ErrSessionUnknown], [ErrSessionExpired],
// [ErrUserUnknown]) — a caller cannot distinguish "no such session" from "no
// such user" (both collapse alike here, exactly as the standalone HTTP
// handler's error-status mapping collapses them), nor tell reaching that
// state via /auth/login apart from reaching it via
// /webauthn/login/conditional/finish. Any OTHER ceremony failure (bad
// signature, challenge mismatch, cloned authenticator) falls through to the
// ordinary invalid_credentials collapse — a different bucket, deliberately:
// those are not a session-existence question.
func (a *WebAuthnPrimaryAuthenticator) Authenticate(ctx context.Context, req *sso.AuthRequest) (*sso.AuthResult, error) {
	sessionID := req.Credential["session_id"]
	assertion := req.Credential["assertion"]
	if sessionID == "" || assertion == "" {
		return nil, errors.New("webauthn_primary: session_id and assertion required")
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "/", bytes.NewReader([]byte(assertion)))
	if err != nil {
		return nil, fmt.Errorf("webauthn_primary: build assertion request: %w", err)
	}
	user, _, err := a.helper.FinishLoginConditional(ctx, sessionID, httpReq)
	if err != nil {
		return nil, a.classifyFinishError(err)
	}
	return &sso.AuthResult{
		UserID:      user.Name,
		Provider:    a.Name(),
		AuthMethods: []string{MethodWebAuthnPrimary},
	}, nil
}

// classifyFinishError wraps a FinishLoginConditional failure so the caller
// (handleAuthFailure) can tell a stateful-ceremony problem apart from any
// other assertion failure — see the Authenticate doc comment for the full
// oracle-safety rationale.
func (a *WebAuthnPrimaryAuthenticator) classifyFinishError(err error) error {
	if errors.Is(err, ErrSessionUnknown) || errors.Is(err, ErrSessionExpired) || errors.Is(err, ErrUserUnknown) {
		if a.logger != nil {
			a.logger.Error("webauthn primary login: ceremony session invalid", "error", err)
		}
		return fmt.Errorf("webauthn_primary: %w: %w", core.ErrCeremonySessionInvalid, err)
	}
	if a.logger != nil {
		a.logger.Error("webauthn primary login: ceremony failed", "error", err)
	}
	return fmt.Errorf("webauthn_primary: finish login: %w", err)
}

// Callback is not supported — WebAuthn is a direct ceremony, never an
// external-IdP redirect flow.
func (a *WebAuthnPrimaryAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, errors.New("webauthn_primary: callback not supported")
}

// LoginURL always returns "" — passkey login is a direct, in-page ceremony
// (navigator.credentials.get()), never a redirect.
func (a *WebAuthnPrimaryAuthenticator) LoginURL(_ string) string { return "" }

// LockoutIdentity declares this credential lockout-UNKEYABLE: a signed
// WebAuthn assertion is not a guessable secret (nothing for a brute-force
// loop to iterate), and — critically — no stable per-account identity exists
// in the credential map BEFORE the ceremony verifies (the discoverable flow
// carries only an opaque session_id + assertion; the identity is the
// ceremony's OUTPUT, not its input). Returning "" skips the per-account
// lockout gate for this authenticator entirely rather than falling back to
// the generic field-precedence key (which would key on nothing meaningful),
// matching [core.LockoutKeyer]'s documented escape hatch.
func (a *WebAuthnPrimaryAuthenticator) LockoutIdentity(_ map[string]string) string { return "" }

// Interface guards. Live in this package per the project convention (the
// implementation package asserts conformance to interfaces it publishes
// against — keeps the root sso package free of import cycles).
var (
	_ sso.Authenticator = (*WebAuthnPrimaryAuthenticator)(nil)
	_ sso.LockoutKeyer  = (*WebAuthnPrimaryAuthenticator)(nil)
)
