package webauthn

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	gw "github.com/go-webauthn/webauthn/webauthn"
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
