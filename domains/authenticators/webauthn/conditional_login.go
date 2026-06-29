package webauthn

import (
	"context"
	"fmt"

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
