package webauthn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/snaplink/sso"
)

// Registrar adapts the WebAuthn ceremony Helper to the sso.WebAuthnRegistrar
// seam the server's AUTHENTICATED self-service passkey endpoints
// (POST /me/mfa/webauthn/{begin,finish}) call. The server can't import this
// package (it imports the server), so the dependency is inverted through the
// interface.
//
// The server always passes the bearer SUBJECT as the begin user, and finish
// binds to the begin session's user — so a passkey can only be added to the
// caller's own account. This is the SAFE counterpart to the unauthenticated
// signup ceremony (which takes the username from the request body).
type Registrar struct {
	h *Helper
}

// NewRegistrar wraps a ceremony Helper for self-service registration. Pass the
// SAME Helper that backs the /webauthn/* ceremony routes so registered
// credentials share one store (and surface in /me/mfa via the adapter).
func NewRegistrar(h *Helper) *Registrar { return &Registrar{h: h} }

// BeginRegistration starts a ceremony for userID and returns the marshaled
// CredentialCreation options + the opaque session id.
func (r *Registrar) BeginRegistration(ctx context.Context, userID, displayName string) ([]byte, string, error) {
	creation, sessionID, err := r.h.BeginRegistration(ctx, userID, displayName)
	if err != nil {
		return nil, "", err
	}
	body, err := json.Marshal(creation)
	if err != nil {
		return nil, "", err
	}
	return body, sessionID, nil
}

// FinishRegistration verifies the attestation in req against the session and
// persists the credential against the session's user, returning the new
// credential id (base64url, the /me/mfa factor handle).
func (r *Registrar) FinishRegistration(ctx context.Context, sessionID string, req *http.Request) (string, error) {
	cred, err := r.h.FinishRegistration(ctx, sessionID, req)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(cred.ID), nil
}

var _ sso.WebAuthnRegistrar = (*Registrar)(nil)
