package webauthn

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/snaplink/sso/interfaces/sso"
)

// mfaFactorLabel is the human-facing label for a passkey in /me/mfa.
// gw.Credential carries no per-credential friendly name, so all passkeys share
// this label; the portal's remove action targets the opaque factor ID, so a
// user with multiple passkeys still removes the right one.
const mfaFactorLabel = "Passkey"

// MFAEnrollmentAdapter presents a user's registered WebAuthn passkeys as
// sso.MFAEnrollmentStore factors so they appear in GET /me/mfa and unbind via
// DELETE /me/mfa/:id alongside TOTP — completing the self-service MFA view.
//
// It lives in this package (next to the UserStore it adapts) rather than in
// defaultimpl so defaultimpl — and everything that imports it (redis, etc.) —
// stays free of the go-webauthn dependency.
//
// It bridges the two key models: the WebAuthn UserStore is keyed by the
// registration USERNAME, while /me/mfa speaks the bearer's USER ID. In the
// stock binary those are the same string (the WebAuthn login/registration token
// subject IS the User.Name), so userID is used directly as the username.
// Operators who mint subjects differently must front this with their own
// resolver.
//
// The factor ID is base64url(rawURL, no padding) of the credential ID — a
// stable, collision-free handle (TOTP factor IDs are random base64 strings;
// credential IDs are CTAP bytes). AddedAt is omitted (gw.Credential carries no
// registration timestamp; the field is json omitzero).
type MFAEnrollmentAdapter struct {
	users UserStore
}

// NewMFAEnrollmentAdapter wraps a UserStore. Compose it with the TOTP store via
// defaultimpl.NewCompositeMFAEnrollmentStore to show both factor kinds.
func NewMFAEnrollmentAdapter(users UserStore) *MFAEnrollmentAdapter {
	return &MFAEnrollmentAdapter{users: users}
}

// ListFactors returns userID's passkeys as MFAEnrolledFactor entries. A user
// with no WebAuthn enrollment yields an empty slice (not an error).
func (a *MFAEnrollmentAdapter) ListFactors(ctx context.Context, userID string) ([]sso.MFAEnrolledFactor, error) {
	u, err := a.users.GetByName(ctx, userID)
	if errors.Is(err, ErrUserUnknown) {
		return []sso.MFAEnrolledFactor{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]sso.MFAEnrolledFactor, 0, len(u.Credentials))
	for _, c := range u.Credentials {
		out = append(out, sso.MFAEnrolledFactor{
			ID:     base64.RawURLEncoding.EncodeToString(c.ID),
			Method: MethodWebAuthn,
			Label:  mfaFactorLabel,
		})
	}
	return out, nil
}

// RemoveFactor unbinds the passkey whose base64url factorID matches. Idempotent:
// a non-decodable factorID, an unknown user, or an absent credential are all
// no-ops (nil) — so it composes safely behind a fan-out where the handler has
// already enforced ownership via ListFactors.
func (a *MFAEnrollmentAdapter) RemoveFactor(ctx context.Context, userID, factorID string) error {
	raw, err := base64.RawURLEncoding.DecodeString(factorID)
	if err != nil {
		// Not a WebAuthn factor ID (e.g. a TOTP id routed here by the composite).
		return nil
	}
	if err := a.users.RemoveCredential(ctx, userID, raw); err != nil && !errors.Is(err, ErrUserUnknown) {
		return err
	}
	return nil
}

var _ sso.MFAEnrollmentStore = (*MFAEnrollmentAdapter)(nil)
