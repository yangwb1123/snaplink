package defaultimpl

import (
	"context"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/core"
)

// CompositeMFAEnrollmentStore fans a single sso.MFAEnrollmentStore view across
// several delegate stores so GET /me/mfa lists factors of every kind (e.g. TOTP
// secrets + WebAuthn passkeys) and DELETE /me/mfa/:id unbinds whichever store
// owns the factor. Mirrors the MultiMFAProvider composition discipline.
//
// ListFactors concatenates every delegate's factors (fail-fast on error).
// RemoveFactor calls each delegate in turn: every MFAEnrollmentStore.RemoveFactor
// is idempotent (a no-op on a factor it doesn't own, per the SPI contract), so
// the owning delegate removes it and the rest no-op — no ownership map needed.
// Delegates MUST mint distinct factor-ID namespaces (TOTP uses random base64
// strings, WebAuthn uses base64url credential IDs — collision-free).
type CompositeMFAEnrollmentStore struct {
	delegates []sso.MFAEnrollmentStore
}

// NewCompositeMFAEnrollmentStore composes delegates into one MFAEnrollmentStore.
// If a delegate also implements sso.TOTPEnrollmentWriter, the returned store
// ALSO satisfies it (forwarding to the first such delegate) — this keeps the
// POST /me/mfa/totp enrollment routes mounted, which gate on the wired
// enrollment store type-asserting to TOTPEnrollmentWriter. Without that
// forwarding, wrapping the TOTP store in a composite would silently unmount
// TOTP self-enrollment.
func NewCompositeMFAEnrollmentStore(delegates ...sso.MFAEnrollmentStore) sso.MFAEnrollmentStore {
	base := &CompositeMFAEnrollmentStore{delegates: delegates}
	for _, d := range delegates {
		if w, ok := d.(sso.TOTPEnrollmentWriter); ok {
			return &compositeMFAWithTOTP{CompositeMFAEnrollmentStore: base, writer: w}
		}
	}
	return base
}

// ListFactors returns the union of every delegate's factors for userID.
func (c *CompositeMFAEnrollmentStore) ListFactors(ctx context.Context, userID string) ([]core.MFAEnrolledFactor, error) {
	var out []core.MFAEnrolledFactor
	for _, d := range c.delegates {
		fs, err := d.ListFactors(ctx, userID)
		if err != nil {
			return nil, err
		}
		out = append(out, fs...)
	}
	if out == nil {
		out = []core.MFAEnrolledFactor{}
	}
	return out, nil
}

// RemoveFactor offers the unbind to every delegate; the owner removes it and the
// rest no-op (each RemoveFactor is idempotent per the SPI contract).
func (c *CompositeMFAEnrollmentStore) RemoveFactor(ctx context.Context, userID, factorID string) error {
	for _, d := range c.delegates {
		if err := d.RemoveFactor(ctx, userID, factorID); err != nil {
			return err
		}
	}
	return nil
}

// compositeMFAWithTOTP is the variant returned when a delegate is a
// TOTPEnrollmentWriter — it forwards AddTOTPFactor so the composite satisfies
// the interface the TOTP-enrollment route gate type-asserts.
type compositeMFAWithTOTP struct {
	*CompositeMFAEnrollmentStore
	writer sso.TOTPEnrollmentWriter
}

func (c *compositeMFAWithTOTP) AddTOTPFactor(ctx context.Context, userID, factorID, label string, secret []byte) error {
	return c.writer.AddTOTPFactor(ctx, userID, factorID, label, secret)
}

var (
	_ sso.MFAEnrollmentStore   = (*CompositeMFAEnrollmentStore)(nil)
	_ sso.MFAEnrollmentStore   = (*compositeMFAWithTOTP)(nil)
	_ sso.TOTPEnrollmentWriter = (*compositeMFAWithTOTP)(nil)
)
