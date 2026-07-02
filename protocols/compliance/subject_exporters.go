package compliance

import (
	"context"

	"github.com/snaplink/sso/shared/core"
)

// Bundle keys for the built-in SubjectExporter implementations below. Named
// consts (not inline literals) so callers checking a bundle for these keys
// (tests, downstream consumers) don't duplicate the string. Chosen to mirror
// the Eraser's field names (Consent, MFAEnrollments) for the same domains.
const (
	ExportKeyConsent        = "consent"
	ExportKeyMFAEnrollments = "mfa_enrollments"
)

// ConsentSubjectExporter contributes the subject's recorded consent grants to
// a GDPR export bundle under ExportKeyConsent. Mirrors the read half of
// Eraser.eraseConsent (erasure.go) — same store, same ListByUser call — so
// export and erasure agree on what "the subject's consent data" is.
type ConsentSubjectExporter struct {
	Store core.ConsentStore
}

func (c ConsentSubjectExporter) ExportKey() string { return ExportKeyConsent }

// ExportSubject returns (nil, nil) when Store is unwired, matching the
// Exporter's documented "nothing for this subject" contract rather than
// erroring — an operator who hasn't wired consent shouldn't see export
// failures for it.
func (c ConsentSubjectExporter) ExportSubject(ctx context.Context, userID string) (any, error) {
	if c.Store == nil {
		return nil, nil
	}
	return c.Store.ListByUser(ctx, userID)
}

// MFAEnrollmentSubjectExporter contributes the subject's registered second
// factors under ExportKeyMFAEnrollments. core.MFAEnrolledFactor carries only
// non-sensitive metadata (id/method/label/added_at) by construction — its
// doc comment states it "never [carries] the TOTP secret or WebAuthn private
// material" — so no redaction step is needed here (unlike User.Attributes in
// export.go, which denylist-strips credential keys before export). Mirrors
// the read half of Eraser.eraseMFAEnrollments.
type MFAEnrollmentSubjectExporter struct {
	Store core.MFAEnrollmentStore
}

func (m MFAEnrollmentSubjectExporter) ExportKey() string { return ExportKeyMFAEnrollments }

func (m MFAEnrollmentSubjectExporter) ExportSubject(ctx context.Context, userID string) (any, error) {
	if m.Store == nil {
		return nil, nil
	}
	return m.Store.ListFactors(ctx, userID)
}

// SubjectExporters assembles the Extra exporters for whichever of the given
// stores are wired, skipping nils, so both cmd/sso-server call sites (admin
// handler + self-service late-bind) and any SDK consumer wiring their own
// binary compose without repeating the nil-check boilerplate.
func SubjectExporters(consent core.ConsentStore, mfa core.MFAEnrollmentStore) []SubjectExporter {
	var out []SubjectExporter
	if consent != nil {
		out = append(out, ConsentSubjectExporter{Store: consent})
	}
	if mfa != nil {
		out = append(out, MFAEnrollmentSubjectExporter{Store: mfa})
	}
	return out
}

var (
	_ SubjectExporter = ConsentSubjectExporter{}
	_ SubjectExporter = MFAEnrollmentSubjectExporter{}
)
