package compliance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/core"
)

// SubjectExporter is an OPTIONAL extension a store (or any subsystem)
// implements to contribute its slice of a subject's data to a GDPR
// Art. 15 / Art. 20 export. The Exporter calls every registered one and
// files the result under Key in the export bundle, so new data domains
// (permissions, audit history, MFA enrollments) plug in without changing
// the Exporter itself.
type SubjectExporter interface {
	// ExportSubject returns this domain's data for userID, JSON-
	// marshalable. Returning (nil, nil) means "nothing for this
	// subject" and is filed as an empty entry.
	ExportSubject(ctx context.Context, userID string) (any, error)
	// ExportKey is the bundle key this exporter's data lands under
	// (e.g. "permissions"). MUST be stable + unique across exporters.
	ExportKey() string
}

// Exporter assembles a portable copy of a subject's data across stores —
// the read-side counterpart to Eraser. It composes the built-in
// UserProvider + SessionManager reads with any number of SubjectExporter
// extensions. Refresh tokens are intentionally absent: opaque secrets
// must never be exported (their hashes carry no portability value and
// re-emitting them would be a credential leak), and the SPI exposes no
// safe read of them anyway.
type Exporter struct {
	Users    core.UserProvider
	Sessions core.SessionManager
	Extra    []SubjectExporter
}

// Export is the assembled bundle, JSON-marshalable as-is for delivery to
// the data subject. Data maps a domain key ("user", "sessions", plus any
// SubjectExporter keys) to that domain's payload.
type Export struct {
	Subject     string         `json:"subject"`
	GeneratedAt time.Time      `json:"generated_at"`
	Data        map[string]any `json:"data"`
}

// ExportSubject collects the subject's data across every wired store.
// Best-effort: a failing store is recorded in the returned (joined)
// error but does not abort the others, so the subject still receives a
// partial bundle rather than nothing. The bundle is always non-nil.
func (e *Exporter) ExportSubject(ctx context.Context, userID string) (*Export, error) {
	if userID == "" {
		return nil, errors.New("compliance: empty user id")
	}
	exp := &Export{Subject: userID, GeneratedAt: time.Now().UTC(), Data: map[string]any{}}
	var errs []error

	if e.Users != nil {
		u, err := e.Users.GetByID(ctx, userID)
		if err != nil {
			errs = append(errs, fmt.Errorf("user: %w", err))
		} else {
			exp.Data["user"] = u
		}
	}
	if e.Sessions != nil {
		sessions, err := e.Sessions.ListByUser(ctx, userID)
		if err != nil {
			errs = append(errs, fmt.Errorf("sessions: %w", err))
		} else {
			exp.Data["sessions"] = sessions
		}
	}
	for _, x := range e.Extra {
		d, err := x.ExportSubject(ctx, userID)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", x.ExportKey(), err))
			continue
		}
		exp.Data[x.ExportKey()] = d
	}

	return exp, errors.Join(errs...)
}
