// Package compliance provides cross-store data-subject workflows that
// regulations (GDPR Art. 17, CCPA, PIPL) require but that no single SPI
// owns — the stores each know how to delete their own slice of a
// subject's data, and this package orchestrates them into one auditable
// operation.
//
// It composes existing SPIs (core.UserProvider / core.SessionManager /
// core.ClientStore / oauth.RefreshTokenSubjectIndex) rather than adding
// new storage — so it works with any backend wired into the server, in
// memory or SQLite, with no new dependency. The package itself stays
// pure: it emits no audit and logs nothing, returning a structured
// Report the caller (admin handler / cmd) records however it audits.
package compliance

import (
	"context"
	"errors"
	"fmt"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/oauth"
)

// Eraser performs a "right to erasure" across the stores holding a
// subject's data. Every field is optional except where noted: a nil
// store means that slice of data is skipped (recorded in Report.Skipped),
// so an operator can run a partial erasure (e.g. token + session
// revocation only) by leaving Users nil. Refresh-token revocation needs
// BOTH Clients (to enumerate per-client token sets) and Refresh.
type Eraser struct {
	// Users deletes the subject's account. Delete is idempotent, so
	// re-running an erasure is safe.
	Users core.UserProvider
	// Sessions destroys the subject's active server-side sessions.
	Sessions core.SessionManager
	// Refresh revokes refresh tokens; requires Clients to enumerate the
	// (subject, client) pairs since the SPI is per-client.
	Refresh oauth.RefreshTokenSubjectIndex
	// Clients enumerates registered clients for Refresh revocation.
	Clients core.ClientStore
}

// EraseOptions tunes an erasure run.
type EraseOptions struct {
	// DryRun previews the erasure without mutating anything. Note:
	// refresh-token revocation cannot be previewed — RefreshTokenSubjectIndex
	// exposes only a destructive DeleteAllForSubject (no count), so a
	// dry run reports RefreshTokensDeleted=0 and notes the limitation in
	// Skipped. Sessions and the user-delete intent ARE previewed.
	DryRun bool
}

// Report is the structured outcome of an erasure, suitable for auditing.
// Steps are best-effort: a failure in one store is recorded in Errors but
// does not abort the others, so a single store outage can't strand the
// rest of the subject's data. Err aggregates any step failures.
type Report struct {
	UserID               string
	DryRun               bool
	RefreshTokensDeleted int
	SessionsDestroyed    int
	UserDeleted          bool
	// Skipped names steps skipped because their SPI wasn't wired (or,
	// for refresh tokens under DryRun, because the step isn't previewable).
	Skipped []string
	// Errors collects per-step failures in execution order.
	Errors []error
}

// Err returns the joined per-step errors, or nil if every step succeeded.
func (r *Report) Err() error { return errors.Join(r.Errors...) }

// EraseSubject revokes the subject's refresh tokens (across every client),
// destroys their active sessions, and deletes their account, in that
// order — credentials first so a deletion that fails midway still leaves
// the subject locked out rather than half-erased-but-usable. It is
// idempotent: a second run finds nothing to delete and returns a clean
// Report. The returned error mirrors Report.Err (best-effort aggregate).
func (e *Eraser) EraseSubject(ctx context.Context, userID string, opts EraseOptions) (*Report, error) {
	if userID == "" {
		return nil, errors.New("compliance: empty user id")
	}
	rep := &Report{UserID: userID, DryRun: opts.DryRun}

	// 1. Refresh tokens — per (subject, client), so enumerate clients.
	switch {
	case e.Refresh == nil || e.Clients == nil:
		rep.Skipped = append(rep.Skipped, "refresh_tokens(not wired)")
	case opts.DryRun:
		rep.Skipped = append(rep.Skipped, "refresh_tokens(dry-run: not previewable)")
	default:
		clients, err := e.Clients.List(ctx)
		if err != nil {
			rep.Errors = append(rep.Errors, fmt.Errorf("list clients: %w", err))
			break
		}
		for _, c := range clients {
			n, err := e.Refresh.DeleteAllForSubject(ctx, userID, c.ID)
			if err != nil {
				rep.Errors = append(rep.Errors, fmt.Errorf("revoke refresh tokens (client=%s): %w", c.ID, err))
				continue
			}
			rep.RefreshTokensDeleted += n
		}
	}

	// 2. Sessions.
	if e.Sessions == nil {
		rep.Skipped = append(rep.Skipped, "sessions(not wired)")
	} else if sessions, err := e.Sessions.ListByUser(ctx, userID); err != nil {
		rep.Errors = append(rep.Errors, fmt.Errorf("list sessions: %w", err))
	} else {
		for _, s := range sessions {
			if opts.DryRun {
				rep.SessionsDestroyed++ // would-destroy count
				continue
			}
			if err := e.Sessions.Destroy(ctx, s.ID); err != nil {
				rep.Errors = append(rep.Errors, fmt.Errorf("destroy session %s: %w", s.ID, err))
				continue
			}
			rep.SessionsDestroyed++
		}
	}

	// 3. User account.
	switch {
	case e.Users == nil:
		rep.Skipped = append(rep.Skipped, "user(not wired)")
	case opts.DryRun:
		// Intent only; Report.DryRun signals UserDeleted is a projection.
		rep.UserDeleted = true
	default:
		if err := e.Users.Delete(ctx, userID); err != nil {
			rep.Errors = append(rep.Errors, fmt.Errorf("delete user: %w", err))
		} else {
			rep.UserDeleted = true
		}
	}

	return rep, rep.Err()
}
