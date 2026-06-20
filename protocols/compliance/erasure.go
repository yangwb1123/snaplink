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

	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
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
	// DryRun previews the erasure without mutating anything. Refresh-token
	// counts are previewed when the store also implements
	// oauth.RefreshTokenSubjectCounter; otherwise that step is noted in
	// Skipped (the index-only SPI exposes no non-destructive count).
	// Sessions and the user-delete intent are always previewed.
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

	// Credentials first so a deletion that fails midway still leaves the
	// subject locked out rather than half-erased-but-usable.
	e.eraseRefreshTokens(ctx, userID, opts, rep)
	e.eraseSessions(ctx, userID, opts, rep)
	e.eraseUser(ctx, userID, opts, rep)

	return rep, rep.Err()
}

// eraseRefreshTokens revokes the subject's refresh tokens across every
// client. Tokens are stored per (subject, client), so it enumerates clients
// first. Under DryRun it projects counts non-destructively when the store
// supports it.
func (e *Eraser) eraseRefreshTokens(ctx context.Context, userID string, opts EraseOptions, rep *Report) {
	switch {
	case e.Refresh == nil || e.Clients == nil:
		rep.Skipped = append(rep.Skipped, "refresh_tokens(not wired)")
	case opts.DryRun:
		e.previewRefreshTokens(ctx, userID, rep)
	default:
		e.revokeRefreshTokens(ctx, userID, rep)
	}
}

// previewRefreshTokens projects the per-client token counts without
// mutating anything, when the store exposes a non-destructive count;
// otherwise it notes the limitation.
func (e *Eraser) previewRefreshTokens(ctx context.Context, userID string, rep *Report) {
	counter, ok := e.Refresh.(oauth.RefreshTokenSubjectCounter)
	if !ok {
		rep.Skipped = append(rep.Skipped, "refresh_tokens(dry-run: store has no CountForSubject)")
		return
	}
	clients, err := e.Clients.List(ctx)
	if err != nil {
		rep.Errors = append(rep.Errors, fmt.Errorf("list clients: %w", err))
		return
	}
	for _, c := range clients {
		n, err := counter.CountForSubject(ctx, userID, c.ID)
		if err != nil {
			rep.Errors = append(rep.Errors, fmt.Errorf("count refresh tokens (client=%s): %w", c.ID, err))
			continue
		}
		rep.RefreshTokensDeleted += n // projected count under DryRun
	}
}

// revokeRefreshTokens destructively deletes the subject's refresh tokens
// for every registered client.
func (e *Eraser) revokeRefreshTokens(ctx context.Context, userID string, rep *Report) {
	clients, err := e.Clients.List(ctx)
	if err != nil {
		rep.Errors = append(rep.Errors, fmt.Errorf("list clients: %w", err))
		return
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

// eraseSessions destroys the subject's active server-side sessions. Under
// DryRun it counts the sessions that would be destroyed.
func (e *Eraser) eraseSessions(ctx context.Context, userID string, opts EraseOptions, rep *Report) {
	if e.Sessions == nil {
		rep.Skipped = append(rep.Skipped, "sessions(not wired)")
		return
	}
	sessions, err := e.Sessions.ListByUser(ctx, userID)
	if err != nil {
		rep.Errors = append(rep.Errors, fmt.Errorf("list sessions: %w", err))
		return
	}
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

// eraseUser deletes the subject's account. Under DryRun it records the
// intent only; Report.DryRun signals UserDeleted is a projection.
func (e *Eraser) eraseUser(ctx context.Context, userID string, opts EraseOptions, rep *Report) {
	switch {
	case e.Users == nil:
		rep.Skipped = append(rep.Skipped, "user(not wired)")
	case opts.DryRun:
		rep.UserDeleted = true
	default:
		if err := e.Users.Delete(ctx, userID); err != nil {
			rep.Errors = append(rep.Errors, fmt.Errorf("delete user: %w", err))
		} else {
			rep.UserDeleted = true
		}
	}
}
