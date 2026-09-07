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

	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
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
	// PasswordCredentials removes the stored password hash when the optional
	// credential store extension is supported. It runs before Users so a
	// mid-operation failure cannot leave a live password behind.
	PasswordCredentials core.PasswordCredentialDeleter
	// Sessions destroys the subject's active server-side sessions.
	Sessions core.SessionManager
	// Refresh revokes refresh tokens; requires Clients to enumerate the
	// (subject, client) pairs since the SPI is per-client.
	Refresh oauth.RefreshTokenSubjectIndex
	// Clients enumerates registered clients for Refresh revocation.
	Clients core.ClientStore
	// Consent revokes the subject's recorded consent grants so a re-registered
	// account under the same id does NOT silently inherit prior consent (which
	// would bypass the consent gate). Optional (nil -> skipped).
	Consent core.ConsentStore
	// MFAEnrollments removes the subject's registered second factors so a
	// re-registered account doesn't inherit (or get locked out by) stale TOTP /
	// WebAuthn enrollments. Optional (nil -> skipped).
	MFAEnrollments core.MFAEnrollmentStore
	// PasswordReset / EmailChange revoke any pending self-service tokens bound to
	// the subject. Optional (nil / not a *Revoker -> skipped).
	PasswordReset           core.PasswordResetRevoker
	EmailChange             core.EmailChangeRevoker
	Notifications           core.NotificationStore
	NotificationPreferences core.NotificationPreferenceStore
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
	UserID                    string
	DryRun                    bool
	RefreshTokensDeleted      int
	SessionsDestroyed         int
	ConsentRevoked            int
	MFAFactorsRemoved         int
	ResetTokensRevoked        int
	EmailChangeTokensRevoked  int
	PasswordCredentialDeleted bool
	NotificationsDeleted      bool
	UserDeleted               bool
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
	e.erasePasswordCredential(ctx, userID, opts, rep)
	e.eraseRefreshTokens(ctx, userID, opts, rep)
	e.eraseSessions(ctx, userID, opts, rep)
	// Clear inheritable state BEFORE deleting the account so a re-registered id
	// can't inherit prior consent / second factors / pending self-service tokens.
	e.eraseConsent(ctx, userID, opts, rep)
	e.eraseMFAEnrollments(ctx, userID, opts, rep)
	e.eraseSelfServiceTokens(ctx, userID, opts, rep)
	e.eraseNotifications(ctx, userID, opts, rep)
	e.eraseUser(ctx, userID, opts, rep)

	return rep, rep.Err()
}

func (e *Eraser) erasePasswordCredential(ctx context.Context, userID string, opts EraseOptions, rep *Report) {
	// Keep the pre-existing response shape for deployments without a password
	// store: this optional step is invisible when its dependency is absent.
	if e.PasswordCredentials == nil {
		return
	}
	if opts.DryRun {
		rep.Skipped = append(rep.Skipped, "password_credential(dry-run not previewable)")
		return
	}
	if err := e.PasswordCredentials.DeletePassword(ctx, userID); err != nil {
		rep.Errors = append(rep.Errors, fmt.Errorf("delete password credential: %w", err))
		return
	}
	rep.PasswordCredentialDeleted = true
}

func (e *Eraser) eraseNotifications(ctx context.Context, userID string, opts EraseOptions, rep *Report) {
	if opts.DryRun {
		rep.Skipped = append(rep.Skipped, "notifications(dry-run not previewable)")
		return
	}
	if e.Notifications == nil {
		rep.Skipped = append(rep.Skipped, "notifications(not wired)")
	} else if err := e.Notifications.DeleteForSubject(ctx, userID); err != nil {
		rep.Errors = append(rep.Errors, fmt.Errorf("delete notifications: %w", err))
	} else {
		rep.NotificationsDeleted = true
	}
	if e.NotificationPreferences != nil {
		if err := e.NotificationPreferences.DeleteForSubject(ctx, userID); err != nil {
			rep.Errors = append(rep.Errors, fmt.Errorf("delete notification preferences: %w", err))
		}
	}
}

// eraseConsent revokes every recorded consent grant for the subject so a
// re-registered account under the same id does not inherit prior consent.
func (e *Eraser) eraseConsent(ctx context.Context, userID string, opts EraseOptions, rep *Report) {
	if e.Consent == nil {
		rep.Skipped = append(rep.Skipped, "consent(not wired)")
		return
	}
	grants, err := e.Consent.ListByUser(ctx, userID)
	if err != nil {
		rep.Errors = append(rep.Errors, fmt.Errorf("list consent: %w", err))
		return
	}
	for _, g := range grants {
		if opts.DryRun {
			rep.ConsentRevoked++
			continue
		}
		if err := e.Consent.RevokeConsent(ctx, userID, g.ClientID); err != nil {
			rep.Errors = append(rep.Errors, fmt.Errorf("revoke consent %s: %w", g.ClientID, err))
			continue
		}
		rep.ConsentRevoked++
	}
}

// eraseMFAEnrollments removes every registered second factor for the subject.
func (e *Eraser) eraseMFAEnrollments(ctx context.Context, userID string, opts EraseOptions, rep *Report) {
	if e.MFAEnrollments == nil {
		rep.Skipped = append(rep.Skipped, "mfa_enrollments(not wired)")
		return
	}
	factors, err := e.MFAEnrollments.ListFactors(ctx, userID)
	if err != nil {
		rep.Errors = append(rep.Errors, fmt.Errorf("list mfa factors: %w", err))
		return
	}
	for _, f := range factors {
		if opts.DryRun {
			rep.MFAFactorsRemoved++
			continue
		}
		if err := e.MFAEnrollments.RemoveFactor(ctx, userID, f.ID); err != nil {
			rep.Errors = append(rep.Errors, fmt.Errorf("remove mfa factor %s: %w", f.ID, err))
			continue
		}
		rep.MFAFactorsRemoved++
	}
}

// eraseSelfServiceTokens revokes pending password-reset + email-change tokens.
// Both backends expose RevokeByUser only as an OPTIONAL extension, so a nil
// store is simply skipped. DryRun can't preview a count without a List SPI, so
// it records the step as skipped under DryRun.
func (e *Eraser) eraseSelfServiceTokens(ctx context.Context, userID string, opts EraseOptions, rep *Report) {
	if opts.DryRun {
		rep.Skipped = append(rep.Skipped, "self_service_tokens(dry-run not previewable)")
		return
	}
	if e.PasswordReset != nil {
		if n, err := e.PasswordReset.RevokeByUser(ctx, userID); err != nil {
			rep.Errors = append(rep.Errors, fmt.Errorf("revoke password-reset tokens: %w", err))
		} else {
			rep.ResetTokensRevoked += n
		}
	}
	if e.EmailChange != nil {
		if n, err := e.EmailChange.RevokeByUser(ctx, userID); err != nil {
			rep.Errors = append(rep.Errors, fmt.Errorf("revoke email-change tokens: %w", err))
		} else {
			// Keep ResetTokensRevoked's historical aggregate semantics while
			// exposing a distinct count for callers that need one.
			rep.ResetTokensRevoked += n
			rep.EmailChangeTokensRevoked += n
		}
	}
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
