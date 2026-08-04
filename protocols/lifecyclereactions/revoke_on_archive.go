package lifecyclereactions

import (
	"context"
	"errors"

	"github.com/yangwb1123/snaplink/domains/userlifecycle"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// RevokeAccessOnArchive returns a userlifecycle.ReactionFunc that revokes
// every refresh token (across every client) and destroys every
// active session for a user the moment they transition into ARCHIVED — the
// reference "user ARCHIVED -> revoke all sessions and refresh tokens"
// reaction, wired via bus.OnUserArchived(RevokeAccessOnArchive(...)).
//
// Credentials-first ordering (refresh tokens before sessions) and
// best-effort-across-stores semantics mirror
// protocols/caep.StoreRevoker.RevokeAllForSubject and
// protocols/compliance.Eraser: a failure partway through still leaves the
// account MORE locked out, never less, and a single store/client error is
// collected rather than a reason to abandon the rest. Idempotent — a second
// call (or a re-ARCHIVED account) finds nothing left to revoke.
//
// sessions and/or (refresh + clients) may be nil to skip that leg entirely
// (e.g. a deployment with no session manager wired); RevokeAccessOnArchive
// still performs whichever leg(s) it can. This is a reaction, not the state
// machine itself — an operator who does not want this behavior simply never
// registers it; domains/userlifecycle's transition table and stores are
// completely unaware this function exists.
func RevokeAccessOnArchive(sessions core.SessionManager, refresh oauth.RefreshTokenSubjectIndex, clients core.ClientStore) userlifecycle.ReactionFunc {
	_ = clients // retained for source compatibility; the index supports all-client deletion.
	return RevokeAccess(sessions, refresh)
}

// RevokeAccessOnSuspend is the SUSPENDED-state counterpart of
// RevokeAccessOnArchive. It is separate for readable composition wiring while
// sharing the same idempotent, best-effort implementation.
func RevokeAccessOnSuspend(sessions core.SessionManager, refresh oauth.RefreshTokenSubjectIndex) userlifecycle.ReactionFunc {
	return RevokeAccess(sessions, refresh)
}

// RevokeAccess revokes every renewable credential and canonical session for a
// subject. It is suitable for any lifecycle state that disallows
// authentication, including SUSPENDED, INACTIVE, ARCHIVED, and PURGED.
func RevokeAccess(sessions core.SessionManager, refresh oauth.RefreshTokenSubjectIndex) userlifecycle.ReactionFunc {
	return func(ctx context.Context, userID string) error {
		if userID == "" {
			return nil
		}
		var errs []error
		if refresh != nil {
			if err := revokeRefreshTokens(ctx, refresh, userID); err != nil {
				errs = append(errs, err)
			}
		}
		if sessions != nil {
			if err := destroySessions(ctx, sessions, userID); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
}

// revokeRefreshTokens deletes userID's refresh tokens for every registered
// client (the SPI is per-client — see oauth.RefreshTokenSubjectIndex).
// Best-effort across clients: one client's failure doesn't stop the rest.
func revokeRefreshTokens(ctx context.Context, refresh oauth.RefreshTokenSubjectIndex, userID string) error {
	_, err := refresh.DeleteAllForSubject(ctx, userID, "")
	return err
}

// destroySessions destroys every active session userID holds. Best-effort
// across sessions: one session's failure doesn't stop the rest.
func destroySessions(ctx context.Context, sessions core.SessionManager, userID string) error {
	list, err := sessions.ListByUser(ctx, userID)
	if err != nil {
		return err
	}
	var errs []error
	for _, s := range list {
		if s == nil {
			continue
		}
		if err := sessions.Destroy(ctx, s.ID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
