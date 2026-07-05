package userlifecycle

import (
	"context"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// LastActiveSource reports the most recent instant a user was active — the
// signal dormancy detection compares against the configured threshold. It is a
// narrow read seam so the "last active" definition can be derived from whatever
// activity data a deployment already has (live sessions, a recorded login
// timestamp, an audit query) without this package taking a hard dependency on
// any one of them.
//
// LastActive returns the zero time.Time when there is NO activity signal for
// userID (never seen, or the source cannot answer). A zero time is treated as
// "unknown, do NOT deprovision" by IsDormant — dormancy detection is fail-safe:
// it only ever acts on positive evidence of inactivity, never on absence of
// data.
type LastActiveSource interface {
	LastActive(ctx context.Context, userID string) (time.Time, error)
}

// IsDormant reports whether a user whose most recent activity was lastActive is
// dormant as of now under threshold: true only when lastActive is non-zero AND
// older than now-threshold. A zero lastActive (no signal) or a non-positive
// threshold (feature off) is never dormant — the conservative default that
// keeps auto-deprovisioning from acting on accounts it has no evidence about.
func IsDormant(lastActive, now time.Time, threshold time.Duration) bool {
	if threshold <= 0 || lastActive.IsZero() {
		return false
	}
	return now.Sub(lastActive) > threshold
}

// SessionLastActive derives a LastActiveSource from the existing
// core.SessionManager: a user's "last active" is the newest CreatedAt among
// their live sessions. It computes the signal from data the server already
// keeps — no new activity store required — and needs only ListByUser.
//
// Caveat (documented, deliberate): because expired sessions are pruned, this
// reflects activity only within the session-retention window; a user with no
// live session reads as zero (unknown), which IsDormant treats as "do not
// deprovision". A deployment that wants dormancy to outlive session expiry
// should wire a persistent recorder (memory.ActivityTracker) instead, which
// keeps the last-active instant independent of session lifetime.
type SessionLastActive struct {
	Sessions core.SessionManager
}

// LastActive returns the newest session CreatedAt for userID, or the zero time
// when the user has no live sessions (or no session manager is wired).
func (s SessionLastActive) LastActive(ctx context.Context, userID string) (time.Time, error) {
	if s.Sessions == nil {
		return time.Time{}, nil
	}
	sessions, err := s.Sessions.ListByUser(ctx, userID)
	if err != nil {
		return time.Time{}, err
	}
	var newest time.Time
	for _, sess := range sessions {
		if sess != nil && sess.CreatedAt.After(newest) {
			newest = sess.CreatedAt
		}
	}
	return newest, nil
}
