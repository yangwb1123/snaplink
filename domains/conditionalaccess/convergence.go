package conditionalaccess

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	DefaultSessionSweepInterval  = 5 * time.Minute
	DefaultSessionSweepBatchSize = 500
)

// ConvergenceSummary is the bounded result returned to operators and logs.
type ConvergenceSummary struct {
	Scanned          int `json:"scanned"`
	Revoked          int `json:"revoked"`
	StepUpMarked     int `json:"step_up_marked"`
	ScopesRestricted int `json:"scopes_restricted"`
	Failed           int `json:"failed"`
}

// SessionContextBuilder enriches persisted session data with current groups,
// device and geo signals. concurrent is exact for the subject/client pair.
type SessionContextBuilder func(context.Context, *core.Session, int) AccessContext

type convergenceState struct {
	mu     sync.Mutex
	cursor int
}

// ConvergeSessions re-evaluates a bounded slice of active sessions against one
// policy snapshot. Store failure is fail-open and causes no session mutation.
func (e *Engine) ConvergeSessions(ctx context.Context, sessions core.SessionManager, build SessionContextBuilder) (ConvergenceSummary, error) {
	var summary ConvergenceSummary
	if e == nil || sessions == nil || build == nil || !e.cfg.Enforce {
		return summary, nil
	}
	policies, err := e.store.List(ctx)
	if err != nil {
		return summary, err
	}
	all, err := sessions.ListAll(ctx)
	if err != nil {
		return summary, err
	}
	e.convergence.mu.Lock()
	defer e.convergence.mu.Unlock()
	active := activeSessions(all)
	counts := concurrentSessionCounts(active)
	for _, session := range e.convergenceBatch(active) {
		key := sessionConcurrencyKey(session)
		decision := Decide(e.cfg, policies, build(ctx, session, counts[key]))
		summary.Scanned++
		if convergeSession(ctx, sessions, session, decision, &summary) {
			counts[key]--
		}
	}
	return summary, nil
}

// StartSessionConvergence runs an immediate pass and then periodic passes until
// ctx is cancelled. Per-pass errors are fail-open; the next tick retries.
func (e *Engine) StartSessionConvergence(ctx context.Context, sessions core.SessionManager, build SessionContextBuilder) <-chan struct{} {
	done := make(chan struct{})
	if e == nil || sessions == nil || build == nil || !e.cfg.Enforce {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		interval := e.cfg.SessionSweepInterval
		if interval <= 0 {
			interval = DefaultSessionSweepInterval
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			_, _ = e.ConvergeSessions(ctx, sessions, build)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return done
}

func activeSessions(all []*core.Session) []*core.Session {
	now := time.Now()
	active := make([]*core.Session, 0, len(all))
	for _, session := range all {
		if session != nil && !session.Revoked && session.ExpiresAt.After(now) {
			active = append(active, session)
		}
	}
	sort.Slice(active, func(i, j int) bool {
		if active[i].CreatedAt.Equal(active[j].CreatedAt) {
			return active[i].ID > active[j].ID
		}
		return active[i].CreatedAt.After(active[j].CreatedAt)
	})
	return active
}

func concurrentSessionCounts(sessions []*core.Session) map[string]int {
	counts := make(map[string]int)
	for _, session := range sessions {
		counts[sessionConcurrencyKey(session)]++
	}
	return counts
}

func sessionConcurrencyKey(session *core.Session) string {
	return session.UserID + "\x00" + session.ClientID
}

func (e *Engine) convergenceBatch(active []*core.Session) []*core.Session {
	if len(active) == 0 {
		e.convergence.cursor = 0
		return nil
	}
	limit := e.cfg.SessionSweepBatchSize
	if limit <= 0 {
		limit = DefaultSessionSweepBatchSize
	}
	if limit >= len(active) {
		e.convergence.cursor = 0
		return active
	}
	start := e.convergence.cursor % len(active)
	out := make([]*core.Session, 0, limit)
	for i := 0; i < limit; i++ {
		out = append(out, active[(start+i)%len(active)])
	}
	e.convergence.cursor = (start + limit) % len(active)
	return out
}

func convergeSession(ctx context.Context, sessions core.SessionManager, session *core.Session, decision Decision, summary *ConvergenceSummary) bool {
	if decision.Verdict == VerdictDeny {
		return revokeConvergedSession(ctx, sessions, session.ID, summary)
	}
	if len(decision.RestrictScopes) > 0 && !convergeScopes(ctx, sessions, session, decision.RestrictScopes, summary) {
		return revokeConvergedSession(ctx, sessions, session.ID, summary)
	}
	if decision.Verdict != VerdictRequireStepUp {
		return false
	}
	marker, ok := sessions.(core.SessionTrustManager)
	if !ok {
		return revokeConvergedSession(ctx, sessions, session.ID, summary)
	}
	if err := marker.MarkStepUp(ctx, session.ID); err != nil {
		summary.Failed++
		return false
	}
	summary.StepUpMarked++
	return false
}

func convergeScopes(ctx context.Context, sessions core.SessionManager, session *core.Session, allowed []string, summary *ConvergenceSummary) bool {
	if len(session.AuthorizedScopes) == 0 {
		return false
	}
	restricted := intersectScopes(session.AuthorizedScopes, allowed)
	if len(restricted) == 0 {
		return false
	}
	if sameScopes(session.AuthorizedScopes, restricted) {
		return true
	}
	updater, ok := sessions.(core.SessionAuthorizationManager)
	if !ok || updater.SetAuthorizedScopes(ctx, session.ID, restricted) != nil {
		return false
	}
	summary.ScopesRestricted++
	return true
}

func revokeConvergedSession(ctx context.Context, sessions core.SessionManager, id string, summary *ConvergenceSummary) bool {
	if err := sessions.Destroy(ctx, id); err != nil {
		summary.Failed++
		return false
	}
	summary.Revoked++
	return true
}

func intersectScopes(current, allowed []string) []string {
	set := make(map[string]struct{}, len(allowed))
	for _, scope := range allowed {
		set[scope] = struct{}{}
	}
	out := make([]string, 0, len(current))
	for _, scope := range current {
		if _, ok := set[scope]; ok {
			out = append(out, scope)
		}
	}
	return out
}

func sameScopes(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
