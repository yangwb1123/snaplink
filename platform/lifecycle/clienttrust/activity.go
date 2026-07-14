// Package clienttrust implements RULE-BASED (no ML) trust scoring for
// registered OAuth clients (core.Client) — a distinct feature from
// shared/trust, which scores the END USER / session at login time.
// clienttrust instead flags a registered CLIENT APPLICATION whose recent
// activity looks anomalous: a spike in auth failures, unusually frequent
// secret-rotation attempts, or sudden scope-request changes. It is
// OBSERVABILITY / SCORING ONLY:
//
//   - Score is never consulted by any authorization decision — no client is
//     ever blocked, rate-limited, or step-up-challenged based on this score
//     in this package. Wiring a score into a live enforcement decision is a
//     separate, materially riskier policy-enforcement feature this package
//     deliberately does not attempt (mirrors shared/trust's own scope cut:
//     "an advisory signal, never an allow/deny decision").
//   - The persisted score (core.Client.ClientTrustScore /
//     ClientTrustSetAt) is additive metadata on the existing ClientStore —
//     see updater.go's doc comment for why this package does NOT invent a
//     separate "ClientTrustStore".
//
// # Design: rule-based counters, not ML
//
// Per the source audit's own guidance ("建议从规则计数器起步而非ML评分" —
// start from rule-based counters, not ML scoring), ClientTrustScorer
// (scorer.go) computes a penalty from simple threshold rules over a
// [ClientActivityStore] window (failure-rate, rotation-frequency, scope-
// anomaly counts) and reuses shared/trust's EXISTING exponential decay
// primitive ([trust.DecayValue]) so an old penalty recovers toward neutral
// over time instead of haunting a client forever.
//
// # Cold start
//
// A client with NO recorded activity at all gets the neutral default
// [ColdStartScore] (0.5) — never 0.0, which would read as "actively
// distrusted" for a client that is simply new.
//
// # Alerting
//
// updater.go's UpdateAndAlert persists a freshly computed score and, on an
// edge-triggered threshold cross, records an [EventClientTrustThresholdCrossed]
// audit event. This package builds NO new alerting mechanism: any
// platform/lifecycle/webhook subscription (or any other audit.Sink) already
// tapping the audit pipeline receives it exactly like every other event type.
package clienttrust

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ClientActivityKind enumerates the discrete, oracle-safe activity signals
// this store records. Deliberately narrow and counters-only — never raw
// request bodies, tokens, or credential material — mirroring platform/audit's
// own Event discipline (Type + Outcome + Timestamp + ClientID + Metadata)
// without importing platform/audit's Event type directly: an activity record
// is a narrower, purpose-built shape than the generic audit vocabulary.
type ClientActivityKind string

const (
	// ClientActivityAuthSuccess records a successful client authentication
	// (e.g. a /token call with valid client credentials).
	ClientActivityAuthSuccess ClientActivityKind = "auth_success"
	// ClientActivityAuthFailure records a failed client authentication
	// (invalid secret, private_key_jwt failure, ...).
	ClientActivityAuthFailure ClientActivityKind = "auth_failure"
	// ClientActivitySecretRotation records one secret-rotation attempt
	// (admin-triggered or scheduled), regardless of outcome.
	ClientActivitySecretRotation ClientActivityKind = "secret_rotation"
	// ClientActivityScopeAnomaly records a sudden/unexpected scope-request
	// change (e.g. a token request for scopes far outside the client's
	// historical pattern). Callers own the anomaly judgment; this store
	// only records that one was flagged.
	ClientActivityScopeAnomaly ClientActivityKind = "scope_anomaly"
)

// ClientActivityEvent is one discrete, timestamped activity observation for
// a client. Reason is a short, audit-safe code (never free-text or PII) —
// same discipline as trust.TrustScore.Reasons.
type ClientActivityEvent struct {
	ClientID  string
	Kind      ClientActivityKind
	Timestamp time.Time
	Reason    string
}

// ErrClientIDRequired is returned by Record when ev.ClientID is empty.
var ErrClientIDRequired = errors.New("clienttrust: client id required")

// ClientActivitySummary is the aggregate a [ClientTrustScorer] rule set
// consults: counts over the scorer's lookback window plus whether ANY
// activity has ever been recorded for the client (cold-start detection is
// deliberately NOT window-scoped — a client with only very old activity is
// still "known", not cold-start).
type ClientActivitySummary struct {
	AuthSuccess     int
	AuthFailure     int
	SecretRotations int
	ScopeAnomalies  int

	// LastNegativeAt is the most recent timestamp, within the window, of any
	// AuthFailure / SecretRotation / ScopeAnomaly event — the decay
	// anchor: the raw rule penalty decays from THIS instant, so a client
	// whose last strike was long ago recovers even if its historical count
	// (outside the window) was high. Zero when no negative event fell in
	// the window.
	LastNegativeAt time.Time

	// HasHistory is true iff at least one activity event has EVER been
	// recorded for this client (regardless of the window) — the cold-start
	// signal. False means the scorer has literally nothing to go on.
	HasHistory bool
}

// ClientActivityStore records and summarizes per-client activity events.
// Implementations MUST be safe for concurrent use. Unlike shared/trust's
// narrow read-only Lookup interfaces (IPFailureLookup, LoginHistoryLookup),
// this store is also the WRITE path (Record) — there is no separate
// "recorder" abstraction, mirroring the existing SPI + memory-impl pattern
// (AGENTS.md "Wire Contracts").
type ClientActivityStore interface {
	// Record appends ev. Returns ErrClientIDRequired when ev.ClientID is
	// empty. A zero ev.Timestamp is stamped to time.Now() by the
	// implementation.
	Record(ctx context.Context, ev ClientActivityEvent) error

	// Summarize aggregates clientID's events at or after since into a
	// ClientActivitySummary. Never returns an error for an unknown/never-
	// seen clientID — it returns a zero-value summary (HasHistory false),
	// the cold-start case; only a genuine backend failure is an error.
	Summarize(ctx context.Context, clientID string, since time.Time) (ClientActivitySummary, error)
}

// MemoryClientActivityStore is an in-memory ClientActivityStore for tests
// and single-replica dev setups. Safe for concurrent use.
type MemoryClientActivityStore struct {
	mu     sync.Mutex
	events map[string][]ClientActivityEvent // clientID -> events, append order
}

// NewMemoryClientActivityStore builds an empty MemoryClientActivityStore.
func NewMemoryClientActivityStore() *MemoryClientActivityStore {
	return &MemoryClientActivityStore{events: make(map[string][]ClientActivityEvent)}
}

// Record implements ClientActivityStore.
func (m *MemoryClientActivityStore) Record(_ context.Context, ev ClientActivityEvent) error {
	if ev.ClientID == "" {
		return ErrClientIDRequired
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events[ev.ClientID] = append(m.events[ev.ClientID], ev)
	return nil
}

// Summarize implements ClientActivityStore.
func (m *MemoryClientActivityStore) Summarize(_ context.Context, clientID string, since time.Time) (ClientActivitySummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	all, ok := m.events[clientID]
	sum := ClientActivitySummary{HasHistory: ok && len(all) > 0}
	for _, ev := range all {
		if ev.Timestamp.Before(since) {
			continue
		}
		sum.tally(ev)
	}
	return sum, nil
}

// tally folds one in-window event into the running summary — split out of
// Summarize to keep both under the complexity/length budget.
func (s *ClientActivitySummary) tally(ev ClientActivityEvent) {
	switch ev.Kind {
	case ClientActivityAuthSuccess:
		s.AuthSuccess++
	case ClientActivityAuthFailure:
		s.AuthFailure++
		s.noteNegative(ev.Timestamp)
	case ClientActivitySecretRotation:
		s.SecretRotations++
		s.noteNegative(ev.Timestamp)
	case ClientActivityScopeAnomaly:
		s.ScopeAnomalies++
		s.noteNegative(ev.Timestamp)
	}
}

// noteNegative advances LastNegativeAt to the latest negative-signal
// timestamp seen so far.
func (s *ClientActivitySummary) noteNegative(at time.Time) {
	if at.After(s.LastNegativeAt) {
		s.LastNegativeAt = at
	}
}

var _ ClientActivityStore = (*MemoryClientActivityStore)(nil)
