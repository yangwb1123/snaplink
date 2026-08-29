// Client-secret expiry warning scan. Client secrets are ENFORCED at /token
// (expired => invalid_client), but expiry is a sudden death for machine
// identities: a forgotten secret_expires_at on one of hundreds of
// DCR-registered clients is a production outage with no warning. This
// background loop scans the client store on an interval and emits one
// bounded audit event + metric per client per warning window (30/14/7 days),
// so the ops team sees the cliff before the fall. It sits beside the
// credential rotation scheduler because it is the same operator surface
// (credential lifecycle) — read-only, unlike the scheduler.
//
// Design constraints:
//   - Public clients (token_endpoint_auth_method=none) carry no secret and
//     are exempt — no noise.
//   - One event per (client, window, expiry generation) per UTC day: local
//     state preserves the fallback behavior and an optional claim store shares
//     the decision across scanner restarts and replicas.
//   - The scanner is read-only: rotation stays a human/admin decision
//     (RotateSecret already supports the SecretOverlapUntil grace period).
package rotation

import (
	"context"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// ClientSecretWarningWindows are the days-before-expiry alert cadences, in
// descending order; each client emits at most one event per window.
var ClientSecretWarningWindows = []time.Duration{
	30 * 24 * time.Hour,
	14 * 24 * time.Hour,
	7 * 24 * time.Hour,
}

// ClientSecretScanInterval bounds the sweep cadence; local claim state is
// pruned when the scanner advances to a later UTC day.
const ClientSecretScanInterval = 6 * time.Hour

// ClientSecretExpiryScanner is the background expiry-warning loop.
type ClientSecretExpiryScanner struct {
	store            core.ClientStore
	auditor          *audit.Recorder
	metrics          *metrics.Metrics
	logger           spi.Logger
	claimStore       ClientSecretWarningClaimStore
	interval         time.Duration
	emittedMu        sync.Mutex
	emitted          map[string]time.Time // claim fingerprint -> UTC day
	emittedDay       time.Time            // last day retained in emitted
	publicAuthMethod map[string]bool
}

// NewClientSecretExpiryScanner builds the scanner over the wired client
// store + recorder. store is required; nil auditor/metrics degrade to
// log-only (the scan still runs — silence is the failure mode we prevent).
// Optional claim-store wiring is additive so existing embedders retain the
// local-only behavior.
func NewClientSecretExpiryScanner(store core.ClientStore, auditor *audit.Recorder, m *metrics.Metrics, logger spi.Logger, opts ...ClientSecretExpiryScannerOption) *ClientSecretExpiryScanner {
	s := &ClientSecretExpiryScanner{
		store:            store,
		auditor:          auditor,
		metrics:          m,
		logger:           logger,
		interval:         ClientSecretScanInterval,
		emitted:          make(map[string]time.Time),
		publicAuthMethod: map[string]bool{"none": true},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// Run executes the loop until ctx is cancelled, returning when the ctx
// completes (the done channel StartClientSecretScan closes). The first sweep
// runs immediately so a restart surfaces expiries without waiting an interval.
func (s *ClientSecretExpiryScanner) Run(ctx context.Context) {
	s.sweep(ctx)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweep(ctx)
		}
	}
}

// StartClientSecretScan launches the scanner on ctx and returns a done
// channel that closes when the loop exits (cancel ctx to stop). The
// composition root wires this beside the rotation scheduler and joins the
// done channel into its shutdown set.
func StartClientSecretScan(ctx context.Context, store core.ClientStore, auditor *audit.Recorder, m *metrics.Metrics, logger spi.Logger, opts ...ClientSecretExpiryScannerOption) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		NewClientSecretExpiryScanner(store, auditor, m, logger, opts...).Run(ctx)
	}()
	return done
}

// sweep lists the client store and emits a warning per client whose secret
// expires inside a warning window. Fail-open: a store outage logs and aborts
// the sweep, while a claim-store outage falls back to local deduplication.
func (s *ClientSecretExpiryScanner) sweep(ctx context.Context) {
	clients, err := s.store.List(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("client secret expiry scan failed", "error", err)
		}
		return
	}
	now := time.Now().UTC()
	today := clientSecretWarningDay(now)
	for _, c := range clients {
		if c == nil || s.publicAuthMethod[c.TokenEndpointAuthMethod] {
			continue
		}
		if c.SecretExpiresAt.IsZero() {
			continue // no expiry pinned: nothing to warn about
		}
		remaining := c.SecretExpiresAt.Sub(now)
		if remaining <= 0 {
			continue // already expired: /token enforcement owns the failure signal
		}
		for _, window := range ClientSecretWarningWindows {
			if remaining > window {
				continue
			}
			claim := ClientSecretWarningClaim{
				ClientID: c.ID, Window: window, Day: today, SecretExpiresAt: c.SecretExpiresAt,
			}
			if !s.claimWarning(ctx, claim) {
				continue
			}
			s.emit(ctx, c.ID, window, remaining)
		}
	}
}

// claimWarning records local state before consulting the optional shared store.
// This makes a store outage fail open without allowing repeated local emits.
func (s *ClientSecretExpiryScanner) claimWarning(ctx context.Context, claim ClientSecretWarningClaim) bool {
	if !s.claimLocally(claim) {
		return false
	}
	if s.claimStore == nil {
		return true
	}
	won, err := s.claimStore.Claim(ctx, claim)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("client secret expiry warning claim failed",
				"client_id", claim.ClientID, "window", claim.Window.String(), "error", err)
		}
		return true
	}
	return won
}

func (s *ClientSecretExpiryScanner) claimLocally(claim ClientSecretWarningClaim) bool {
	day := clientSecretWarningDay(claim.Day)
	key := claim.Fingerprint()
	s.emittedMu.Lock()
	defer s.emittedMu.Unlock()
	if s.emitted == nil {
		s.emitted = make(map[string]time.Time)
	}
	if s.emittedDay.IsZero() || day.After(s.emittedDay) {
		for fingerprint, emittedDay := range s.emitted {
			if emittedDay.Before(day) {
				delete(s.emitted, fingerprint)
			}
		}
		s.emittedDay = day
	}
	if _, exists := s.emitted[key]; exists {
		return false
	}
	s.emitted[key] = day
	return true
}

// emit records one bounded audit event + metric for a client entering a
// warning window. The event's consumer is the ops team: ClientID names the
// machine identity and Reason names the window.
func (s *ClientSecretExpiryScanner) emit(ctx context.Context, clientID string, window time.Duration, remaining time.Duration) {
	if s.auditor != nil {
		s.auditor.Record(ctx, &audit.Event{
			Type:     audit.EventClientSecretExpiring,
			Outcome:  audit.OutcomeFailure, // an at-risk credential is a something-to-look-at event
			ClientID: clientID,
			Reason:   window.String(),
		})
	}
	if s.metrics != nil {
		s.metrics.ObserveClientSecretExpiring(window.String())
	}
	if s.logger != nil {
		s.logger.Error("client secret expiring",
			"client_id", clientID,
			"window", window.String(),
			"days_remaining", int(remaining.Hours()/24))
	}
}
