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
//   - One event per (client, window) per day: a dedup map bounds audit
//     volume while keeping the daily cadence for the 30d and 14d windows.
//   - The scanner is read-only: rotation stays a human/admin decision
//     (RotateSecret already supports the SecretOverlapUntil grace period).
package rotation

import (
	"context"
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

// ClientSecretScanInterval bounds the sweep cadence (and the dedup map's
// growth): at most len(windows) entries per client per day.
const ClientSecretScanInterval = 6 * time.Hour

// ClientSecretExpiryScanner is the background expiry-warning loop.
type ClientSecretExpiryScanner struct {
	store            core.ClientStore
	auditor          *audit.Recorder
	metrics          *metrics.Metrics
	logger           spi.Logger
	interval         time.Duration
	emitted          map[string]time.Time // "clientID|window" -> date of last emission
	publicAuthMethod map[string]bool
}

// NewClientSecretExpiryScanner builds the scanner over the wired client
// store + recorder. store is required; nil auditor/metrics degrade to
// log-only (the scan still runs — silence is the failure mode we prevent).
func NewClientSecretExpiryScanner(store core.ClientStore, auditor *audit.Recorder, m *metrics.Metrics, logger spi.Logger) *ClientSecretExpiryScanner {
	return &ClientSecretExpiryScanner{
		store:            store,
		auditor:          auditor,
		metrics:          m,
		logger:           logger,
		interval:         ClientSecretScanInterval,
		emitted:          make(map[string]time.Time),
		publicAuthMethod: map[string]bool{"none": true},
	}
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
func StartClientSecretScan(ctx context.Context, store core.ClientStore, auditor *audit.Recorder, m *metrics.Metrics, logger spi.Logger) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		NewClientSecretExpiryScanner(store, auditor, m, logger).Run(ctx)
	}()
	return done
}

// sweep lists the client store and emits a warning per client whose secret
// expires inside a warning window. Fail-open: a store outage logs and aborts
// the sweep (never crashes, never blocks the server).
func (s *ClientSecretExpiryScanner) sweep(ctx context.Context) {
	clients, err := s.store.List(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("client secret expiry scan failed", "error", err)
		}
		return
	}
	now := time.Now()
	today := now.Truncate(24 * time.Hour)
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
			key := c.ID + "|" + window.String()
			if last, ok := s.emitted[key]; ok && !last.Before(today) {
				continue // already emitted for this window today
			}
			s.emitted[key] = today
			s.emit(ctx, c.ID, window, remaining)
		}
	}
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
