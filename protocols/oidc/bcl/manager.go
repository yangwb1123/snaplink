package bcl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/spi"
)

type DeliveredFunc func(context.Context, Failure) error

type ManagerOption func(*Manager)

func WithRetryInterval(d time.Duration) ManagerOption { return func(m *Manager) { m.interval = d } }
func WithBatchSize(n int) ManagerOption               { return func(m *Manager) { m.batchSize = n } }
func WithLeaseDuration(d time.Duration) ManagerOption { return func(m *Manager) { m.lease = d } }
func WithLogger(logger spi.Logger) ManagerOption      { return func(m *Manager) { m.logger = logger } }
func WithAuditor(rec *audit.Recorder) ManagerOption   { return func(m *Manager) { m.auditor = rec } }
func WithDelivered(fn DeliveredFunc) ManagerOption    { return func(m *Manager) { m.delivered = fn } }

type Manager struct {
	issuer    Issuer
	notifier  Notifier
	store     Store
	logger    spi.Logger
	auditor   *audit.Recorder
	delivered DeliveredFunc
	interval  time.Duration
	batchSize int
	lease     time.Duration
	mu        sync.Mutex
	cancel    context.CancelFunc
	done      chan struct{}
	closed    bool
}

func NewManager(issuer Issuer, notifier Notifier, store Store, opts ...ManagerOption) *Manager {
	m := &Manager{issuer: issuer, notifier: notifier, store: store, logger: spi.NopLogger{},
		interval: DefaultRetryInterval, batchSize: DefaultBatchSize, lease: DefaultLeaseDuration}
	for _, opt := range opts {
		opt(m)
	}
	if m.interval <= 0 {
		m.interval = DefaultRetryInterval
	}
	if m.batchSize <= 0 {
		m.batchSize = DefaultBatchSize
	}
	m.lease = normalizedLease(m.lease)
	return m
}

func (m *Manager) Notify(ctx context.Context, uri, token string) error {
	return m.notifier.Notify(ctx, uri, token)
}

func (m *Manager) RecordFailure(ctx context.Context, f Failure) error {
	now := time.Now().UTC()
	if f.ID == "" {
		f.ID = failureID(f)
	}
	if f.Attempts <= 0 {
		f.Attempts = DefaultMaxAttempts
	}
	f.FirstFailedAt, f.LastFailedAt = now, now
	f.NextAttemptAt = now.Add(m.interval)
	stored, err := m.store.Enqueue(ctx, f)
	if err != nil {
		return err
	}
	m.logger.Error("backchannel logout queued for replay", "failure_id", stored.ID, "client", stored.ClientID)
	m.startWorker()
	return nil
}

func failureID(f Failure) string {
	h := sha256.New()
	for _, part := range []string{f.TenantID, f.Subject, f.ClientID, f.SID, f.URI} {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

func (m *Manager) ListFailures(ctx context.Context, tenantID string, limit int) ([]Failure, error) {
	return m.store.List(ctx, Filter{TenantID: tenantID, Limit: normalizedLimit(limit)})
}

func (m *Manager) ReplayFailure(ctx context.Context, id, tenantID string) (Failure, error) {
	f, token, err := m.store.Claim(ctx, id, tenantID, m.lease)
	if err != nil {
		return f, err
	}
	deliveryCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	err = deliverWithRetry(deliveryCtx, m.issuer, m.notifier, f)
	cancel()
	if err != nil {
		return m.rescheduleFailure(ctx, f, token, err)
	}
	f.DeliveredAt = time.Now().UTC()
	m.recordReplay(f, nil)
	if err = m.store.Ack(ctx, f, token); err != nil {
		return f, errors.Join(ErrReplayCleanup, err)
	}
	if m.delivered != nil {
		if callbackErr := m.delivered(ctx, f); callbackErr != nil {
			m.logger.Error("backchannel logout replay cleanup callback failed", "error", callbackErr, "failure_id", f.ID)
		}
	}
	return f, nil
}

func (m *Manager) rescheduleFailure(ctx context.Context, f Failure, token string, deliveryErr error) (Failure, error) {
	f.Attempts += DefaultMaxAttempts
	f.LastError = deliveryErr.Error()
	f.LastFailedAt = time.Now().UTC()
	f.NextAttemptAt = f.LastFailedAt.Add(replayBackoff(m.interval, f.Attempts))
	if err := m.store.Reschedule(ctx, f, token); err != nil {
		return f, errors.Join(deliveryErr, err)
	}
	m.recordReplay(f, deliveryErr)
	return f, deliveryErr
}

func replayBackoff(base time.Duration, attempts int) time.Duration {
	rounds := attempts / DefaultMaxAttempts
	if rounds < 1 {
		rounds = 1
	}
	if rounds > 7 {
		rounds = 7
	}
	delay := base * time.Duration(1<<(rounds-1))
	if delay > time.Hour {
		return time.Hour
	}
	return delay
}

func deliverWithRetry(ctx context.Context, issuer Issuer, notifier Notifier, f Failure) error {
	request := &Request{Subject: f.TokenSubject, Audience: f.ClientID, SID: f.SID}
	var lastErr error
	for attempt := 1; attempt <= DefaultMaxAttempts; attempt++ {
		token, err := issuer.IssueLogoutToken(ctx, request)
		if err != nil {
			return err
		}
		lastErr = notifier.Notify(ctx, f.URI, token)
		if lastErr == nil || !retryable(lastErr) || attempt == DefaultMaxAttempts {
			return lastErr
		}
		if err := waitRetry(ctx, attempt); err != nil {
			return err
		}
	}
	return lastErr
}

func retryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var classified interface{ Retryable() bool }
	if errors.As(err, &classified) {
		return classified.Retryable()
	}
	return true
}

func waitRetry(ctx context.Context, attempt int) error {
	base := DefaultRetryBase << (attempt - 1)
	delay := time.Duration(float64(base) * (0.75 + rand.Float64()*0.5))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (m *Manager) ReplayDue(ctx context.Context, tenantID string, limit int) (ReplaySummary, error) {
	entries, err := m.store.List(ctx, Filter{TenantID: tenantID, Limit: normalizedLimit(limit), DueBefore: time.Now().UTC()})
	if err != nil {
		return ReplaySummary{}, err
	}
	summary := ReplaySummary{}
	for _, entry := range entries {
		summary.Attempted++
		_, replayErr := m.ReplayFailure(ctx, entry.ID, tenantID)
		switch {
		case replayErr == nil:
			summary.Delivered++
		case errors.Is(replayErr, ErrLeaseUnavailable):
			summary.Busy++
		default:
			summary.Failed++
		}
	}
	return summary, nil
}

func (m *Manager) startWorker() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel, m.done = cancel, make(chan struct{})
	go m.run(ctx, m.done)
}

func (m *Manager) run(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := m.ReplayDue(ctx, "", m.batchSize); err != nil && ctx.Err() == nil {
				m.logger.Error("backchannel logout replay sweep failed", "error", err)
			}
		}
	}
}

func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	cancel, done := m.cancel, m.done
	m.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) recordReplay(f Failure, replayErr error) {
	if m.auditor == nil {
		return
	}
	e := &audit.Event{Type: audit.EventLogoutNotified, Outcome: audit.OutcomeSuccess,
		Timestamp: time.Now().UTC(), ActorID: f.Subject, ClientID: f.ClientID, TenantID: f.TenantID}
	audit.SetMeta(e, "delivery_source", "bcl_failure_replay")
	audit.SetMeta(e, "failure_id", f.ID)
	if replayErr != nil {
		e.Outcome, e.Reason = audit.OutcomeFailure, replayErr.Error()
	}
	m.auditor.Record(context.Background(), e)
}

var _ Notifier = (*Manager)(nil)
var _ AdminManager = (*Manager)(nil)
