package auditgovernance

import (
	"context"
	"errors"
	"hash/fnv"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

const (
	reasonInvalidEvent   = "governance event validation failed"
	reasonInvalidReceipt = "governance receipt validation failed"
	reasonProtocol       = "governance protocol conflict"
	reasonConflict       = "governance idempotency conflict"
	reasonRejected       = "governance rejected event"
	reasonAuthorization  = "governance authorization rejected"
	reasonRateLimited    = "governance rate limited"
	reasonUnavailable    = "governance service unavailable"
	reasonTransport      = "governance transport unavailable"
)

// RelayConfig controls ownership, batch claiming, and bounded retries.
type RelayConfig struct {
	Owner          string
	Lease          time.Duration
	BatchSize      int
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	PollInterval   time.Duration
}

// Relay drains a commerce outbox using at-least-once delivery.
type Relay struct {
	store  commerce.OutboxStore
	client Client
	config RelayConfig
	now    func() time.Time
}

// RelayOption customizes process-local relay behavior.
type RelayOption func(*Relay)

// WithRelayClock injects a clock for deterministic scheduling tests.
func WithRelayClock(now func() time.Time) RelayOption {
	return func(relay *Relay) {
		if now != nil {
			relay.now = now
		}
	}
}

// NewRelay builds a worker for one durable commerce outbox.
func NewRelay(
	store commerce.OutboxStore, client Client, config RelayConfig, options ...RelayOption,
) (*Relay, error) {
	config = defaultRelayConfig(config)
	if store == nil || client == nil || !validRelayConfig(config) {
		return nil, ErrInvalidConfig
	}
	relay := &Relay{store: store, client: client, config: config, now: func() time.Time {
		return time.Now().UTC()
	}}
	for _, option := range options {
		option(relay)
	}
	return relay, nil
}

func defaultRelayConfig(config RelayConfig) RelayConfig {
	if config.Lease <= 0 {
		config.Lease = 30 * time.Second
	}
	if config.BatchSize <= 0 {
		config.BatchSize = 100
	}
	if config.MaxAttempts <= 0 {
		config.MaxAttempts = 10
	}
	if config.InitialBackoff <= 0 {
		config.InitialBackoff = time.Second
	}
	if config.MaxBackoff <= 0 {
		config.MaxBackoff = time.Minute
	}
	if config.PollInterval <= 0 {
		config.PollInterval = 500 * time.Millisecond
	}
	return config
}

func validRelayConfig(config RelayConfig) bool {
	return config.Owner != "" && config.Lease > 0 && config.BatchSize > 0 &&
		config.MaxAttempts > 0 && config.InitialBackoff > 0 &&
		config.MaxBackoff >= config.InitialBackoff && config.PollInterval > 0
}

// RunResult reports persisted transitions from one claimed batch.
type RunResult struct {
	Claimed     int
	Delivered   int
	Retried     int
	Dead        int
	Quarantined int
}

// Run polls until the context ends or an operational error requires the
// supervisor to pause the worker.
func (r *Relay) Run(ctx context.Context) error {
	for {
		result, err := r.RunOnce(ctx)
		if err != nil {
			return err
		}
		if result.Claimed > 0 {
			continue
		}
		if !waitForPoll(ctx, r.config.PollInterval) {
			return ctx.Err()
		}
	}
}

func waitForPoll(ctx context.Context, interval time.Duration) bool {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (r *Relay) RunOnce(ctx context.Context) (RunResult, error) {
	now := r.now()
	events, err := r.store.ClaimOutbox(
		ctx, r.config.Owner, now, r.config.Lease, r.config.BatchSize,
	)
	result := RunResult{Claimed: len(events)}
	if err != nil {
		return result, err
	}
	for _, event := range events {
		outcome, deliverErr := r.deliver(ctx, event, r.now())
		result.add(outcome)
		if deliverErr != nil {
			return result, deliverErr
		}
	}
	return result, nil
}

type deliveryOutcome uint8

const (
	deliveryNone deliveryOutcome = iota
	deliveryDelivered
	deliveryRetried
	deliveryDead
	deliveryQuarantined
)

func (r *Relay) deliver(
	ctx context.Context, event *commerce.OutboxEvent, now time.Time,
) (deliveryOutcome, error) {
	_, err := r.client.Publish(ctx, event)
	if err == nil {
		transitionErr := r.store.CompleteOutbox(ctx, event.ID, r.config.Owner, now)
		return persistedOutcome(deliveryDelivered, transitionErr)
	}
	if ctx.Err() != nil {
		return deliveryNone, ctx.Err()
	}
	action, reason := classifyDeliveryError(err)
	switch action {
	case deliveryQuarantined:
		transitionErr := r.store.QuarantineOutbox(ctx, event.ID, r.config.Owner, reason, now)
		return persistedOutcome(action, transitionErr)
	case deliveryDead:
		return persistedOutcome(action, r.deadLetter(ctx, event, reason, now))
	case deliveryRetried:
		if reason == reasonAuthorization {
			return persistedOutcome(action, r.pauseSource(ctx, event, now))
		}
		return persistedOutcome(action, r.retry(ctx, event, reason, now))
	default:
		return deliveryNone, err
	}
}

func persistedOutcome(outcome deliveryOutcome, err error) (deliveryOutcome, error) {
	if err == nil || errors.Is(err, ErrAuthorizationRejected) {
		return outcome, err
	}
	return deliveryNone, err
}

func (r *Relay) deadLetter(
	ctx context.Context, event *commerce.OutboxEvent, reason string, now time.Time,
) error {
	err := r.store.FailOutbox(ctx, event.ID, r.config.Owner, reason, now, now, 1)
	if err != nil {
		return err
	}
	return nil
}

func (r *Relay) pauseSource(
	ctx context.Context, event *commerce.OutboxEvent, now time.Time,
) error {
	nextAttempt := now.Add(r.backoff(event))
	err := r.store.FailOutbox(
		ctx, event.ID, r.config.Owner, reasonAuthorization, now, nextAttempt, 0,
	)
	if err != nil {
		return err
	}
	// Stop before another claim is affected by the same bad credential.
	// Unprocessed claims become eligible after their lease expires.
	return ErrAuthorizationRejected
}

func (r *Relay) retry(
	ctx context.Context, event *commerce.OutboxEvent, reason string, now time.Time,
) error {
	nextAttempt := now.Add(r.backoff(event))
	return r.store.FailOutbox(
		ctx, event.ID, r.config.Owner, reason, now, nextAttempt, r.config.MaxAttempts,
	)
}

func classifyDeliveryError(err error) (deliveryOutcome, string) {
	switch {
	case errors.Is(err, ErrProtocolConflict):
		return deliveryQuarantined, reasonProtocol
	case errors.Is(err, ErrInvalidReceipt):
		return deliveryQuarantined, reasonInvalidReceipt
	case errors.Is(err, ErrInvalidEvent):
		return deliveryDead, reasonInvalidEvent
	}
	status, ok := responseStatus(err)
	if !ok {
		return deliveryRetried, reasonTransport
	}
	switch {
	case status == 401 || status == 403:
		return deliveryRetried, reasonAuthorization
	case status == 409:
		return deliveryQuarantined, reasonConflict
	case status >= 300 && status < 400:
		return deliveryQuarantined, reasonProtocol
	case status == 400 || status == 422:
		return deliveryDead, reasonRejected
	case status == 429:
		return deliveryRetried, reasonRateLimited
	case status >= 500:
		return deliveryRetried, reasonUnavailable
	default:
		return deliveryDead, reasonRejected
	}
}

func (r *Relay) backoff(event *commerce.OutboxEvent) time.Duration {
	delay := r.config.InitialBackoff
	for attempt := 1; attempt < event.Attempts && delay < r.config.MaxBackoff; attempt++ {
		if delay > r.config.MaxBackoff/2 {
			delay = r.config.MaxBackoff
			break
		}
		delay *= 2
	}
	if delay > r.config.MaxBackoff {
		delay = r.config.MaxBackoff
	}
	return jitterBelow(delay, event.ID, event.Attempts)
}

func jitterBelow(delay time.Duration, eventID string, attempts int) time.Duration {
	base := delay - delay/4
	window := delay - base
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(eventID))
	var attemptBytes [8]byte
	for index := range attemptBytes {
		attemptBytes[index] = byte(uint64(attempts) >> (index * 8))
	}
	_, _ = hash.Write(attemptBytes[:])
	return base + time.Duration(hash.Sum64()%uint64(window+1))
}

func (r *RunResult) add(outcome deliveryOutcome) {
	switch outcome {
	case deliveryDelivered:
		r.Delivered++
	case deliveryRetried:
		r.Retried++
	case deliveryDead:
		r.Dead++
	case deliveryQuarantined:
		r.Quarantined++
	}
}
