package quotaprojection

import (
	"context"
	"errors"
	"hash/fnv"
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	reasonInvalidEvent       = "quota projection event invalid"
	reasonEntitlementMissing = "quota projection entitlement unavailable"
	reasonEntitlementDrift   = "quota projection entitlement revision mismatch"
	reasonProjectionInvalid  = "quota projection value invalid"
	reasonAuthorization      = "quota projection authorization rejected"
	reasonRejected           = "quota projection rejected"
	reasonRateLimited        = "quota projection rate limited"
	reasonUnavailable        = "quota projection service unavailable"
	reasonProtocol           = "quota projection protocol conflict"
	reasonTransport          = "quota projection transport unavailable"
)

type RelayConfig struct {
	Owner          string
	Lease          time.Duration
	BatchSize      int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	PollInterval   time.Duration
	MaxLag         time.Duration
}

type Relay struct {
	store  commerce.QuotaProjectionDeliveryStore
	reader commerce.EntitlementReader
	client Client
	config RelayConfig
	now    func() time.Time
}

type RelayOption func(*Relay)

func WithRelayClock(now func() time.Time) RelayOption {
	return func(relay *Relay) {
		if now != nil {
			relay.now = now
		}
	}
}

func NewRelay(
	store commerce.QuotaProjectionDeliveryStore, reader commerce.EntitlementReader,
	client Client, config RelayConfig, options ...RelayOption,
) (*Relay, error) {
	config = defaultRelayConfig(config)
	if store == nil || reader == nil || client == nil || !validRelayConfig(config) {
		return nil, ErrInvalidConfig
	}
	relay := &Relay{
		store: store, reader: reader, client: client, config: config,
		now: func() time.Time { return time.Now().UTC() },
	}
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
	if config.InitialBackoff <= 0 {
		config.InitialBackoff = time.Second
	}
	if config.MaxBackoff <= 0 {
		config.MaxBackoff = time.Minute
	}
	if config.PollInterval <= 0 {
		config.PollInterval = 500 * time.Millisecond
	}
	if config.MaxLag <= 0 {
		config.MaxLag = 5 * time.Minute
	}
	return config
}

func validRelayConfig(config RelayConfig) bool {
	return config.Owner != "" && config.Lease > 0 && config.BatchSize > 0 &&
		config.InitialBackoff > 0 && config.MaxBackoff >= config.InitialBackoff &&
		config.PollInterval > 0 && config.MaxLag > 0
}

type RunResult struct {
	Claimed   int
	Delivered int
	Retried   int
}

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
	result := RunResult{}
	for result.Claimed < r.config.BatchSize {
		event, err := r.claimNext(ctx, r.now())
		if err != nil {
			return result, err
		}
		if event == nil {
			return result, nil
		}
		result.Claimed++
		delivered, deliverErr := r.deliver(ctx, event, r.now())
		if delivered {
			result.Delivered++
		} else {
			result.Retried++
		}
		if deliverErr != nil {
			return result, deliverErr
		}
	}
	return result, nil
}

func (r *Relay) claimNext(ctx context.Context, now time.Time) (*commerce.OutboxEvent, error) {
	events, err := r.store.ClaimQuotaProjectionDeliveries(ctx, r.config.Owner, now, r.config.Lease, 1)
	if err != nil || len(events) == 0 {
		return nil, err
	}
	return events[0], nil
}

func (r *Relay) Ready(ctx context.Context) error {
	return r.store.QuotaProjectionDeliveryReady(ctx, r.now(), r.config.MaxLag)
}

func (r *Relay) deliver(ctx context.Context, event *commerce.OutboxEvent, now time.Time) (bool, error) {
	projection, err := r.currentProjection(ctx, event, now)
	if err != nil {
		return false, r.retry(ctx, event, classifyProjectionError(err), now)
	}
	_, err = r.client.Publish(ctx, event, projection)
	if err == nil {
		err = r.store.CompleteQuotaProjectionDelivery(
			ctx, event.ID, r.config.Owner, projection.Revision, now,
		)
		return err == nil, err
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	reason, pause := classifyPublishError(err)
	if retryErr := r.retry(ctx, event, reason, now); retryErr != nil {
		return false, retryErr
	}
	if pause {
		return false, ErrAuthorizationRejected
	}
	return false, nil
}

func (r *Relay) currentProjection(
	ctx context.Context, event *commerce.OutboxEvent, now time.Time,
) (core.TenantQuotaProjection, error) {
	if event == nil || event.ID == "" || event.Type != commerce.EventEntitlementPublished ||
		event.AggregateVersion == 0 || core.ValidateQuotaTenantID(event.TenantID) != nil {
		return core.TenantQuotaProjection{}, ErrInvalidEvent
	}
	snapshot, err := r.reader.CurrentEntitlement(ctx, event.TenantID)
	if err != nil || snapshot == nil {
		return core.TenantQuotaProjection{}, commerce.ErrEntitlementNotFound
	}
	if snapshot.TenantID != event.TenantID || snapshot.Revision < event.AggregateVersion {
		return core.TenantQuotaProjection{}, commerce.ErrRevisionConflict
	}
	projection := commerce.ProjectQuotaProjection(snapshot, now)
	if core.ValidateTenantQuotaProjection(&projection) != nil {
		return core.TenantQuotaProjection{}, ErrInvalidProjection
	}
	return projection, nil
}

func (r *Relay) retry(
	ctx context.Context, event *commerce.OutboxEvent, reason string, now time.Time,
) error {
	return r.store.FailQuotaProjectionDelivery(
		ctx, event.ID, r.config.Owner, reason, now, now.Add(r.backoff(event)),
	)
}

func classifyProjectionError(err error) string {
	switch {
	case errors.Is(err, ErrInvalidEvent):
		return reasonInvalidEvent
	case errors.Is(err, commerce.ErrEntitlementNotFound):
		return reasonEntitlementMissing
	case errors.Is(err, commerce.ErrRevisionConflict):
		return reasonEntitlementDrift
	default:
		return reasonProjectionInvalid
	}
}

func classifyPublishError(err error) (string, bool) {
	if errors.Is(err, ErrAuthorizationRejected) {
		return reasonAuthorization, true
	}
	if errors.Is(err, ErrInvalidEvent) || errors.Is(err, ErrInvalidProjection) {
		return reasonProjectionInvalid, false
	}
	if errors.Is(err, ErrInvalidReceipt) || errors.Is(err, ErrProtocolConflict) {
		return reasonProtocol, false
	}
	status, ok := responseStatus(err)
	if !ok {
		return reasonTransport, false
	}
	switch {
	case status == http.StatusTooManyRequests:
		return reasonRateLimited, false
	case status >= http.StatusInternalServerError:
		return reasonUnavailable, false
	case status >= http.StatusMultipleChoices && status < http.StatusBadRequest:
		return reasonProtocol, false
	default:
		return reasonRejected, false
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
	return projectionJitter(delay, event.ID, event.Attempts)
}

func projectionJitter(delay time.Duration, eventID string, attempts int) time.Duration {
	base, window := delay-delay/4, delay/4
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(eventID))
	var attemptBytes [8]byte
	for index := range attemptBytes {
		attemptBytes[index] = byte(uint64(attempts) >> (index * 8))
	}
	_, _ = hash.Write(attemptBytes[:])
	return base + time.Duration(hash.Sum64()%uint64(window+1))
}
