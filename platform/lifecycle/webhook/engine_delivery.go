package webhook

import (
	"context"
	"fmt"
	"time"

	"github.com/snaplink/sso/platform/audit"
)

// deliver POSTs ev to sub's URL under the Engine's configured retry policy,
// running in its own goroutine (see Record). A panic in the HTTP path
// (e.g. a custom *http.Client transport) is contained here rather than
// crashing the process, mirroring protocols/caep.Transmitter.deliver.
func (e *Engine) deliver(sub EventSubscription, ev audit.Event) {
	defer e.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			e.fail(sub, ev, fmt.Sprintf("panic: %v", r))
		}
	}()
	retrying := audit.NewRetryingSink(e.newWebhookSink(sub),
		audit.WithRetryMaxAttempts(e.retryMaxAttempts),
		audit.WithRetryInitialBackoff(e.retryInitialBackoff),
		audit.WithRetryMaxBackoff(e.retryMaxBackoff),
	)
	if err := retrying.Record(e.ctx, &ev); err != nil {
		e.fail(sub, ev, err.Error())
		return
	}
	if e.metric != nil {
		e.metric(OutcomeDelivered)
	}
}

// newWebhookSink builds the per-delivery signing/POST sink over the
// Engine's shared *http.Client (connection reuse across deliveries) and
// sub's own HMAC secret — reusing auditsink.WebhookSink rather than
// duplicating HTTP + signing logic (AGENTS.md: study CAEP, stay consistent;
// wire via the same seam without duplicating audit plumbing).
func (e *Engine) newWebhookSink(sub EventSubscription) *audit.WebhookSink {
	opts := []audit.WebhookOption{audit.WithWebhookHTTPClient(e.client)}
	if e.timeout > 0 {
		opts = append(opts, audit.WithWebhookTimeout(e.timeout))
	}
	if sub.Secret != "" {
		opts = append(opts, audit.WithWebhookSigningSecret(sub.Secret))
	}
	return audit.NewWebhookSink(sub.URL, opts...)
}

// fail records a delivery's exhausted-retry outcome: metric, log, an
// EventWebhookDeliveryFailed audit event (best-effort, when a failure
// recorder is wired), and — the durable piece — a DeadLetterEntry so an
// operator can inspect and replay it later.
func (e *Engine) fail(sub EventSubscription, ev audit.Event, reason string) {
	if e.metric != nil {
		e.metric(OutcomeFailed)
	}
	if e.logger != nil {
		e.logger.Error("webhook: delivery failed", "subscription_id", sub.ID, "url", sub.URL, "reason", reason)
	}
	now := time.Now().UTC()
	if e.dlq != nil {
		if e.metric != nil {
			e.metric(OutcomeDeadLettered)
		}
		_, _ = e.dlq.Add(context.Background(), DeadLetterEntry{
			SubscriptionID: sub.ID,
			URL:            sub.URL,
			Event:          ev,
			Attempts:       e.retryMaxAttempts,
			LastError:      reason,
			FirstFailedAt:  now,
			LastFailedAt:   now,
		})
	}
	if e.recorder != nil {
		fe := &audit.Event{
			Type:      EventWebhookDeliveryFailed,
			Outcome:   audit.OutcomeFailure,
			Timestamp: now,
			Reason:    reason,
		}
		audit.SetMeta(fe, "webhook_subscription_id", sub.ID)
		audit.SetMeta(fe, "webhook_url", sub.URL)
		e.recorder.Record(context.Background(), fe)
	}
}

// Replay re-attempts delivery of a dead-lettered event to its subscription,
// resolved FRESH from the SubscriptionStore (so a since-rotated secret or
// since-edited URL is honored — mirrors protocols/caep's "resolve fresh, no
// cache" philosophy). A single attempt, no retry chain: replay is an
// explicit synchronous admin action, and the operator gets an immediate
// result rather than waiting out a multi-attempt backoff.
//
// Success removes the entry from the dead-letter queue. A repeat failure
// updates the SAME entry's Attempts/LastError in place (DeadLetterStore.Add
// is upsert-by-ID) so the operator sees the latest failure without losing
// the entry or its position in the queue.
func (e *Engine) Replay(ctx context.Context, id string) (DeadLetterEntry, error) {
	if e == nil || e.dlq == nil {
		return DeadLetterEntry{}, ErrDeadLetterNotFound
	}
	entry, err := e.dlq.Get(ctx, id)
	if err != nil {
		return DeadLetterEntry{}, err
	}
	if e.subs == nil {
		return DeadLetterEntry{}, ErrSubscriptionNotFound
	}
	sub, err := e.subs.Get(ctx, entry.SubscriptionID)
	if err != nil {
		return DeadLetterEntry{}, fmt.Errorf("webhook: replay %s: resolve subscription %s: %w", id, entry.SubscriptionID, err)
	}

	evCopy := entry.Event
	if sendErr := e.newWebhookSink(sub).Record(ctx, &evCopy); sendErr != nil {
		entry.Attempts++
		entry.LastError = sendErr.Error()
		entry.LastFailedAt = time.Now().UTC()
		_, _ = e.dlq.Add(ctx, entry)
		return entry, sendErr
	}
	_ = e.dlq.Delete(ctx, id)
	return entry, nil
}
