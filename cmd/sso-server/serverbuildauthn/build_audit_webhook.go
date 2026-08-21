package serverbuildauthn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/audit/auditspi"
	"github.com/yangwb1123/snaplink/platform/lifecycle/modules"
	"github.com/yangwb1123/snaplink/platform/lifecycle/webhook"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// DefaultAuditWebhookSubscriptionName is the reserved name given to the
// implicit subscription synthesized from the legacy scalar audit.webhook.url.
// An explicit subscriptions[] entry may not reuse it when a scalar URL is also
// set, since both would collapse to the same identity.
const DefaultAuditWebhookSubscriptionName = "default"

// BuildAuditWebhookSinks compiles the configured audit webhook subscriptions
// into one delivery sink each, ready to fan into the primary MultiSink. Each
// sink is RetryingSink(FilteringSink(WebhookSink)): the webhook transports the
// event, the filter drops types the subscription didn't select, and the retry
// wrapper masks transient downstream failures.
//
// The legacy scalar url (when set) becomes an implicit unfiltered subscription
// named DefaultAuditWebhookSubscriptionName, preserving the single-endpoint
// firehose behavior. Boot fails when a subscription has no name or url, or two
// subscriptions share a name (including a scalar-vs-list "default" clash).
func BuildAuditWebhookSinks(w config.AuditWebhookConfig, logger spi.Logger) ([]audit.Sink, error) {
	subs := effectiveAuditWebhookSubscriptions(w)
	if len(subs) == 0 {
		return nil, errors.New("audit.webhook.enabled requires url or at least one subscription")
	}
	seen := make(map[string]struct{}, len(subs))
	sinks := make([]audit.Sink, 0, len(subs))
	for _, sub := range subs {
		if sub.Name == "" {
			return nil, errors.New("audit.webhook.subscriptions[].name is required")
		}
		if _, dup := seen[sub.Name]; dup {
			return nil, fmt.Errorf("audit.webhook: duplicate subscription name %q", sub.Name)
		}
		seen[sub.Name] = struct{}{}
		sink, err := buildAuditSubscriptionSink(sub, logger)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, sink)
	}
	return sinks, nil
}

// BuildManagedWebhookRuntime builds the runtime-registered event exporter
// used by stock sso-server. Subscription and dead-letter stores are shared by
// every generation; only delivery policy and HTTP workers rotate.
func BuildManagedWebhookRuntime(
	cfg config.WebhooksConfig, recorder *audit.Recorder, logger spi.Logger,
) (*webhook.ManagedRuntime, error) {
	subs := webhook.NewMemorySubscriptionStore()
	deadLetters := webhook.NewMemoryDeadLetterStore(cfg.DeadLetterCapacity)
	initial, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("webhooks: encode initial policy: %w", err)
	}
	factory := func(ctx context.Context, raw []byte, generation uint64) (*webhook.Engine, error) {
		var current config.WebhooksConfig
		if err := json.Unmarshal(raw, &current); err != nil {
			return nil, fmt.Errorf("webhooks generation %d: decode policy: %w", generation, err)
		}
		if !current.Enabled {
			return nil, errors.New("webhooks: disabling requires a server restart")
		}
		return webhook.NewEngine(subs, deadLetters, managedWebhookOptions(current, recorder, logger)...), nil
	}
	options := modules.Options{
		TransitionObserver: webhookTransitionObserver(recorder, logger),
	}
	runtime, err := webhook.NewManagedRuntime(factory, initial, options)
	if err != nil {
		return nil, fmt.Errorf("webhooks: lifecycle startup: %w", err)
	}
	return runtime, nil
}

func managedWebhookOptions(
	cfg config.WebhooksConfig, recorder *audit.Recorder, logger spi.Logger,
) []webhook.Option {
	opts := []webhook.Option{
		webhook.WithFailureRecorder(recorder),
		webhook.WithLogger(logger),
	}
	if cfg.DeliveryTimeout > 0 {
		opts = append(opts, webhook.WithDeliveryTimeout(cfg.DeliveryTimeout))
	}
	if cfg.Retry.MaxAttempts > 0 || cfg.Retry.InitialBackoff > 0 || cfg.Retry.MaxBackoff > 0 {
		opts = append(opts, webhook.WithDeliveryRetry(
			cfg.Retry.MaxAttempts, cfg.Retry.InitialBackoff, cfg.Retry.MaxBackoff,
		))
	}
	return opts
}

func webhookTransitionObserver(recorder *audit.Recorder, logger spi.Logger) modules.TransitionObserver {
	return modules.TransitionObserverFunc(func(ctx context.Context, event modules.TransitionEvent) error {
		if logger != nil {
			logger.Info("webhook exporter lifecycle transition",
				"type", event.Type, "generation", event.Generation,
				"related_generation", event.RelatedGeneration)
		}
		if recorder == nil {
			return nil
		}
		auditEvent := &audit.Event{
			Type:      audit.EventWebhookLifecycleTransition,
			Outcome:   audit.OutcomeSuccess,
			Timestamp: event.OccurredAt,
			Reason:    string(event.Type),
		}
		audit.SetMeta(auditEvent, "module_id", event.ModuleID)
		audit.SetMeta(auditEvent, "generation", fmt.Sprintf("%d", event.Generation))
		if event.RelatedGeneration != 0 {
			audit.SetMeta(auditEvent, "related_generation", fmt.Sprintf("%d", event.RelatedGeneration))
		}
		recorder.Record(ctx, auditEvent)
		return nil
	})
}

// effectiveAuditWebhookSubscriptions prepends the legacy scalar webhook (when a
// url is set) as the implicit "default" subscription, then appends the explicit
// list. The scalar carries no event_types, so it stays a firehose.
func effectiveAuditWebhookSubscriptions(w config.AuditWebhookConfig) []config.AuditWebhookSubscription {
	var subs []config.AuditWebhookSubscription
	if w.URL != "" {
		subs = append(subs, config.AuditWebhookSubscription{
			Name:          DefaultAuditWebhookSubscriptionName,
			URL:           w.URL,
			Timeout:       w.Timeout,
			Headers:       w.Headers,
			SigningSecret: w.SigningSecret,
			Retry:         w.Retry,
		})
	}
	return append(subs, w.Subscriptions...)
}

// buildAuditSubscriptionSink assembles one subscription's delivery stack and
// logs its (non-secret) shape. The signing secret is a credential — only its
// presence is logged, never its value.
func buildAuditSubscriptionSink(sub config.AuditWebhookSubscription, logger spi.Logger) (audit.Sink, error) {
	if sub.URL == "" {
		return nil, fmt.Errorf("audit.webhook subscription %q: url is required", sub.Name)
	}
	warnUnknownAuditEventTypes(sub, logger)
	webhook := audit.NewWebhookSink(sub.URL, auditWebhookOptions(sub)...)
	filtered := audit.NewFilteringSink(webhook, audit.WithEventTypeFilter(sub.EventTypes...))
	retrying := audit.NewRetryingSink(filtered, auditRetryOptions(sub.Retry)...)
	logger.Info("audit: webhook subscription enabled",
		"name", sub.Name,
		"url", sub.URL,
		"event_types", len(sub.EventTypes),
		"header_count", len(sub.Headers),
		"signed", sub.SigningSecret != "",
	)
	return retrying, nil
}

func auditWebhookOptions(sub config.AuditWebhookSubscription) []audit.WebhookOption {
	opts := []audit.WebhookOption{}
	if sub.Timeout > 0 {
		opts = append(opts, audit.WithWebhookTimeout(sub.Timeout))
	}
	for k, v := range sub.Headers {
		opts = append(opts, audit.WithWebhookHeader(k, v))
	}
	if sub.SigningSecret != "" {
		opts = append(opts, audit.WithWebhookSigningSecret(sub.SigningSecret))
	}
	return opts
}

func auditRetryOptions(r config.AuditWebhookRetryConfig) []audit.RetryOption {
	opts := []audit.RetryOption{}
	if r.MaxAttempts > 0 {
		opts = append(opts, audit.WithRetryMaxAttempts(r.MaxAttempts))
	}
	if r.InitialBackoff > 0 {
		opts = append(opts, audit.WithRetryInitialBackoff(r.InitialBackoff))
	}
	if r.MaxBackoff > 0 {
		opts = append(opts, audit.WithRetryMaxBackoff(r.MaxBackoff))
	}
	return opts
}

// warnUnknownAuditEventTypes logs each exact filter entry the SDK does not
// itself emit. Custom event types are legal (an operator's own emitters may
// produce them), so this never fails boot — it only surfaces likely typos.
// Wildcard patterns and blanks are skipped: they are not literal type names.
func warnUnknownAuditEventTypes(sub config.AuditWebhookSubscription, logger spi.Logger) {
	for _, t := range sub.EventTypes {
		if t == "" || strings.HasSuffix(t, audit.EventTypeWildcardSuffix) {
			continue
		}
		if _, known := auditspi.KnownEventTypes[auditspi.EventType(t)]; !known {
			logger.Info("audit.webhook subscription: unrecognized event_type (custom types are allowed)",
				"name", sub.Name, "event_type", t)
		}
	}
}
