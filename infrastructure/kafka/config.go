package kafkaaudit

import "time"

// Config configures the Kafka producer backing [New]. Brokers and Topic are
// required; every other field falls back to a production-safe default when
// zero — the same zero-value-as-default convention config.AuditWebhookConfig
// uses, so an operator's mental model transfers directly.
type Config struct {
	// Brokers lists the bootstrap broker addresses (host:port), tried in
	// order; kafka-go discovers the full cluster metadata from whichever one
	// answers first. Required.
	Brokers []string

	// Topic is the destination topic for every published event. Required.
	// There is no per-tenant/per-event-type topic routing in v1 — pair with
	// a downstream Kafka Streams/Connect job if that fan-out is needed.
	Topic string

	// ClientID identifies this producer in Kafka broker-side logs/metrics.
	// Defaults to "sso-server" when empty.
	ClientID string

	// RequiredAcks selects the durability/latency trade-off: "none" (fire
	// and forget), "one" (leader ack), or "all" (full ISR ack). Defaults to
	// "all" — audit events are a compliance record this Sink does not want
	// silently dropped on a leader failover, the opposite of kafka-go's own
	// library default (RequireNone).
	RequiredAcks string

	// BatchTimeout bounds how long the writer buffers a partial batch before
	// flushing. kafka-go's library default (1s) applies when zero.
	BatchTimeout time.Duration

	// Async publishes fire-and-forget (WriteMessages returns without
	// waiting for the broker ack, and swallows any resulting error) when
	// true. Defaults to false: Record blocks for the ack so its error
	// return is a real signal for the audit Recorder's fail-open /
	// ErrorHandler policy. Pair false with platform/audit's AsyncSink to
	// move the wait off the request hot path instead of setting this true.
	Async bool
}
