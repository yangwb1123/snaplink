package kafkaaudit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	kafkago "github.com/segmentio/kafka-go"

	"github.com/snaplink/sso/platform/audit/auditsink"
)

// Producer is the subset of *kafka-go.Writer this Sink depends on — narrow
// enough that tests substitute an in-memory fake instead of dialing a real
// broker. Mirrors how auditsink.WebhookSink's tests fake the transport with
// an httptest.Server: there is no in-process Kafka broker to stand up, so
// the seam here is the producer interface instead of a real listener.
type Producer interface {
	WriteMessages(ctx context.Context, msgs ...kafkago.Message) error
	Close() error
}

// Sink publishes each recorded audit event as one Kafka message on the
// configured topic. It embeds auditsink.WriterSink so Record/Get/Query and
// the Formatter contract are reused UNCHANGED from the existing CEF/OCSF/
// syslog sinks — see auditsink.Formatter's doc comment: "this is the exact
// contract roadmap item 19 (Kafka/NATS export) reuses." Get/Query therefore
// return auditsink.ErrSinkWriteOnly, same as the webhook and SIEM sinks;
// pair with audit.MultiSink alongside a queryable sink (memory/sqlite) for
// readback.
type Sink struct {
	*auditsink.WriterSink
	producer Producer
}

// producerWriter adapts Producer to io.Writer for auditsink.WriterSink: one
// Write call is always exactly one formatted event (WriterSink.Record calls
// w.Write once per event, with the format's uniform trailing '\n' already
// appended — see auditsink's writer_sink.go), so trimming that newline and
// wrapping the remainder in a single kafka.Message preserves a strict
// one-event-per-message mapping.
type producerWriter struct {
	ctx      context.Context
	topic    string
	producer Producer
}

// Write implements io.Writer. ctx is context.Background (io.Writer.Write
// carries no context parameter); the underlying kafka.Writer's own
// WriteTimeout bounds the call instead — see Config.BatchTimeout and New's
// doc for the durability/latency knobs available on this transport.
func (p *producerWriter) Write(b []byte) (int, error) {
	value := b
	if n := len(value); n > 0 && value[n-1] == '\n' {
		value = value[:n-1]
	}
	// Copy: kafka-go retains msgs across the WriteMessages call for retry
	// bookkeeping, but b is only valid for the duration of this Write call
	// per the io.Writer contract.
	cp := make([]byte, len(value))
	copy(cp, value)
	if err := p.producer.WriteMessages(p.ctx, kafkago.Message{Topic: p.topic, Value: cp, Time: time.Now()}); err != nil {
		return 0, err
	}
	return len(b), nil
}

// New builds a Kafka-backed audit.Sink. cfg.Brokers and cfg.Topic are
// required; WithFormat overrides the default JSON-with-schema_version
// envelope (see FormatJSON) with one of the SDK's SIEM formatters.
func New(cfg Config, opts ...Option) (*Sink, error) {
	if len(cfg.Brokers) == 0 {
		return nil, errors.New("kafkaaudit: at least one broker is required")
	}
	if cfg.Topic == "" {
		return nil, errors.New("kafkaaudit: topic is required")
	}
	acks, err := parseRequiredAcks(cfg.RequiredAcks)
	if err != nil {
		return nil, err
	}
	w := &kafkago.Writer{
		Addr:         kafkago.TCP(cfg.Brokers...),
		Topic:        cfg.Topic,
		Balancer:     &kafkago.LeastBytes{},
		RequiredAcks: acks,
		Async:        cfg.Async,
		BatchTimeout: cfg.BatchTimeout,
	}
	return newWithProducer(w, cfg.Topic, opts...), nil
}

// newWithProducer builds the Sink over an already-constructed Producer —
// the seam sink_test.go uses to inject a fake, and New's real path after
// building the concrete *kafka.Writer.
func newWithProducer(producer Producer, topic string, opts ...Option) *Sink {
	options := &sinkOptions{format: FormatJSON}
	for _, opt := range opts {
		opt(options)
	}
	pw := &producerWriter{ctx: context.Background(), topic: topic, producer: producer}
	return &Sink{
		WriterSink: auditsink.NewWriterSink(pw, auditsink.WithWriterFormat(options.format)),
		producer:   producer,
	}
}

// Close flushes any buffered messages and closes the underlying Kafka
// producer connection. Safe to call once at shutdown; the
// interface{ Close(context.Context) error } shape matches what
// cmd/sso-server's shutdown path type-asserts audit sinks against (the same
// pattern platform/audit.AsyncSink.Close and the CAEP transmitter's Close
// already use) so a registered Kafka sink drains on graceful shutdown
// without cmd/sso-server needing to import this module's concrete type.
func (s *Sink) Close(ctx context.Context) error {
	done := make(chan error, 1)
	go func() { done <- s.producer.Close() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("kafkaaudit: close deadline exceeded: %w", ctx.Err())
	}
}

// parseRequiredAcks maps the config string onto kafka-go's RequiredAcks.
// Empty defaults to "all" (full ISR ack) — see Config.RequiredAcks doc for
// why this Sink's default differs from kafka-go's own library default.
func parseRequiredAcks(v string) (kafkago.RequiredAcks, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "all":
		return kafkago.RequireAll, nil
	case "one":
		return kafkago.RequireOne, nil
	case "none":
		return kafkago.RequireNone, nil
	default:
		return 0, fmt.Errorf("kafkaaudit: required_acks %q must be none|one|all", v)
	}
}
