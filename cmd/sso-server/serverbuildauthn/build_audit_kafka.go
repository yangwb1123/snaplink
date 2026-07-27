package serverbuildauthn

import (
	"errors"
	"fmt"
	"sync"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// AuditKafkaSinkFactory builds a Kafka-backed audit.Sink from
// config.AuditKafkaConfig. The concrete implementation (backed by
// segmentio/kafka-go) lives in the infrastructure/kafka nested module so its
// dependency never enters this (the core) module's go.mod — mirrors
// serverbuildsign.ExternalSignerFactory / RegisterExternalSigner for
// KMS/HSM signers. The standard-kafka cold profile imports the module and
// calls RegisterAuditKafkaSinkFactory(kafkaaudit.Factory) explicitly before
// configuration is loaded.
type AuditKafkaSinkFactory func(cfg config.AuditKafkaConfig, logger spi.Logger) (audit.Sink, error)

// auditKafkaFactory holds the single registered factory. Unlike
// ExternalSignerRegistry (which supports several named KMS/HSM vendors
// behind one generic crypto.Signer interface) this is a single named slot:
// every field a Kafka producer needs already lives in
// config.AuditKafkaConfig, so there is exactly one integration to register,
// not one per vendor.
var auditKafkaFactory struct {
	mu sync.RWMutex
	f  AuditKafkaSinkFactory
}

// RegisterAuditKafkaSinkFactory registers the factory this binary uses when
// audit.kafka.enabled. Panics on a nil factory or a second call (both
// unrecoverable wiring mistakes — same posture as RegisterExternalSigner).
func RegisterAuditKafkaSinkFactory(f AuditKafkaSinkFactory) {
	if f == nil {
		panic("RegisterAuditKafkaSinkFactory: nil factory")
	}
	auditKafkaFactory.mu.Lock()
	defer auditKafkaFactory.mu.Unlock()
	if auditKafkaFactory.f != nil {
		panic("RegisterAuditKafkaSinkFactory: already registered")
	}
	auditKafkaFactory.f = f
}

// lookupAuditKafkaSinkFactory returns the registered factory, if any. Test-only
// resets go through resetAuditKafkaSinkFactoryForTest below — production code
// has no unregister path (a registration is a boot-time, once-only wiring
// decision, same as RegisterExternalSigner).
func lookupAuditKafkaSinkFactory() (AuditKafkaSinkFactory, bool) {
	auditKafkaFactory.mu.RLock()
	defer auditKafkaFactory.mu.RUnlock()
	return auditKafkaFactory.f, auditKafkaFactory.f != nil
}

// BuildAuditKafkaSink builds the Kafka sink when audit.kafka.enabled, or
// returns (nil, nil) when disabled. The returned sink is the RAW factory
// output (not retry-wrapped) so the caller can both wrap it for the
// MultiSink chain AND retain the unwrapped reference for graceful-shutdown
// Close — RetryingSink does not forward Close (see platform/audit/auditsink
// retrying_sink.go).
func BuildAuditKafkaSink(cfg config.AuditKafkaConfig, logger spi.Logger) (audit.Sink, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if len(cfg.Brokers) == 0 {
		return nil, errors.New("audit.kafka.enabled requires at least one broker")
	}
	if cfg.Topic == "" {
		return nil, errors.New("audit.kafka.enabled requires topic")
	}
	factory, ok := lookupAuditKafkaSinkFactory()
	if !ok {
		return nil, errors.New("audit.kafka.enabled requires the audit-kafka module; build profile standard-kafka (see docs/plugin-system.md)")
	}
	sink, err := factory(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("audit.kafka: %w", err)
	}
	if sink == nil {
		return nil, errors.New("audit.kafka: registered factory returned a nil sink")
	}
	logger.Info("audit: kafka sink enabled", "brokers", len(cfg.Brokers), "topic", cfg.Topic, "format", cfg.Format)
	return sink, nil
}
