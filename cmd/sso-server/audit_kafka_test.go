package main

import (
	"testing"

	"github.com/snaplink/sso/config"
)

// audit.kafka's HAPPY path (a real Kafka producer actually publishing) can
// only be exercised by an operator's forked binary that imports
// infrastructure/kafka and calls
// serverbuildauthn.RegisterAuditKafkaSinkFactory — see that module's package
// doc and cmd/sso-server/serverbuildauthn/build_audit_kafka_test.go for the
// registry-level coverage (fake factory, no real broker). What cmd/sso-server
// itself must guarantee, without that registration ever happening, is the
// FAIL-CLOSED behavior below: a binary that enables audit.kafka but forgets
// to fork+register never silently drops the audit stream.

func TestBuildApp_AuditKafkaDisabledIsNoop(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	// audit.kafka.enabled left false (zero value).

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	if a.auditKafkaSink != nil {
		t.Fatal("auditKafkaSink must be nil when audit.kafka.enabled=false")
	}
}

func TestBuildApp_AuditKafkaRequiresBrokersAndTopic(t *testing.T) {
	t.Parallel()
	noBrokers := &config.Config{}
	noBrokers.Audit.Enabled = true
	noBrokers.Audit.MemoryCapacity = 16
	noBrokers.Audit.Kafka.Enabled = true
	noBrokers.Audit.Kafka.Topic = "audit-events"
	if _, err := buildApp(noBrokers, quietLogger()); err == nil {
		t.Fatal("expected error when audit.kafka.enabled with no brokers")
	}

	noTopic := &config.Config{}
	noTopic.Audit.Enabled = true
	noTopic.Audit.MemoryCapacity = 16
	noTopic.Audit.Kafka.Enabled = true
	noTopic.Audit.Kafka.Brokers = []string{"broker:9092"}
	if _, err := buildApp(noTopic, quietLogger()); err == nil {
		t.Fatal("expected error when audit.kafka.enabled with no topic")
	}
}

func TestBuildApp_AuditKafkaFailsClosedWithoutRegisteredFactory(t *testing.T) {
	t.Parallel()
	// A well-formed config (brokers + topic set) but this binary — like the
	// shipped cmd/sso-server, which never imports infrastructure/kafka —
	// has no factory registered. Boot must fail with a clear error, not
	// silently build the server with the audit stream missing its Kafka
	// leg.
	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	cfg.Audit.Kafka.Enabled = true
	cfg.Audit.Kafka.Brokers = []string{"broker:9092"}
	cfg.Audit.Kafka.Topic = "audit-events"

	_, err := buildApp(cfg, quietLogger())
	if err == nil {
		t.Fatal("expected error when audit.kafka.enabled with no registered factory")
	}
}
