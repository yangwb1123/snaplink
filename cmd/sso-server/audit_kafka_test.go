package main

import (
	"testing"

	"github.com/yangwb1123/snaplink/config"
)

// The standard-kafka cold profile compiles the explicit registration path and
// verifies the linked module in binary metadata. The root module keeps
// registry-level behavior coverage with a fake factory and no real broker.
// The stock binary must still fail closed when Kafka is configured but the
// audit-kafka module was not compiled in.

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
