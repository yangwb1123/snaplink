package kafkaaudit

import (
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/shared/spi"
)

func TestFactory_BuildsSinkFromConfig(t *testing.T) {
	t.Parallel()
	sink, err := Factory(config.AuditKafkaConfig{
		Brokers: []string{"127.0.0.1:9"},
		Topic:   "audit-events",
	}, spi.NopLogger{})
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	if sink == nil {
		t.Fatal("Factory returned nil sink")
	}
}

func TestFactory_RejectsUnknownFormat(t *testing.T) {
	t.Parallel()
	_, err := Factory(config.AuditKafkaConfig{
		Brokers: []string{"127.0.0.1:9"},
		Topic:   "audit-events",
		Format:  "protobuf",
	}, spi.NopLogger{})
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestFactory_NilLoggerIsSafe(t *testing.T) {
	t.Parallel()
	// logger is optional — Factory must not panic on nil.
	if _, err := Factory(config.AuditKafkaConfig{
		Brokers: []string{"127.0.0.1:9"},
		Topic:   "audit-events",
	}, nil); err != nil {
		t.Fatalf("Factory: %v", err)
	}
}

func TestResolveFormat(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"", "json", "cef", "ocsf", "syslog"} {
		if _, err := resolveFormat(name); err != nil {
			t.Fatalf("resolveFormat(%q): %v", name, err)
		}
	}
	if _, err := resolveFormat("bogus"); err == nil {
		t.Fatal("expected error for unknown format name")
	}
}
