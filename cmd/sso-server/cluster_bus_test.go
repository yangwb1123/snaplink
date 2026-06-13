package main

import (
	"strings"
	"testing"

	"github.com/snaplink/sso/config"
)

// TestBuildInvalidationBus_UnsetIsNil proves the default (no backend)
// yields a nil bus — single-node deployments invalidate locally and
// must not be forced to stand up a bus.
func TestBuildInvalidationBus_UnsetIsNil(t *testing.T) {
	bus, kind, err := buildInvalidationBus(&config.ClusterBusConfig{}, quietLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if bus != nil {
		t.Errorf("bus = %v; want nil for unset backend", bus)
	}
	if kind != "" {
		t.Errorf("kind = %q; want empty", kind)
	}
}

// TestBuildInvalidationBus_Memory proves the in-process backend wires up.
func TestBuildInvalidationBus_Memory(t *testing.T) {
	bus, kind, err := buildInvalidationBus(&config.ClusterBusConfig{Backend: "memory"}, quietLogger())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if bus == nil || kind != "memory" {
		t.Fatalf("bus=%v kind=%q; want non-nil memory", bus, kind)
	}
	defer func() { _ = bus.Close() }()
}

// TestBuildInvalidationBus_EtcdRequiresEndpoints mirrors buildRegistry's
// contract: the etcd path must fail fast with an operator-facing error
// rather than dialing nothing.
func TestBuildInvalidationBus_EtcdRequiresEndpoints(t *testing.T) {
	_, _, err := buildInvalidationBus(&config.ClusterBusConfig{Backend: "etcd"}, quietLogger())
	if err == nil {
		t.Fatal("expected error when etcd_endpoints is empty")
	}
	if !strings.Contains(err.Error(), "etcd_endpoints") {
		t.Errorf("error %q does not mention etcd_endpoints", err)
	}
}

// TestBuildInvalidationBus_UnknownBackendErrors guards YAML typos.
func TestBuildInvalidationBus_UnknownBackendErrors(t *testing.T) {
	_, _, err := buildInvalidationBus(&config.ClusterBusConfig{Backend: "mythical"}, quietLogger())
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}
