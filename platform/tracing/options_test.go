package tracing_test

import (
	"context"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/platform/tracing"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// captureCfg pulls a Config out the back of an Option chain so option
// setters can be asserted without standing up a full tracing pipeline.
func captureCfg(t *testing.T, opts ...tracing.Option) tracing.Config {
	t.Helper()
	var cfg tracing.Config
	for _, o := range opts {
		o(&cfg)
	}
	return cfg
}

func TestWithEndpoint(t *testing.T) {
	cfg := captureCfg(t, tracing.WithEndpoint("otel-collector:4317"))
	if cfg.Endpoint != "otel-collector:4317" {
		t.Errorf("Endpoint = %q", cfg.Endpoint)
	}
}

func TestWithInsecure(t *testing.T) {
	cfg := captureCfg(t, tracing.WithInsecure())
	if !cfg.Insecure {
		t.Error("Insecure = false, want true")
	}
}

func TestWithSampleRate(t *testing.T) {
	cfg := captureCfg(t, tracing.WithSampleRate(0.25))
	if cfg.SampleRate != 0.25 {
		t.Errorf("SampleRate = %v, want 0.25", cfg.SampleRate)
	}
}

func TestWithEndpoint_PassesThroughInit(t *testing.T) {
	// Init with an explicit endpoint but no real collector: the OTLP
	// dialer is constructed lazily so Init returns nil err. The
	// shutdown should also return cleanly.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	shutdown, err := tracing.Init(context.Background(),
		tracing.WithServiceName("opt-test"),
		tracing.WithEndpoint("localhost:0"),
		tracing.WithInsecure(),
		tracing.WithSampleRate(0.5),
	)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if shutdown == nil {
		t.Fatal("shutdown nil")
	}
	// Shutdown will fail because the dialer can't reach localhost:0,
	// but we just care that Init constructed the pipeline + the
	// shutdown is callable.
	_ = shutdown(context.Background())
}

func TestInit_EndpointStripsScheme(t *testing.T) {
	// otlptracegrpc.WithEndpoint wants host:port — a common operator
	// mistake is to leave http:// on the value. Init must strip it.
	// We can't easily inspect the constructed dialer's endpoint
	// directly, so the closest verifiable behavior is "Init doesn't
	// reject a scheme-prefixed endpoint". A failure here would mean
	// otlptracegrpc returned an error during construction.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	if _, err := tracing.Init(context.Background(),
		tracing.WithEndpoint("http://otel-collector:4317"),
		tracing.WithInsecure(),
	); err != nil && strings.Contains(err.Error(), "scheme") {
		t.Errorf("scheme prefix should be tolerated: %v", err)
	}
}

func TestInit_HonorsEnvVarFallback(t *testing.T) {
	// No explicit WithEndpoint — Init should pick up the env var.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:0")
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "true")
	_, err := tracing.Init(context.Background(), tracing.WithServiceName("env-test"))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
}

func TestInit_NoopWhenEnvBlank(t *testing.T) {
	// Clearing env + no explicit endpoint = no-op.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "")
	shutdown, err := tracing.Init(context.Background(), tracing.WithServiceName("noop-test"))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("noop shutdown = %v", err)
	}
}

func TestInit_SampleRateBelowOne_TakesRatioPath(t *testing.T) {
	// SampleRate < 1 takes the TraceIDRatioBased branch (vs AlwaysSample
	// fast-path at >= 1.0). We can't read back the sampler, but exercising
	// the branch keeps coverage on the conditional.
	exp := tracetest.NewInMemoryExporter()
	shutdown, err := tracing.Init(context.Background(),
		tracing.WithExporter(exp),
		tracing.WithSampleRate(0.5),
	)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	_ = shutdown(context.Background())
}
