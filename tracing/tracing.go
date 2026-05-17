// Package tracing wires an OTLP-exporting OpenTelemetry trace
// provider into the SSO server. Companion to metrics/ — together they
// make up the observability story (metrics for aggregates, traces
// for per-request causal chains).
//
// Operator UX:
//
//	shutdown, _ := tracing.Init(ctx, tracing.WithServiceName("sso-server"))
//	defer shutdown(ctx)
//	// ... start sso-server ...
//
// When OTEL_EXPORTER_OTLP_ENDPOINT is unset AND no [WithEndpoint] is
// passed, Init is a no-op that returns a no-op shutdown — callers can
// always wire `defer shutdown(ctx)` without conditional logic. Otel
// env vars are honored as defaults so operators set:
//
//	OTEL_EXPORTER_OTLP_ENDPOINT=otel-collector:4317   # required
//	OTEL_EXPORTER_OTLP_PROTOCOL=grpc                  # default
//	OTEL_EXPORTER_OTLP_INSECURE=true                  # for dev
//
// and don't touch sso-server config.
package tracing

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
)

// Config holds the SDK init knobs. All fields optional; sensible
// defaults defer to OTEL_* env vars where applicable.
type Config struct {
	// ServiceName populates the `service.name` resource attribute
	// every span carries. Default: "snaplink-sso".
	ServiceName string

	// Endpoint is the OTLP collector address. When empty, falls back
	// to OTEL_EXPORTER_OTLP_ENDPOINT; when both are empty, Init is a
	// no-op (returns a no-op shutdown).
	Endpoint string

	// Insecure skips TLS to the collector. Default false. Honors
	// OTEL_EXPORTER_OTLP_INSECURE=true when this field is false.
	Insecure bool

	// SampleRate is the head-sampling fraction (0.0 to 1.0). Wrapped
	// in ParentBased so an upstream traceparent's sampled flag is
	// honored regardless. Default: 1.0 (sample everything; rely on
	// upstream parent decisions in production).
	SampleRate float64

	// Exporter is for tests — when non-nil, replaces the OTLP
	// exporter Init would otherwise construct from Endpoint. Lets
	// tests drive an InMemoryExporter without standing up a real
	// collector.
	Exporter sdktrace.SpanExporter
}

// Option mutates a Config. Options chain in declaration order.
type Option func(*Config)

// WithServiceName sets the `service.name` resource attribute.
func WithServiceName(n string) Option {
	return func(c *Config) { c.ServiceName = n }
}

// WithEndpoint overrides the OTLP collector address (and the
// OTEL_EXPORTER_OTLP_ENDPOINT fallback).
func WithEndpoint(e string) Option {
	return func(c *Config) { c.Endpoint = e }
}

// WithInsecure disables TLS to the collector.
func WithInsecure() Option {
	return func(c *Config) { c.Insecure = true }
}

// WithSampleRate sets the head-sampling fraction (0.0 to 1.0). The
// resulting sampler is wrapped in ParentBased so upstream traceparent
// sampled-flag decisions still win.
func WithSampleRate(r float64) Option {
	return func(c *Config) { c.SampleRate = r }
}

// WithExporter injects a custom SpanExporter, bypassing OTLP
// construction. For tests — InMemoryExporter is the common choice.
// Production code should not call this; let Init build the OTLP
// exporter from the endpoint config.
func WithExporter(e sdktrace.SpanExporter) Option {
	return func(c *Config) { c.Exporter = e }
}

// Init constructs a TracerProvider with an OTLP gRPC exporter and
// registers it as the global provider + propagator. Returns a
// shutdown function that flushes in-flight spans on process exit.
//
// No-op behavior: when neither cfg.Endpoint nor cfg.Exporter is set
// AND OTEL_EXPORTER_OTLP_ENDPOINT is unset, Init does NOT register a
// provider (the global stays the no-op default) and returns a no-op
// shutdown. Callers can wire `shutdown, _ := tracing.Init(...)` and
// `defer shutdown(ctx)` unconditionally.
func Init(ctx context.Context, opts ...Option) (shutdown func(context.Context) error, err error) {
	cfg := &Config{
		ServiceName: "snaplink-sso",
		SampleRate:  1.0,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	exporter := cfg.Exporter
	if exporter == nil {
		endpoint := cfg.Endpoint
		if endpoint == "" {
			endpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		}
		if endpoint == "" {
			// No endpoint, no exporter — operate as no-op.
			return func(context.Context) error { return nil }, nil
		}
		// Strip scheme — otlptracegrpc.WithEndpoint expects
		// host:port, not http://host:port (a common operator mistake).
		endpoint = strings.TrimPrefix(endpoint, "http://")
		endpoint = strings.TrimPrefix(endpoint, "https://")

		grpcOpts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(endpoint),
		}
		if cfg.Insecure || os.Getenv("OTEL_EXPORTER_OTLP_INSECURE") == "true" {
			grpcOpts = append(grpcOpts, otlptracegrpc.WithInsecure())
		}
		client := otlptracegrpc.NewClient(grpcOpts...)
		exp, err := otlptrace.New(ctx, client)
		if err != nil {
			return nil, fmt.Errorf("tracing: otlp exporter: %w", err)
		}
		exporter = exp
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("tracing: resource: %w", err)
	}

	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRate))
	if cfg.SampleRate >= 1.0 {
		// Cheap fast-path — AlwaysSample skips the ratio computation
		// per span.
		sampler = sdktrace.ParentBased(sdktrace.AlwaysSample())
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)
	otel.SetTracerProvider(tp)

	// W3C TraceContext + Baggage propagators — the standard pair every
	// service in a polyglot deployment expects. Without registering,
	// otelhttp.NewHandler can't extract incoming traceparent headers.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp.Shutdown, nil
}

// Middleware wraps an http.Handler so every request creates a span.
// Incoming W3C traceparent headers are honored as the parent span;
// when absent, a fresh trace is rooted.
//
// operation is the span name template; otelhttp adds the route +
// method as attributes so a single template ("sso-server") yields
// per-endpoint breakdowns in tools like Tempo / Jaeger via attribute
// filters.
func Middleware(operation string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return otelhttp.NewHandler(next, operation)
	}
}
