package migrate_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/platform/tracing"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	_ "modernc.org/sqlite"
)

// initSpanExporter wires an InMemoryExporter as the global TracerProvider
// for one test. Deliberately NOT t.Parallel(): this package's other tests
// run in parallel and the OTel SDK's TracerProvider is process-global.
func initSpanExporter(t *testing.T) *tracetest.InMemoryExporter {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	shutdown, err := tracing.Init(context.Background(), tracing.WithExporter(exp))
	if err != nil {
		t.Fatalf("tracing.Init: %v", err)
	}
	t.Cleanup(func() {
		if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
			_ = tp.ForceFlush(context.Background())
		}
		_ = shutdown(context.Background())
	})
	return exp
}

func flushSpans(t *testing.T, exp *tracetest.InMemoryExporter) tracetest.SpanStubs {
	t.Helper()
	if tp, ok := otel.GetTracerProvider().(*sdktrace.TracerProvider); ok {
		_ = tp.ForceFlush(context.Background())
	}
	return exp.GetSpans()
}

func findMigrateSpan(spans tracetest.SpanStubs, name string) *tracetest.SpanStub {
	for i := range spans {
		if spans[i].Name == name {
			return &spans[i]
		}
	}
	return nil
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "m.db") + "?_busy_timeout=5000"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

var testMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: `CREATE TABLE IF NOT EXISTS widgets (id TEXT PRIMARY KEY)`},
	{Version: 2, Name: "add_name", SQL: `ALTER TABLE widgets ADD COLUMN name TEXT`},
}

// TestRun_CreatesSpan_ChildOfCtx proves Run is a child of whatever span the
// caller's ctx carries — every shipped caller passes context.Background(),
// but Run itself has no opinion, so a caller WITH a live span (e.g. an
// offline migration CLI wrapped in tracing) gets correct parenting.
func TestRun_CreatesSpan_ChildOfCtx(t *testing.T) {
	exp := initSpanExporter(t)
	db := openTestDB(t)

	ctx, parent := otel.Tracer("test").Start(context.Background(), "boot")
	if err := migrate.Run(ctx, db, "widgets", testMigrations); err != nil {
		t.Fatalf("Run: %v", err)
	}
	parent.End()

	spans := flushSpans(t, exp)
	span := findMigrateSpan(spans, "migrate.run")
	if span == nil {
		t.Fatalf("no migrate.run span; got %d spans", len(spans))
	}
	if span.SpanContext.TraceID() != parent.SpanContext().TraceID() {
		t.Errorf("trace id = %s, want parent's %s", span.SpanContext.TraceID(), parent.SpanContext().TraceID())
	}
	var sawNamespace, sawApplied bool
	for _, attr := range span.Attributes {
		switch string(attr.Key) {
		case "migrate.namespace":
			sawNamespace = attr.Value.AsString() == "widgets"
		case "migrate.applied":
			sawApplied = attr.Value.AsInt64() == 2
		}
	}
	if !sawNamespace {
		t.Error("missing/wrong migrate.namespace attribute")
	}
	if !sawApplied {
		t.Error("missing/wrong migrate.applied attribute (want 2 on a fresh DB)")
	}
}

// TestRun_NoParent_RootsSpan mirrors production reality: every shipped
// caller runs Run(context.Background(), ...) at backend construction, well
// before any request is in flight — so the span is always a fresh root.
func TestRun_NoParent_RootsSpan(t *testing.T) {
	exp := initSpanExporter(t)
	db := openTestDB(t)

	if err := migrate.Run(context.Background(), db, "widgets", testMigrations); err != nil {
		t.Fatalf("Run: %v", err)
	}

	span := findMigrateSpan(flushSpans(t, exp), "migrate.run")
	if span == nil {
		t.Fatal("no migrate.run span")
	}
	if !span.SpanContext.TraceID().IsValid() {
		t.Error("expected a freshly-minted valid trace id")
	}
	if span.Parent.IsValid() {
		t.Error("expected no parent for a context.Background() caller")
	}
}

// TestRun_Rerun_AppliedIsZero proves the idempotent no-op re-run reports
// zero applied migrations on the span, not a stale count from the first run.
func TestRun_Rerun_AppliedIsZero(t *testing.T) {
	exp := initSpanExporter(t)
	db := openTestDB(t)

	if err := migrate.Run(context.Background(), db, "widgets", testMigrations); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if err := migrate.Run(context.Background(), db, "widgets", testMigrations); err != nil {
		t.Fatalf("second Run: %v", err)
	}

	spans := flushSpans(t, exp)
	var runSpans []*tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "migrate.run" {
			runSpans = append(runSpans, &spans[i])
		}
	}
	if len(runSpans) != 2 {
		t.Fatalf("got %d migrate.run spans, want 2", len(runSpans))
	}
	for _, attr := range runSpans[1].Attributes {
		if string(attr.Key) == "migrate.applied" && attr.Value.AsInt64() != 0 {
			t.Errorf("second run migrate.applied = %d, want 0", attr.Value.AsInt64())
		}
	}
}

// TestRun_MalformedMigrations_SpanRecordsError proves a validate() failure
// (caught before any DB work) still lands on the span, not just the
// returned error.
func TestRun_MalformedMigrations_SpanRecordsError(t *testing.T) {
	exp := initSpanExporter(t)
	db := openTestDB(t)

	bad := []migrate.Migration{{Version: 1, Name: "both-set", SQL: "SELECT 1", Func: func(context.Context, migrate.Execer) error { return nil }}}
	err := migrate.Run(context.Background(), db, "widgets", bad)
	if err == nil {
		t.Fatal("expected validation error")
	}

	span := findMigrateSpan(flushSpans(t, exp), "migrate.run")
	if span == nil {
		t.Fatal("no migrate.run span")
	}
	if span.Status.Code != codes.Error {
		t.Errorf("status code = %v, want Error", span.Status.Code)
	}
	if span.Status.Description != err.Error() {
		t.Errorf("status description = %q, want %q", span.Status.Description, err.Error())
	}
}
