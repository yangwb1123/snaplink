package metrics_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/metrics"
)

type errSink struct{}

func (errSink) Record(context.Context, *audit.Event) error {
	return errors.New("nope")
}
func (errSink) Get(context.Context, string) (*audit.Event, error) {
	return nil, audit.ErrEventNotFound
}
func (errSink) Query(context.Context, audit.Query) ([]*audit.Event, error) {
	return nil, nil
}

func TestAsyncSinkCollector_ScrapeReportsCounters(t *testing.T) {
	t.Parallel()
	async := audit.NewAsyncSink(errSink{}, audit.WithAsyncBuffer(4))
	async.Start()
	t.Cleanup(func() { _ = async.Close(context.Background()) })

	reg := prometheus.NewRegistry()
	reg.MustRegister(metrics.NewAsyncSinkCollector(async))

	// Drive one event through; inner returns err so inner-error
	// counter ticks. Close drains so the count is stable when we
	// scrape.
	_ = async.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	if err := async.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	scrape := scrapeRegistry(t, reg)
	for _, want := range []string{
		metrics.NameAuditAsyncDropsQueueFull,
		metrics.NameAuditAsyncDropsClosed,
		metrics.NameAuditAsyncDropsInnerError,
		metrics.NameAuditAsyncQueueDepth,
		metrics.NameAuditAsyncQueueCapacity,
	} {
		if !strings.Contains(scrape, want) {
			t.Errorf("metric %q missing from scrape:\n%s", want, scrape)
		}
	}
	// The error sink guarantees DropsInnerError advanced by 1.
	if !strings.Contains(scrape, metrics.NameAuditAsyncDropsInnerError+" 1") {
		t.Errorf("inner-error counter didn't tick:\n%s", scrape)
	}
	// Capacity matches buffer.
	if !strings.Contains(scrape, metrics.NameAuditAsyncQueueCapacity+" 4") {
		t.Errorf("capacity gauge wrong:\n%s", scrape)
	}
}

func TestAsyncSinkCollector_NilSinkIsHarmless(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	reg.MustRegister(metrics.NewAsyncSinkCollector(nil))
	// Scraping a nil-sink collector should not panic.
	_ = scrapeRegistry(t, reg)
}

func scrapeRegistry(t *testing.T, reg *prometheus.Registry) string {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	// Just render via promhttp's text encoder by inverting: easier
	// is to walk MetricFamily directly.
	_ = promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	var b strings.Builder
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			b.WriteString(mf.GetName())
			if v := m.GetCounter(); v != nil {
				fmtAppendFloat(&b, v.GetValue())
			} else if v := m.GetGauge(); v != nil {
				fmtAppendFloat(&b, v.GetValue())
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

func fmtAppendFloat(b *strings.Builder, v float64) {
	if v == float64(int64(v)) {
		b.WriteByte(' ')
		// integer form for clean substring asserts
		b.WriteString(strconv.FormatInt(int64(v), 10))
		return
	}
	b.WriteByte(' ')
	b.WriteString(strconv.FormatFloat(v, 'f', -1, 64))
}
