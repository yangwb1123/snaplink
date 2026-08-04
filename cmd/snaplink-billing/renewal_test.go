package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	tenantcommerce "github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

func TestRenewalDefaultsAreDisabledAndBounded(t *testing.T) {
	config, err := renewalDefaults(mapEnvironment(nil))
	if err != nil {
		t.Fatal(err)
	}
	config.finalize()
	if config.Enabled || config.Interval != time.Minute || config.Lease != 2*time.Minute ||
		config.RetryDelay != time.Hour || config.BatchSize != 50 || config.Owner != "" {
		t.Fatalf("renewal defaults = %+v", config)
	}
	if err := config.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRenewalConfigRejectsUnsafeValues(t *testing.T) {
	config := renewalConfig{
		Enabled: true, Owner: "worker\nforged", Interval: time.Minute,
		Lease: 2 * time.Minute, RetryDelay: time.Hour, BatchSize: 50,
	}
	if err := config.validate(); err == nil {
		t.Fatal("owner containing a newline was accepted")
	}
	config.Owner, config.BatchSize = "worker", maxRenewalBatchSize+1
	if err := config.validate(); err == nil {
		t.Fatal("oversized renewal batch was accepted")
	}
	config.BatchSize, config.Interval = 50, renewalMaxToleratedLag
	if err := config.validate(); err == nil {
		t.Fatal("renewal interval exhausting the readiness tolerance was accepted")
	}
}

func TestRuntimeConfigEnablesRenewalWorkerFromFlags(t *testing.T) {
	environment := map[string]string{
		"SNAPLINK_BILLING_DEV_MEMORY": "true",
		"SNAPLINK_BILLING_ISSUER":     "https://sso.example",
		"SNAPLINK_BILLING_AUDIENCE":   "billing-api",
	}
	args := []string{
		"--renewals-enabled", "--renewals-owner", " worker-a ",
		"--renewals-interval", "30s", "--renewals-lease", "1m",
		"--renewals-retry-delay", "15m", "--renewals-batch-size", "25",
	}
	config, err := parseRuntimeConfig(args, mapEnvironment(environment), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if !config.Renewals.Enabled || config.Renewals.Owner != "worker-a" ||
		config.Renewals.Interval != 30*time.Second || config.Renewals.Lease != time.Minute ||
		config.Renewals.RetryDelay != 15*time.Minute || config.Renewals.BatchSize != 25 {
		t.Fatalf("renewal runtime config = %+v", config.Renewals)
	}
}

type fakeRenewalSettler struct {
	batches    []int
	err        error
	backlog    tenantcommerce.RenewalBacklog
	inspectErr error
	commands   []tenantcommerce.SettleRenewalsCommand
}

func (settler *fakeRenewalSettler) SettleDueSubscriptions(
	_ context.Context, command tenantcommerce.SettleRenewalsCommand,
) ([]*tenantcommerce.RenewalResult, error) {
	settler.commands = append(settler.commands, command)
	if len(settler.batches) == 0 {
		return nil, settler.err
	}
	size := settler.batches[0]
	settler.batches = settler.batches[1:]
	return make([]*tenantcommerce.RenewalResult, size), settler.err
}

func (settler *fakeRenewalSettler) InspectRenewalBacklog(
	_ context.Context, _ time.Time,
) (tenantcommerce.RenewalBacklog, error) {
	return settler.backlog, settler.inspectErr
}

func TestRenewalRunnerExhaustsFullBatches(t *testing.T) {
	settler := &fakeRenewalSettler{batches: []int{2, 2, 1}}
	config := renewalConfig{
		Enabled: true, Owner: "worker-a", Interval: time.Minute,
		Lease: 2 * time.Minute, RetryDelay: time.Hour, BatchSize: 2,
	}
	metrics := newBillingMetrics(config, time.Now)
	runner := newRenewalRunner(config, settler, metrics.renewal)
	settled, err := runner.settleAvailable(context.Background())
	if err != nil || settled != 5 || len(settler.commands) != 3 {
		t.Fatalf("settled=%d commands=%d err=%v", settled, len(settler.commands), err)
	}
	for _, command := range settler.commands {
		if command.Owner != config.Owner || command.Lease != config.Lease ||
			command.RetryDelay != config.RetryDelay || command.Limit != config.BatchSize {
			t.Fatalf("renewal command = %+v", command)
		}
	}
}

func TestRenewalRunnerReturnsPartialProgressAndError(t *testing.T) {
	wanted := errors.New("settlement unavailable")
	settler := &fakeRenewalSettler{batches: []int{1}, err: wanted}
	config := renewalConfig{
		Enabled: true, Owner: "worker-a", Interval: time.Minute,
		Lease: 2 * time.Minute, RetryDelay: time.Hour, BatchSize: 2,
	}
	metrics := newBillingMetrics(config, time.Now)
	runner := newRenewalRunner(config, settler, metrics.renewal)
	settled, err := runner.settleAvailable(context.Background())
	if settled != 1 || !errors.Is(err, wanted) {
		t.Fatalf("settled=%d err=%v", settled, err)
	}
}

func TestApplicationBackgroundStopsRenewalRunner(t *testing.T) {
	settler := &fakeRenewalSettler{}
	config := renewalConfig{
		Enabled: true, Owner: "worker-a", Interval: time.Hour,
		Lease: 2 * time.Minute, RetryDelay: time.Hour, BatchSize: 2,
	}
	metrics := newBillingMetrics(config, time.Now)
	app := &application{renewal: newRenewalRunner(config, settler, metrics.renewal)}
	ctx, cancel := context.WithCancel(context.Background())
	wait := app.startBackground(ctx, io.Discard)
	cancel()
	done := make(chan struct{})
	go func() {
		wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("renewal worker did not stop after cancellation")
	}
}

func TestRenewalMetricsExposeBoundedCycleAndBacklogState(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	config := renewalConfig{Enabled: true, Owner: "worker-a", Interval: time.Minute,
		Lease: 2 * time.Minute, RetryDelay: time.Hour, BatchSize: 2}
	metrics := newBillingMetrics(config, clock)
	settler := &fakeRenewalSettler{
		batches: []int{1},
		backlog: tenantcommerce.RenewalBacklog{DueCount: 2, OldestDueAt: now.Add(-5 * time.Minute)},
	}
	runner := newRenewalRunner(config, settler, metrics.renewal)
	runner.runAndReport(context.Background(), log.New(io.Discard, "", 0))

	response := httptest.NewRecorder()
	metrics.handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, pathMetrics, nil))
	body := response.Body.String()
	for _, sample := range []string{
		metricRenewalDue + " 2", metricRenewalOldestAge + " 300",
		metricRenewalSuccessTotal + " 1", metricRenewalSettledTotal + " 1",
		metricRenewalLastError + " 0", metricRenewalDegraded + " 0",
	} {
		if !strings.Contains(body, sample) {
			t.Fatalf("metrics missing %q:\n%s", sample, body)
		}
	}
}

func TestRenewalReadinessIgnoresTransientCycleErrorThenVetoesStall(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	config := renewalConfig{Enabled: true, Owner: "worker-a", Interval: time.Minute,
		Lease: 2 * time.Minute, RetryDelay: time.Hour, BatchSize: 2}
	metrics := newBillingMetrics(config, clock)
	settler := &fakeRenewalSettler{}
	runner := newRenewalRunner(config, settler, metrics.renewal)
	runner.runAndReport(context.Background(), log.New(io.Discard, "", 0))

	now = now.Add(time.Minute)
	settler.err = errors.New("database unavailable")
	runner.runAndReport(context.Background(), log.New(io.Discard, "", 0))
	if err := runner.Ready(context.Background()); err != nil {
		t.Fatalf("transient renewal error vetoed readiness: %v", err)
	}
	if !metrics.renewal.lastCycleError.Load() {
		t.Fatal("transient renewal error was not recorded")
	}
	now = now.Add(renewalMaxToleratedLag)
	if err := runner.Ready(context.Background()); !errors.Is(err, errRenewalLagExceeded) {
		t.Fatalf("stalled renewal readiness error = %v", err)
	}
}

func TestRenewalReadinessVetoesOnlyBacklogOlderThanTolerance(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	metrics := newBillingMetrics(renewalConfig{Enabled: true}, func() time.Time { return now })
	backlog := &tenantcommerce.RenewalBacklog{DueCount: 1, OldestDueAt: now.Add(-renewalMaxToleratedLag)}
	metrics.renewal.observeCycle(now, 0, backlog, nil)
	if err := metrics.renewal.Ready(context.Background()); err != nil {
		t.Fatalf("boundary backlog vetoed readiness: %v", err)
	}
	now = now.Add(time.Second)
	if err := metrics.renewal.Ready(context.Background()); !errors.Is(err, errRenewalLagExceeded) {
		t.Fatalf("old backlog readiness error = %v", err)
	}
}
