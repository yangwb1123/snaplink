package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	tenantcommerce "github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

const (
	maxRenewalBatchSize       = 500
	renewalMaxToleratedLag    = 15 * time.Minute
	metricRenewalEnabled      = "snaplink_billing_renewal_enabled"
	metricRenewalDue          = "snaplink_billing_renewal_due_subscriptions"
	metricRenewalOldestAge    = "snaplink_billing_renewal_backlog_oldest_age_seconds"
	metricRenewalObservedAt   = "snaplink_billing_renewal_backlog_observed_timestamp_seconds"
	metricRenewalSucceededAt  = "snaplink_billing_renewal_last_successful_cycle_timestamp_seconds"
	metricRenewalLastError    = "snaplink_billing_renewal_last_cycle_error"
	metricRenewalDegraded     = "snaplink_billing_renewal_readiness_degraded"
	metricRenewalSuccessTotal = "snaplink_billing_renewal_cycle_successes_total"
	metricRenewalErrorTotal   = "snaplink_billing_renewal_cycle_errors_total"
	metricRenewalSettledTotal = "snaplink_billing_renewal_settled_subscriptions_total"
)

var errRenewalLagExceeded = errors.New("subscription renewal lag exceeded")

type renewalConfig struct {
	Enabled    bool
	Owner      string
	Interval   time.Duration
	Lease      time.Duration
	RetryDelay time.Duration
	BatchSize  int
}

func renewalDefaults(getenv func(string) string) (renewalConfig, error) {
	enabled, err := envBool(getenv, "SNAPLINK_BILLING_RENEWALS_ENABLED", false)
	if err != nil {
		return renewalConfig{}, err
	}
	interval, err := envDuration(getenv, "SNAPLINK_BILLING_RENEWALS_INTERVAL", time.Minute)
	if err != nil {
		return renewalConfig{}, err
	}
	lease, err := envDuration(getenv, "SNAPLINK_BILLING_RENEWALS_LEASE", 2*time.Minute)
	if err != nil {
		return renewalConfig{}, err
	}
	retryDelay, err := envDuration(getenv, "SNAPLINK_BILLING_RENEWALS_RETRY_DELAY", time.Hour)
	if err != nil {
		return renewalConfig{}, err
	}
	batchSize, err := envInt(getenv, "SNAPLINK_BILLING_RENEWALS_BATCH_SIZE", 50)
	if err != nil {
		return renewalConfig{}, err
	}
	return renewalConfig{
		Enabled: enabled, Owner: getenv("SNAPLINK_BILLING_RENEWALS_OWNER"),
		Interval: interval, Lease: lease, RetryDelay: retryDelay, BatchSize: batchSize,
	}, nil
}

func addRenewalFlags(flags *flag.FlagSet, config *renewalConfig) {
	flags.BoolVar(&config.Enabled, "renewals-enabled", config.Enabled, "enable automatic subscription renewal settlement")
	flags.StringVar(&config.Owner, "renewals-owner", config.Owner, "unique subscription renewal lease owner")
	flags.DurationVar(&config.Interval, "renewals-interval", config.Interval, "subscription renewal scan interval")
	flags.DurationVar(&config.Lease, "renewals-lease", config.Lease, "subscription renewal claim lease")
	flags.DurationVar(&config.RetryDelay, "renewals-retry-delay", config.RetryDelay, "insufficient balance retry delay")
	flags.IntVar(&config.BatchSize, "renewals-batch-size", config.BatchSize, "maximum subscriptions claimed per batch")
}

func (config *renewalConfig) finalize() {
	config.Owner = strings.TrimSpace(config.Owner)
	if config.Enabled && config.Owner == "" {
		config.Owner = defaultRelayOwner() + "-renewal"
	}
}

func (config renewalConfig) validate() error {
	if config.Interval <= 0 || config.Lease <= 0 || config.RetryDelay <= 0 {
		return errors.New("renewal intervals and lease must be positive")
	}
	if config.BatchSize <= 0 || config.BatchSize > maxRenewalBatchSize {
		return errors.New("renewal batch size must be between 1 and 500")
	}
	if config.Enabled && config.Interval >= renewalMaxToleratedLag {
		return errors.New("enabled renewal interval must be less than the readiness lag tolerance")
	}
	if config.Enabled && (config.Owner == "" || strings.ContainsAny(config.Owner, "\r\n")) {
		return errors.New("enabled renewal worker requires a valid owner")
	}
	return nil
}

type renewalSettler interface {
	SettleDueSubscriptions(
		context.Context, tenantcommerce.SettleRenewalsCommand,
	) ([]*tenantcommerce.RenewalResult, error)
	InspectRenewalBacklog(context.Context, time.Time) (tenantcommerce.RenewalBacklog, error)
}

type renewalRunner struct {
	config  renewalConfig
	settler renewalSettler
	metrics *renewalMetrics
}

func newRenewalRunner(
	config renewalConfig, settler renewalSettler, metrics *renewalMetrics,
) *renewalRunner {
	if !config.Enabled {
		return nil
	}
	return &renewalRunner{config: config, settler: settler, metrics: metrics}
}

func (runner *renewalRunner) run(ctx context.Context, logger *log.Logger) {
	runner.runAndReport(ctx, logger)
	ticker := time.NewTicker(runner.config.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runner.runAndReport(ctx, logger)
		}
	}
}

func (runner *renewalRunner) runAndReport(ctx context.Context, logger *log.Logger) {
	settled, settleErr := runner.settleAvailable(ctx)
	at := runner.metrics.now()
	backlog, inspectErr := runner.settler.InspectRenewalBacklog(ctx, at)
	cycleErr := errors.Join(settleErr, inspectErr)
	if errors.Is(cycleErr, context.Canceled) {
		runner.metrics.addSettled(settled)
		return
	}
	var observed *tenantcommerce.RenewalBacklog
	if inspectErr == nil {
		observed = &backlog
	}
	runner.metrics.observeCycle(at, settled, observed, cycleErr)
	if cycleErr != nil {
		logger.Printf("subscription renewal settlement failed after %d results: %v", settled, cycleErr)
		return
	}
	if settled > 0 {
		logger.Printf("subscription renewal settlement completed: %d results", settled)
	}
}

func (runner *renewalRunner) Ready(ctx context.Context) error {
	return runner.metrics.Ready(ctx)
}

func (runner *renewalRunner) settleAvailable(ctx context.Context) (int, error) {
	total := 0
	for ctx.Err() == nil {
		results, err := runner.settler.SettleDueSubscriptions(ctx, tenantcommerce.SettleRenewalsCommand{
			Owner: runner.config.Owner, Lease: runner.config.Lease,
			RetryDelay: runner.config.RetryDelay, Limit: runner.config.BatchSize,
		})
		total += len(results)
		if err != nil || len(results) < runner.config.BatchSize {
			return total, err
		}
	}
	return total, ctx.Err()
}

type billingMetrics struct {
	registry *prometheus.Registry
	renewal  *renewalMetrics
}

func newBillingMetrics(config renewalConfig, now func() time.Time) *billingMetrics {
	if now == nil {
		now = time.Now
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	renewal := newRenewalMetrics(registry, config.Enabled, now)
	return &billingMetrics{registry: registry, renewal: renewal}
}

func (metrics *billingMetrics) handler() http.Handler {
	return promhttp.HandlerFor(metrics.registry, promhttp.HandlerOpts{EnableOpenMetrics: true})
}

type renewalMetrics struct {
	enabled        bool
	startedAt      time.Time
	now            func() time.Time
	dueCount       atomic.Int64
	oldestDue      atomic.Int64
	observedAt     atomic.Int64
	lastSuccessful atomic.Int64
	lastCycleError atomic.Bool
	cycleSuccesses prometheus.Counter
	cycleErrors    prometheus.Counter
	settledTotal   prometheus.Counter
}

func newRenewalMetrics(
	registry *prometheus.Registry, enabled bool, now func() time.Time,
) *renewalMetrics {
	metrics := &renewalMetrics{
		enabled: enabled, startedAt: now(), now: now,
		cycleSuccesses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: metricRenewalSuccessTotal, Help: "Successful automatic subscription renewal cycles."}),
		cycleErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: metricRenewalErrorTotal, Help: "Automatic subscription renewal cycles ending in an operational error."}),
		settledTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: metricRenewalSettledTotal, Help: "Subscriptions settled by the automatic renewal worker."}),
	}
	registry.MustRegister(metrics.cycleSuccesses, metrics.cycleErrors, metrics.settledTotal)
	metrics.registerGauges(registry)
	return metrics
}

func (metrics *renewalMetrics) registerGauges(registry *prometheus.Registry) {
	registerRenewalGauge(registry, metricRenewalEnabled,
		"Whether automatic subscription renewal is enabled on this process.", metrics.enabledValue)
	registerRenewalGauge(registry, metricRenewalDue,
		"Durable subscriptions currently eligible for automatic settlement.", metrics.dueValue)
	registerRenewalGauge(registry, metricRenewalOldestAge,
		"Age in seconds of the oldest subscription currently eligible for settlement.", metrics.oldestAge)
	registerRenewalGauge(registry, metricRenewalObservedAt,
		"Unix timestamp of the last successful durable backlog observation.", metrics.observedValue)
	registerRenewalGauge(registry, metricRenewalSucceededAt,
		"Unix timestamp of the last fully successful renewal cycle.", metrics.successValue)
	registerRenewalGauge(registry, metricRenewalLastError,
		"Whether the most recent completed renewal cycle had an operational error.", metrics.errorValue)
	registerRenewalGauge(registry, metricRenewalDegraded,
		"Whether renewal lag exceeds the readiness tolerance on this process.", metrics.degradedValue)
}

func registerRenewalGauge(
	registry *prometheus.Registry, name, help string, value func() float64,
) {
	registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: name, Help: help}, value))
}

func (metrics *renewalMetrics) observeCycle(
	at time.Time, settled int, backlog *tenantcommerce.RenewalBacklog, cycleErr error,
) {
	metrics.addSettled(settled)
	if backlog != nil {
		metrics.dueCount.Store(backlog.DueCount)
		metrics.oldestDue.Store(timeValue(backlog.OldestDueAt))
		metrics.observedAt.Store(at.UnixNano())
	}
	metrics.lastCycleError.Store(cycleErr != nil)
	if cycleErr != nil {
		metrics.cycleErrors.Inc()
		return
	}
	metrics.cycleSuccesses.Inc()
	metrics.lastSuccessful.Store(at.UnixNano())
}

func (metrics *renewalMetrics) addSettled(settled int) {
	if settled > 0 {
		metrics.settledTotal.Add(float64(settled))
	}
}

func (metrics *renewalMetrics) Ready(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !metrics.enabled {
		return nil
	}
	now := metrics.now()
	if timestampTooOld(now, metrics.oldestDue.Load(), renewalMaxToleratedLag) {
		return errRenewalLagExceeded
	}
	lastSuccess := metrics.lastSuccessful.Load()
	if lastSuccess == 0 && now.After(metrics.startedAt.Add(renewalMaxToleratedLag)) {
		return errRenewalLagExceeded
	}
	if timestampTooOld(now, lastSuccess, renewalMaxToleratedLag) {
		return errRenewalLagExceeded
	}
	return nil
}

func timestampTooOld(now time.Time, timestamp int64, maximum time.Duration) bool {
	return timestamp != 0 && now.After(time.Unix(0, timestamp).Add(maximum))
}

func timeValue(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixNano()
}

func (metrics *renewalMetrics) enabledValue() float64 {
	if metrics.enabled {
		return 1
	}
	return 0
}

func (metrics *renewalMetrics) dueValue() float64 {
	return float64(metrics.dueCount.Load())
}

func (metrics *renewalMetrics) oldestAge() float64 {
	timestamp := metrics.oldestDue.Load()
	if timestamp == 0 {
		return 0
	}
	age := metrics.now().Sub(time.Unix(0, timestamp)).Seconds()
	if age < 0 {
		return 0
	}
	return age
}

func (metrics *renewalMetrics) observedValue() float64 {
	return float64(metrics.observedAt.Load()) / float64(time.Second)
}

func (metrics *renewalMetrics) successValue() float64 {
	return float64(metrics.lastSuccessful.Load()) / float64(time.Second)
}

func (metrics *renewalMetrics) errorValue() float64 {
	if metrics.lastCycleError.Load() {
		return 1
	}
	return 0
}

func (metrics *renewalMetrics) degradedValue() float64 {
	if metrics.Ready(context.Background()) != nil {
		return 1
	}
	return 0
}
