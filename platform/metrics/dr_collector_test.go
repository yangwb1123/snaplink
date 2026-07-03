package metrics_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/snaplink/sso/platform/lifecycle/dr"
	"github.com/snaplink/sso/platform/metrics"
)

func TestDRCollector_NilReadinessIsHarmless(t *testing.T) {
	t.Parallel()
	reg := prometheus.NewRegistry()
	reg.MustRegister(metrics.NewDRCollector(nil))
	_ = scrapeRegistry(t, reg)
}

func TestDRCollector_NoReplicationYet_LagAndRecoveryAbsent(t *testing.T) {
	t.Parallel()
	replicator, err := dr.NewSnapshotReplicator(
		func(context.Context) (string, []byte, error) { return "snap_x", nil, nil },
		t.TempDir(), 0, 0, nil)
	if err != nil {
		t.Fatalf("NewSnapshotReplicator: %v", err)
	}
	readiness := dr.NewDRReadiness(replicator, nil, time.Hour, 0)

	reg := prometheus.NewRegistry()
	reg.MustRegister(metrics.NewDRCollector(readiness))
	scrape := scrapeRegistry(t, reg)

	if !strings.Contains(scrape, dr.MetricReadiness+" 0") {
		t.Errorf("expected %s 0 (not ready pre-replication), got:\n%s", dr.MetricReadiness, scrape)
	}
	if strings.Contains(scrape, dr.MetricReplicationLagSeconds) {
		t.Errorf("%s should be absent before the first successful replication:\n%s", dr.MetricReplicationLagSeconds, scrape)
	}
	if strings.Contains(scrape, dr.MetricLastRecoverySeconds) {
		t.Errorf("%s should be absent with no tracker/history:\n%s", dr.MetricLastRecoverySeconds, scrape)
	}
}

func TestDRCollector_AfterReplicationAndRecovery_AllThreeReported(t *testing.T) {
	t.Parallel()
	replicator, err := dr.NewSnapshotReplicator(
		func(context.Context) (string, []byte, error) { return "snap_x", []byte("payload"), nil },
		t.TempDir(), 0, 0, nil)
	if err != nil {
		t.Fatalf("NewSnapshotReplicator: %v", err)
	}
	if err := replicator.ReplicateOnce(context.Background()); err != nil {
		t.Fatalf("ReplicateOnce: %v", err)
	}
	tracker := dr.NewRecoveryTimeTracker(0)
	timer := tracker.Start("drill")
	timer.Stop(nil)
	readiness := dr.NewDRReadiness(replicator, tracker, time.Hour, 0)

	reg := prometheus.NewRegistry()
	reg.MustRegister(metrics.NewDRCollector(readiness))
	scrape := scrapeRegistry(t, reg)

	for _, name := range []string{dr.MetricReadiness, dr.MetricReplicationLagSeconds, dr.MetricLastRecoverySeconds} {
		if !strings.Contains(scrape, name) {
			t.Errorf("metric %q missing from scrape:\n%s", name, scrape)
		}
	}
	if !strings.Contains(scrape, dr.MetricReadiness+" 1") {
		t.Errorf("expected %s 1 (ready, fresh replica), got:\n%s", dr.MetricReadiness, scrape)
	}
}
