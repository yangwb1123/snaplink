package metrics

import (
	"testing"
	"time"
)

func TestAuthHookExecutionMetric(t *testing.T) {
	metrics := New()
	metrics.ObserveAuthHookExecution("pre_authenticate", "test", "success", 25*time.Millisecond)
	families, err := metrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == NameAuthHookExecutionDuration {
			if len(family.Metric) != 1 || family.Metric[0].Histogram.GetSampleCount() != 1 {
				t.Fatalf("metric family=%#v", family)
			}
			return
		}
	}
	t.Fatalf("metric %s not registered", NameAuthHookExecutionDuration)
}

func TestNotificationDeliveryMetricCountsOnlyFailures(t *testing.T) {
	metrics := New()
	metrics.ObserveNotificationDelivery("email", "success")
	metrics.ObserveNotificationDelivery("email", "failed")
	metrics.ObserveNotificationDelivery("queue", "dropped")
	families, err := metrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != NameNotificationDeliveryFailed {
			continue
		}
		if len(family.Metric) != 2 {
			t.Fatalf("metric family=%#v", family)
		}
		return
	}
	t.Fatalf("metric %s not registered", NameNotificationDeliveryFailed)
}
