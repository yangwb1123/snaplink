package metering

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestUsagePeriodValid(t *testing.T) {
	if PeriodDay != "day" {
		t.Errorf("expected PeriodDay='day', got %q", PeriodDay)
	}
	if PeriodMonth != "month" {
		t.Errorf("expected PeriodMonth='month', got %q", PeriodMonth)
	}
}

func TestTenantUsageZeroValues(t *testing.T) {
	u := TenantUsage{}
	if u.Logins != 0 {
		t.Errorf("expected zero Logins, got %d", u.Logins)
	}
	if u.TokensIssued != 0 {
		t.Errorf("expected zero TokensIssued, got %d", u.TokensIssued)
	}
	if u.ActiveUsers != 0 {
		t.Errorf("expected zero ActiveUsers, got %d", u.ActiveUsers)
	}
	if u.MFAChallenges != 0 {
		t.Errorf("expected zero MFAChallenges, got %d", u.MFAChallenges)
	}
	if u.ActiveClients != 0 {
		t.Errorf("expected zero ActiveClients, got %d", u.ActiveClients)
	}
}

func TestTenantUsageFields(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	u := TenantUsage{
		TenantID:      "tenant-1",
		Period:        PeriodDay,
		PeriodStart:   now,
		Logins:        100,
		TokensIssued:  250,
		ActiveUsers:   45,
		MFAChallenges: 10,
		ActiveClients: 3,
	}

	if u.TenantID != "tenant-1" {
		t.Errorf("expected tenant-1, got %s", u.TenantID)
	}
	if u.Period != PeriodDay {
		t.Errorf("expected PeriodDay, got %s", u.Period)
	}
	if u.Logins != 100 {
		t.Errorf("expected 100 logins, got %d", u.Logins)
	}
	if u.PeriodStart != now {
		t.Errorf("expected period start %v, got %v", now, u.PeriodStart)
	}
}

func TestTenantUsageJSONUsesStableSnakeCase(t *testing.T) {
	body, err := json.Marshal(TenantUsage{TenantID: "tenant-1", Period: PeriodDay})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	text := string(body)
	for _, key := range []string{
		`"tenant_id"`, `"period_start"`, `"tokens_issued"`,
		`"active_users"`, `"mfa_challenges"`, `"active_clients"`,
	} {
		if !strings.Contains(text, key) {
			t.Errorf("JSON %s does not contain %s", text, key)
		}
	}
	if strings.Contains(text, `"TenantID"`) {
		t.Fatalf("JSON exposes Go field names: %s", text)
	}
}

func TestAggregatorInterfaceCompileCheck(t *testing.T) {
	// Compile-time check that memory aggregator implements Aggregator
	var _ Aggregator = (*memoryAggregator)(nil)
}

// memoryAggregator is a compile-test stub (not a real implementation).
type memoryAggregator struct{}

func (m *memoryAggregator) Usage(ctx context.Context, tenantID string, period UsagePeriod, start time.Time) (*TenantUsage, error) {
	return &TenantUsage{}, nil
}

func (m *memoryAggregator) TopTenants(ctx context.Context, period UsagePeriod, start time.Time, n int) ([]*TenantUsage, error) {
	return nil, nil
}
