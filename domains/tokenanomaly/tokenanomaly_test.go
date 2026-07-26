package tokenanomaly

import (
	"testing"
	"time"
)

func TestSeverityConstants(t *testing.T) {
	if SeverityWarn != "warn" {
		t.Errorf("expected 'warn', got %q", SeverityWarn)
	}
	if SeverityCritical != "critical" {
		t.Errorf("expected 'critical', got %q", SeverityCritical)
	}
}

func TestFindingTypeConstants(t *testing.T) {
	if FindingMultiGeo != "multi_geo" {
		t.Errorf("expected 'multi_geo', got %q", FindingMultiGeo)
	}
	if FindingVelocity != "velocity" {
		t.Errorf("expected 'velocity', got %q", FindingVelocity)
	}
	if FindingRateSpike != "rate_spike" {
		t.Errorf("expected 'rate_spike', got %q", FindingRateSpike)
	}
}

func TestFindingDedupKey(t *testing.T) {
	// DedupKey uses Type + Thumbprint (fallback to ClientID)
	f1 := Finding{Type: FindingMultiGeo, Thumbprint: "tp-1", ClientID: "c1"}
	f2 := Finding{Type: FindingMultiGeo, Thumbprint: "tp-1", ClientID: "c2"}

	if f1.DedupKey() != f2.DedupKey() {
		t.Error("same thumbprint should have same DedupKey regardless of ClientID")
	}

	f3 := Finding{Type: FindingMultiGeo, Thumbprint: "tp-2"}
	if f1.DedupKey() == f3.DedupKey() {
		t.Error("different thumbprints should have different DedupKey")
	}

	f4 := Finding{Type: FindingMultiGeo, ClientID: "c1"}
	f5 := Finding{Type: FindingMultiGeo, ClientID: "c1"}
	if f4.DedupKey() != f5.DedupKey() {
		t.Error("same ClientID should have same DedupKey when Thumbprint empty")
	}

	f6 := Finding{Type: "test"}
	if f6.DedupKey() == "" {
		t.Error("expected non-empty DedupKey even with empty fields")
	}
}

func TestFindingFields(t *testing.T) {
	now := time.Now()
	then := now.Add(-1 * time.Hour)
	f := Finding{
		Type:      FindingVelocity,
		Severity:  SeverityCritical,
		SubjectID: "user-1",
		ClientID:  "client-1",
		Detail:    "Token used from NYC and Tokyo within 5 minutes",
		FirstSeen: then,
		LastSeen:  now,
		Count:     42,
	}

	if f.Type != FindingVelocity {
		t.Errorf("expected 'velocity', got %q", f.Type)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("expected SeverityCritical, got %s", f.Severity)
	}
	if f.Detail != "Token used from NYC and Tokyo within 5 minutes" {
		t.Errorf("unexpected Detail: %q", f.Detail)
	}
	if !f.FirstSeen.Equal(then) {
		t.Errorf("expected FirstSeen %v, got %v", then, f.FirstSeen)
	}
	if f.Count != 42 {
		t.Errorf("expected Count 42, got %d", f.Count)
	}
}

func TestFindingQueryDefaults(t *testing.T) {
	q := FindingQuery{}
	if q.Limit != 0 {
		t.Errorf("expected zero Limit, got %d", q.Limit)
	}
	if q.Type != "" {
		t.Errorf("expected empty Type, got %q", q.Type)
	}
}
