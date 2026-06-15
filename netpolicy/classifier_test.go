package netpolicy

import (
	"testing"
)

func TestNewClassifier(t *testing.T) {
	t.Parallel()

	c := NewClassifier()
	if c == nil {
		t.Fatal("NewClassifier() returned nil")
	}
}

func TestClassifyEmpty(t *testing.T) {
	t.Parallel()

	c := NewClassifier()
	policy := c.Classify("10.0.0.1", "example.com")
	if policy != nil {
		t.Errorf("Classify() on empty classifier = %v, want nil", policy)
	}
}

func TestClassifyByCIDR(t *testing.T) {
	t.Parallel()

	c := NewClassifier()
	c.upsertLocked(&Policy{
		Name:  "internal",
		CIDRs: []string{"10.0.0.0/8"},
	})

	policy := c.Classify("10.0.0.1", "example.com")
	if policy == nil {
		t.Fatal("Classify() on matching CIDR returned nil")
	}
	if policy.Name != "internal" {
		t.Errorf("Classify().Name = %q, want internal", policy.Name)
	}

	// Non-matching
	policy = c.Classify("192.168.1.1", "example.com")
	if policy != nil {
		t.Errorf("Classify() on non-matching got %v, want nil", policy)
	}
}

func TestClassifyByHostname(t *testing.T) {
	t.Parallel()

	c := NewClassifier()
	c.upsertLocked(&Policy{
		Name:      "api-policy",
		Hostnames: []string{"api.example.com"},
	})

	// Matching hostname
	policy := c.Classify("10.0.0.1", "api.example.com")
	if policy == nil {
		t.Fatal("Classify() on matching hostname returned nil")
	}
	if policy.Name != "api-policy" {
		t.Errorf("Classify().Name = %q, want api-policy", policy.Name)
	}

	// Non-matching hostname
	policy = c.Classify("10.0.0.1", "other.example.com")
	if policy != nil {
		t.Errorf("Classify() on non-matching hostname got %v, want nil", policy)
	}
}

func TestClassifyHostnameBeatsCIDR(t *testing.T) {
	t.Parallel()

	c := NewClassifier()
	c.upsertLocked(&Policy{
		Name:      "hostname-policy",
		Hostnames: []string{"app.example.com"},
		CIDRs:     []string{"10.0.0.0/8"},
	})
	c.upsertLocked(&Policy{
		Name:  "cidr-policy",
		CIDRs: []string{"10.0.0.0/8"},
	})

	// Hostname match should be returned (Pass 1), not the CIDR match (Pass 2)
	policy := c.Classify("10.0.0.1", "app.example.com")
	if policy == nil {
		t.Fatal("Classify() returned nil")
	}
	if policy.Name != "hostname-policy" {
		t.Errorf("Classify().Name = %q, want hostname-policy (hostname should beat CIDR)", policy.Name)
	}
}

func TestSnapshot(t *testing.T) {
	t.Parallel()

	c := NewClassifier()
	c.upsertLocked(&Policy{Name: "policy-a", CIDRs: []string{"10.0.0.0/8"}})

	sn := c.Snapshot()
	if len(sn) != 1 {
		t.Fatalf("Snapshot() len = %d, want 1", len(sn))
	}
	if sn[0].Name != "policy-a" {
		t.Errorf("Snapshot()[0].Name = %q, want policy-a", sn[0].Name)
	}
}

func TestRemoveLocked(t *testing.T) {
	t.Parallel()

	c := NewClassifier()
	c.upsertLocked(&Policy{Name: "p1", CIDRs: []string{"10.0.0.0/8"}})
	c.upsertLocked(&Policy{Name: "p2", CIDRs: []string{"192.168.0.0/16"}})

	c.removeLocked("p1")
	sn := c.Snapshot()
	if len(sn) != 1 {
		t.Fatalf("after remove, len = %d, want 1", len(sn))
	}
	if sn[0].Name != "p2" {
		t.Errorf("remaining = %q, want p2", sn[0].Name)
	}
}
