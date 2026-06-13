package netpolicy_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/netpolicy/memory"
)

func mustApply(t *testing.T, s netpolicy.Store, p *netpolicy.Policy) {
	t.Helper()
	if _, err := s.Apply(context.Background(), p); err != nil {
		t.Fatalf("Apply %s: %v", p.Name, err)
	}
}

func twoPolicyStore(t *testing.T) netpolicy.Store {
	t.Helper()
	s := memory.New()
	mustApply(t, s, &netpolicy.Policy{
		Name:      "intranet",
		CIDRs:     []string{"10.0.0.0/8", "192.168.0.0/16"},
		Hostnames: []string{"sso.intranet.local"},
		Priority:  100,
	})
	mustApply(t, s, &netpolicy.Policy{
		Name:      "public",
		Hostnames: []string{"sso.example.com"},
		Priority:  50,
	})
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func newClassifier(t *testing.T, s netpolicy.Store) *netpolicy.Classifier {
	t.Helper()
	c := netpolicy.NewClassifier()
	if err := c.Reload(context.Background(), s); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	return c
}

func TestClassifier_HostnameBeatsCIDR(t *testing.T) {
	s := twoPolicyStore(t)
	c := newClassifier(t, s)
	// 10.0.0.1 matches "intranet" CIDR, but the Host header says public.
	got := c.Classify("10.0.0.1:5555", "sso.example.com")
	if got == nil || got.Name != "public" {
		t.Fatalf("expected public, got %+v", got)
	}
}

func TestClassifier_CIDRMatch(t *testing.T) {
	s := twoPolicyStore(t)
	c := newClassifier(t, s)
	got := c.Classify("10.5.5.5:1234", "")
	if got == nil || got.Name != "intranet" {
		t.Fatalf("expected intranet, got %+v", got)
	}
}

func TestClassifier_HostMatchWithPort(t *testing.T) {
	s := twoPolicyStore(t)
	c := newClassifier(t, s)
	got := c.Classify("203.0.113.1:8080", "SSO.EXAMPLE.COM:8080")
	if got == nil || got.Name != "public" {
		t.Fatalf("expected public, got %+v", got)
	}
}

func TestClassifier_NoMatchReturnsNil(t *testing.T) {
	s := twoPolicyStore(t)
	c := newClassifier(t, s)
	got := c.Classify("203.0.113.1", "unrelated.host")
	if got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestClassifier_PriorityBreaksHostnameTie(t *testing.T) {
	s := memory.New()
	defer func() { _ = s.Close() }()
	mustApply(t, s, &netpolicy.Policy{Name: "lo", Hostnames: []string{"x.example"}, Priority: 1})
	mustApply(t, s, &netpolicy.Policy{Name: "hi", Hostnames: []string{"x.example"}, Priority: 99})
	c := newClassifier(t, s)
	got := c.Classify("", "x.example")
	if got == nil || got.Name != "hi" {
		t.Fatalf("expected hi, got %+v", got)
	}
}

func TestClassifier_BareIPCIDR(t *testing.T) {
	s := memory.New()
	defer func() { _ = s.Close() }()
	mustApply(t, s, &netpolicy.Policy{Name: "single", CIDRs: []string{"203.0.113.42"}})
	c := newClassifier(t, s)
	if got := c.Classify("203.0.113.42", ""); got == nil || got.Name != "single" {
		t.Fatalf("expected single, got %+v", got)
	}
	if got := c.Classify("203.0.113.43", ""); got != nil {
		t.Fatalf("expected nil for non-match, got %+v", got)
	}
}

func TestClassifier_StartAppliesWatchUpdates(t *testing.T) {
	s := memory.New()
	defer func() { _ = s.Close() }()
	c := netpolicy.NewClassifier()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone, err := c.Start(ctx, s)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	mustApply(t, s, &netpolicy.Policy{Name: "intranet", CIDRs: []string{"10.0.0.0/8"}})

	// Wait briefly for the watch event to propagate.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if c.Classify("10.1.2.3", "") != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	got := c.Classify("10.1.2.3", "")
	if got == nil || got.Name != "intranet" {
		t.Fatalf("expected intranet after Run+Apply, got %+v", got)
	}

	_ = s.Delete(context.Background(), "intranet")
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if c.Classify("10.1.2.3", "") == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := c.Classify("10.1.2.3", ""); got != nil {
		t.Fatalf("expected nil after Delete, got %+v", got)
	}

	cancel()
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("Start goroutine didn't shut down")
	}
}

func TestClassifier_Snapshot(t *testing.T) {
	s := twoPolicyStore(t)
	c := newClassifier(t, s)
	all := c.Snapshot()
	if len(all) != 2 {
		t.Fatalf("Snapshot len=%d, want 2", len(all))
	}
	// Snapshot is priority-sorted desc.
	if all[0].Name != "intranet" {
		t.Errorf("first by priority should be intranet, got %s", all[0].Name)
	}
}

func TestPolicy_CloneIsDeep(t *testing.T) {
	p := &netpolicy.Policy{
		Name:      "x",
		CIDRs:     []string{"10.0.0.0/8"},
		Hostnames: []string{"h"},
		Metadata:  map[string]string{"k": "v"},
	}
	cp := p.Clone()
	cp.CIDRs[0] = "tampered"
	cp.Metadata["k"] = "tampered"
	if p.CIDRs[0] == "tampered" || p.Metadata["k"] == "tampered" {
		t.Fatal("Clone is not deep")
	}
}
