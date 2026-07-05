package health_test

import (
	"testing"
	"time"

	"github.com/snaplink/sso/domains/federation/health"
)

func TestMemoryConnectionHealth_RecordSuccessThenFailure(t *testing.T) {
	t.Parallel()
	store := health.NewMemoryConnectionHealth()
	t0 := time.Unix(1_900_000_000, 0)
	certExp := t0.Add(60 * 24 * time.Hour)

	store.RecordSuccess("https://op.test", t0, certExp)
	peers := store.List()
	if len(peers) != 1 {
		t.Fatalf("List() len = %d, want 1", len(peers))
	}
	p := peers[0]
	if p.PeerID != "https://op.test" || !p.LastSuccessAt.Equal(t0) || !p.CertNotAfter.Equal(certExp) {
		t.Fatalf("unexpected snapshot after success: %+v", p)
	}
	if p.ConsecutiveFailures != 0 {
		t.Fatalf("ConsecutiveFailures = %d, want 0", p.ConsecutiveFailures)
	}

	t1 := t0.Add(time.Minute)
	store.RecordFailure("https://op.test", t1, "dial: connection refused")
	peers = store.List()
	p = peers[0]
	if p.ConsecutiveFailures != 1 {
		t.Fatalf("ConsecutiveFailures = %d, want 1", p.ConsecutiveFailures)
	}
	if p.LastError != "dial: connection refused" {
		t.Fatalf("LastError = %q", p.LastError)
	}
	// A failure must NOT erase a previously-observed cert expiry — the last
	// good observation is still the freshest signal available.
	if !p.CertNotAfter.Equal(certExp) {
		t.Fatalf("CertNotAfter erased by failure: got %v, want %v", p.CertNotAfter, certExp)
	}

	// Consecutive failures accumulate.
	store.RecordFailure("https://op.test", t1.Add(time.Minute), "timeout")
	if got := store.List()[0].ConsecutiveFailures; got != 2 {
		t.Fatalf("ConsecutiveFailures = %d, want 2", got)
	}

	// A subsequent success resets the failure streak and clears LastError.
	t2 := t1.Add(2 * time.Minute)
	store.RecordSuccess("https://op.test", t2, time.Time{})
	p = store.List()[0]
	if p.ConsecutiveFailures != 0 || p.LastError != "" {
		t.Fatalf("success did not reset failure state: %+v", p)
	}
	// Zero certNotAfter on this call must NOT blank the prior observation.
	if !p.CertNotAfter.Equal(certExp) {
		t.Fatalf("CertNotAfter blanked by a zero-value success: got %v, want %v", p.CertNotAfter, certExp)
	}
}

func TestMemoryConnectionHealth_ListIsSortedAndMultiPeer(t *testing.T) {
	t.Parallel()
	store := health.NewMemoryConnectionHealth()
	now := time.Unix(1_900_000_000, 0)
	store.RecordSuccess("https://zzz.test", now, time.Time{})
	store.RecordFailure("https://aaa.test", now, "boom")
	store.RecordSuccess("https://mmm.test", now, time.Time{})

	peers := store.List()
	if len(peers) != 3 {
		t.Fatalf("List() len = %d, want 3", len(peers))
	}
	want := []string{"https://aaa.test", "https://mmm.test", "https://zzz.test"}
	for i, id := range want {
		if peers[i].PeerID != id {
			t.Fatalf("List()[%d].PeerID = %q, want %q (not sorted)", i, peers[i].PeerID, id)
		}
	}
}

func TestMemoryConnectionHealth_ExpiringWithin(t *testing.T) {
	t.Parallel()
	store := health.NewMemoryConnectionHealth()
	now := time.Unix(1_900_000_000, 0)

	store.RecordSuccess("https://soon.test", now, now.Add(5*24*time.Hour))
	store.RecordSuccess("https://later.test", now, now.Add(400*24*time.Hour))
	store.RecordSuccess("https://unknown.test", now, time.Time{}) // never observed a cert
	store.RecordFailure("https://never-succeeded.test", now, "dial timeout")

	expiring := store.ExpiringWithin(now, 30*24*time.Hour)
	if len(expiring) != 1 || expiring[0].PeerID != "https://soon.test" {
		t.Fatalf("ExpiringWithin() = %+v, want only https://soon.test", expiring)
	}
}

func TestMemoryConnectionHealth_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	store := health.NewMemoryConnectionHealth()
	now := time.Unix(1_900_000_000, 0)
	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			store.RecordSuccess("https://op.test", now, time.Time{})
			store.RecordFailure("https://op.test", now, "x")
			_ = store.List()
			_ = store.ExpiringWithin(now, time.Hour)
		}(i)
	}
	for i := 0; i < 20; i++ {
		<-done
	}
}
