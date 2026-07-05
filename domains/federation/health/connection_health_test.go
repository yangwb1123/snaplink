package health_test

import (
	"testing"
	"time"

	"github.com/snaplink/sso/domains/federation/health"
)

func TestPeerHealth_ExpiresWithin_UnknownExpiryNeverFlags(t *testing.T) {
	t.Parallel()
	p := health.PeerHealth{PeerID: "https://op.test"}
	now := time.Unix(1_900_000_000, 0)
	if p.ExpiresWithin(now, 365*24*time.Hour) {
		t.Fatal("a peer with no observed cert expiry must never be flagged as expiring")
	}
}

func TestPeerHealth_ExpiresWithin(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_900_000_000, 0)
	cases := []struct {
		name       string
		notAfter   time.Time
		threshold  time.Duration
		wantExpire bool
	}{
		{"far future", now.Add(365 * 24 * time.Hour), 30 * 24 * time.Hour, false},
		{"within threshold", now.Add(10 * 24 * time.Hour), 30 * 24 * time.Hour, true},
		{"already expired", now.Add(-time.Hour), 30 * 24 * time.Hour, true},
		{"exactly at threshold boundary", now.Add(30 * 24 * time.Hour), 30 * 24 * time.Hour, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			p := health.PeerHealth{PeerID: "https://op.test", CertNotAfter: c.notAfter}
			if got := p.ExpiresWithin(now, c.threshold); got != c.wantExpire {
				t.Fatalf("ExpiresWithin() = %v, want %v", got, c.wantExpire)
			}
		})
	}
}
