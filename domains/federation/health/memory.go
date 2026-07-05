package health

import (
	"sort"
	"sync"
	"time"
)

// MemoryConnectionHealth is the in-process ConnectionHealth implementation —
// the SDK default (AGENTS.md: every SPI ships a real Memory* impl, no mocks).
// Safe for concurrent use; state does not survive a restart, mirroring every
// other Memory* store in the SDK (durability is an operator choice via a
// custom ConnectionHealth, not this package's concern).
type MemoryConnectionHealth struct {
	mu    sync.Mutex
	peers map[string]PeerHealth
}

var _ ConnectionHealth = (*MemoryConnectionHealth)(nil)

// NewMemoryConnectionHealth returns an empty, ready-to-use store.
func NewMemoryConnectionHealth() *MemoryConnectionHealth {
	return &MemoryConnectionHealth{peers: make(map[string]PeerHealth)}
}

// RecordSuccess implements ConnectionHealth.
func (m *MemoryConnectionHealth) RecordSuccess(peerID string, checkedAt time.Time, certNotAfter time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.peers[peerID]
	p.PeerID = peerID
	p.LastSuccessAt = checkedAt
	p.LastError = ""
	p.ConsecutiveFailures = 0
	// A zero certNotAfter means THIS call observed no fresh TLS handshake
	// (e.g. a reused keep-alive connection) — keep whatever expiry a past
	// success last saw rather than blanking it.
	if !certNotAfter.IsZero() {
		p.CertNotAfter = certNotAfter
		p.CertObservedAt = checkedAt
	}
	m.peers[peerID] = p
}

// RecordFailure implements ConnectionHealth.
func (m *MemoryConnectionHealth) RecordFailure(peerID string, checkedAt time.Time, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.peers[peerID]
	p.PeerID = peerID
	p.LastFailureAt = checkedAt
	p.LastError = errMsg
	p.ConsecutiveFailures++
	m.peers[peerID] = p
}

// List implements ConnectionHealth.
func (m *MemoryConnectionHealth) List() []PeerHealth {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PeerHealth, 0, len(m.peers))
	for _, p := range m.peers {
		out = append(out, p)
	}
	sortByPeerID(out)
	return out
}

// ExpiringWithin implements ConnectionHealth.
func (m *MemoryConnectionHealth) ExpiringWithin(now time.Time, d time.Duration) []PeerHealth {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []PeerHealth
	for _, p := range m.peers {
		if p.ExpiresWithin(now, d) {
			out = append(out, p)
		}
	}
	sortByPeerID(out)
	return out
}

// sortByPeerID gives List/ExpiringWithin a stable, deterministic order (the
// map iteration above is not) so repeated admin listings don't jitter.
func sortByPeerID(peers []PeerHealth) {
	sort.Slice(peers, func(i, j int) bool { return peers[i].PeerID < peers[j].PeerID })
}
