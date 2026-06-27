package tokengrant

import (
	"sync"
	"time"
)

// refreshGraceCache makes a benign concurrent double-submit of a refresh token
// idempotent. When a token is rotated, its successor response is cached for a
// short window keyed by the CONSUMED token; a near-simultaneous second
// presentation of the SAME token (a multi-tab SPA, a mobile cold-start race, or
// an HTTP retry after a dropped 200) then replays that SAME successor instead
// of tripping refresh-token-family reuse detection and killing the whole family
// — the "double-submit logout storm" false-positive.
//
// This does NOT weaken BCP §4.13 reuse detection: the grace only ever returns
// the ALREADY-ISSUED successor for the immediately-prior token within the
// window. A genuine post-window replay (or any token never cached here) finds
// no entry and falls through to the family-reuse kill exactly as before. The
// cached response is held at most `window` and the map is pruned lazily on each
// access, so it stays bounded by rotation-rate × window.
type RefreshGraceCache struct {
	window time.Duration
	mu     sync.Mutex
	m      map[string]refreshGraceEntry
}

type refreshGraceEntry struct {
	resp    map[string]any
	expires time.Time
}

func NewRefreshGraceCache(window time.Duration) *RefreshGraceCache {
	return &RefreshGraceCache{window: window, m: make(map[string]refreshGraceEntry)}
}

// remember caches resp as the successor for the just-consumed token. resp is
// cloned so a later caller mutation can't corrupt the cached copy.
func (c *RefreshGraceCache) Remember(token string, resp map[string]any, now time.Time) {
	if c == nil || token == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	cp := make(map[string]any, len(resp))
	for k, v := range resp {
		cp[k] = v
	}
	c.m[token] = refreshGraceEntry{resp: cp, expires: now.Add(c.window)}
}

// lookup returns a COPY of the cached successor response for token if it was
// rotated within the grace window (else nil,false). Expired-at-exactly-now is
// treated as expired.
func (c *RefreshGraceCache) Lookup(token string, now time.Time) (map[string]any, bool) {
	if c == nil || token == "" {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[token]
	if !ok || !now.Before(e.expires) {
		return nil, false
	}
	cp := make(map[string]any, len(e.resp))
	for k, v := range e.resp {
		cp[k] = v
	}
	return cp, true
}

// pruneLocked drops every expired entry. Caller holds c.mu.
func (c *RefreshGraceCache) pruneLocked(now time.Time) {
	for k, e := range c.m {
		if !now.Before(e.expires) {
			delete(c.m, k)
		}
	}
}

// RefreshGraceStore is the pluggable backend for the double-submit grace window.
// *RefreshGraceCache is the in-process (single-replica) impl; a Redis-backed
// impl with the SAME method set makes the decision CLUSTER-SHARED, so a
// double-submit landing on a different replica than the rotation still replays
// the successor instead of tripping a false family-reuse kill (the logout storm
// on every multi-replica deployment). Lookup MUST return false on ANY
// uncertainty (miss / expiry / backend error) so the caller fails closed to
// family-reuse detection — BCP 4.13 is never weakened.
type RefreshGraceStore interface {
	Remember(token string, resp map[string]any, now time.Time)
	Lookup(token string, now time.Time) (map[string]any, bool)
}

var _ RefreshGraceStore = (*RefreshGraceCache)(nil)
