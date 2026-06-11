package sso

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
type refreshGraceCache struct {
	window time.Duration
	mu     sync.Mutex
	m      map[string]refreshGraceEntry
}

type refreshGraceEntry struct {
	resp    map[string]any
	expires time.Time
}

func newRefreshGraceCache(window time.Duration) *refreshGraceCache {
	return &refreshGraceCache{window: window, m: make(map[string]refreshGraceEntry)}
}

// remember caches resp as the successor for the just-consumed token. resp is
// cloned so a later caller mutation can't corrupt the cached copy.
func (c *refreshGraceCache) remember(token string, resp map[string]any, now time.Time) {
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
func (c *refreshGraceCache) lookup(token string, now time.Time) (map[string]any, bool) {
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
func (c *refreshGraceCache) pruneLocked(now time.Time) {
	for k, e := range c.m {
		if !now.Before(e.expires) {
			delete(c.m, k)
		}
	}
}
