package federation

import (
	"sync"
	"time"
)

// ----- negative (failure) cache + concurrency semaphore -------------------
//
// The resolution trigger (an /auth/login miss for an HTTPS-shaped client_id) is
// UNAUTHENTICATED, so these blunt abuse: the negative cache stops a repeated
// fake id from re-fetching; the semaphore caps distinct-id parallelism. Both
// keep the wire shape unchanged (a blunted path yields the same unknown-client
// error) — they only DELAY/SHED, never admit or reject differently.

// negativeCacheHit reports whether entityID has a FRESH negative entry (a
// recent failure within negTTL). A stale entry is lazily evicted so the map
// self-trims on lookups for previously-failed ids.
func (s *RegistrationClientStore) negativeCacheHit(entityID string, now time.Time) bool {
	if s.negTTL <= 0 {
		return false
	}
	s.negMu.Lock()
	defer s.negMu.Unlock()
	exp, ok := s.negCache[entityID]
	if !ok {
		return false
	}
	if now.Before(exp) {
		return true
	}
	// Stale — lazy-expire.
	delete(s.negCache, entityID)
	return false
}

// recordNegative remembers a FAILED resolution for entityID with a short TTL.
// It enforces the entry cap so the negative cache cannot itself become an
// unbounded-memory DoS: at the cap it first sweeps expired entries, then evicts
// the soonest-to-expire entry to admit the new one.
func (s *RegistrationClientStore) recordNegative(entityID string, now time.Time) {
	if s.negTTL <= 0 {
		return
	}
	s.negMu.Lock()
	defer s.negMu.Unlock()
	if _, exists := s.negCache[entityID]; !exists && s.negMax > 0 && len(s.negCache) >= s.negMax {
		s.evictNegativeLocked(now)
	}
	s.negCache[entityID] = now.Add(s.negTTL)
}

// clearNegative drops any negative entry for entityID (called on a successful
// resolution). nil-safe via the mutex.
func (s *RegistrationClientStore) clearNegative(entityID string) {
	s.negMu.Lock()
	delete(s.negCache, entityID)
	s.negMu.Unlock()
}

// evictNegativeLocked makes room under the entry cap. Caller holds negMu. It
// first deletes every expired entry (cheap, bounded sweep — the map is capped);
// if that frees nothing (every entry still fresh under a sustained distinct-id
// flood), it evicts the entry with the EARLIEST expiry so a bounded amount of
// memory is reclaimed deterministically.
func (s *RegistrationClientStore) evictNegativeLocked(now time.Time) {
	freed := false
	for k, exp := range s.negCache {
		if !now.Before(exp) {
			delete(s.negCache, k)
			freed = true
		}
	}
	if freed {
		return
	}
	var oldestKey string
	var oldestExp time.Time
	first := true
	for k, exp := range s.negCache {
		if first || exp.Before(oldestExp) {
			oldestKey, oldestExp, first = k, exp, false
		}
	}
	if !first {
		delete(s.negCache, oldestKey)
	}
}

// acquireResolveSlot tries to take one of the bounded resolution slots WITHOUT
// blocking. true ⇒ a slot was acquired (the caller MUST releaseResolveSlot);
// false ⇒ the semaphore is saturated (fail-closed: the caller sheds the
// resolution and returns the oracle-safe unknown-client error). A nil semaphore
// (never constructed) is treated as unbounded — acquire always succeeds.
func (s *RegistrationClientStore) acquireResolveSlot() bool {
	if s.resolveSem == nil {
		return true
	}
	select {
	case s.resolveSem <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseResolveSlot returns a slot taken by acquireResolveSlot.
func (s *RegistrationClientStore) releaseResolveSlot() {
	if s.resolveSem == nil {
		return
	}
	<-s.resolveSem
}

// ----- keyedMutex ---------------------------------------------------------

// keyedMutex serializes work per string key (here: per entity ID), so a burst
// of concurrent first-time resolutions for ONE federation RP resolves the
// chain once while DIFFERENT RPs resolve in parallel. Lazily allocates a
// *sync.Mutex per active key and reference-counts it so idle keys don't leak.
type keyedMutex struct {
	mu sync.Mutex
	m  map[string]*kmEntry
}

type kmEntry struct {
	mu   sync.Mutex
	refs int
}

// lock acquires the per-key mutex and returns an unlock func that releases it
// and drops the (ref-counted) entry when no waiter remains.
func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	if k.m == nil {
		k.m = make(map[string]*kmEntry)
	}
	e := k.m[key]
	if e == nil {
		e = &kmEntry{}
		k.m[key] = e
	}
	e.refs++
	k.mu.Unlock()

	e.mu.Lock()
	return func() {
		e.mu.Unlock()
		k.mu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(k.m, key)
		}
		k.mu.Unlock()
	}
}
