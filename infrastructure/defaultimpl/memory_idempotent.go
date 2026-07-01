package defaultimpl

import (
	"context"
	"sync"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// MemoryIdempotentCache is an in-process, non-persistent idempotency
// cache for the /token endpoint. Entries expire after ttl and are
// periodically cleaned up. Safe for concurrent use.
type MemoryIdempotentCache struct {
	mu       sync.RWMutex
	entries  map[string]memIdempotentEntry
	ttl      time.Duration
	stopCh   chan struct{}
	stopOnce sync.Once
}

type memIdempotentEntry struct {
	body      []byte
	expiresAt time.Time
}

// NewMemoryIdempotentCache returns an empty MemoryIdempotentCache with
// the given ttl. A background goroutine prunes expired entries every
// 5 minutes; call Close to stop it.
func NewMemoryIdempotentCache(ttl time.Duration) *MemoryIdempotentCache {
	c := &MemoryIdempotentCache{
		entries: make(map[string]memIdempotentEntry),
		ttl:     ttl,
		stopCh:  make(chan struct{}),
	}
	go c.pruneLoop()
	return c
}

func (c *MemoryIdempotentCache) pruneLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			for k, e := range c.entries {
				if now.After(e.expiresAt) {
					delete(c.entries, k)
				}
			}
			c.mu.Unlock()
		case <-c.stopCh:
			return
		}
	}
}

// Close stops the background prune loop. Safe to call multiple times.
func (c *MemoryIdempotentCache) Close() {
	c.stopOnce.Do(func() { close(c.stopCh) })
}

// Get implements core.IdempotentCache.
func (c *MemoryIdempotentCache) Get(_ context.Context, key string) ([]byte, bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[key]
	if !ok || time.Now().After(e.expiresAt) {
		return nil, false, nil
	}
	return e.body, true, nil
}

// Set implements core.IdempotentCache.
func (c *MemoryIdempotentCache) Set(_ context.Context, key string, body []byte, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ttl <= 0 {
		ttl = c.ttl
	}
	c.entries[key] = memIdempotentEntry{
		body:      body,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

// compile-time check.
var _ core.IdempotentCache = (*MemoryIdempotentCache)(nil)
