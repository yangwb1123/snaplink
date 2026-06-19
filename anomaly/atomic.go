package anomaly

import "sync"

// atomicBool is a tiny inline wrapper over sync/atomic.Bool — kept
// local to avoid bumping the Go version requirement if/when this
// file's import set shifts. Only Start's once-only latch uses it now;
// the closed flag moved to a sync.RWMutex so the closed-check and the
// queue send share one lock (see Runner.mu).
type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (a *atomicBool) compareAndSwap(old, new bool) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.v != old {
		return false
	}
	a.v = new
	return true
}
