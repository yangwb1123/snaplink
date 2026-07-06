// Package memreaper provides a tiny background-sweep primitive shared by
// the in-process memory OAuth/credential stores (refresh token, device
// code, PAR, JTI replay). Each of those stores already does LAZY
// expiry cleanup on the specific key a caller touches (see each store's
// own doc comment); what lazy-only GC can't reach is an entry whose key
// is never looked up again after it expires — an issued-but-abandoned
// refresh token, a device code nobody ever polls to completion, a PAR
// request_uri nobody redeems. Reaper closes that gap with an opt-in
// ticker loop; a store built without one keeps its existing lazy-only
// behavior, byte-identical to before this package existed.
package memreaper

import (
	"sync"
	"time"
)

// Reaper runs sweep on a fixed interval in its own goroutine until Close.
type Reaper struct {
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// Start launches the sweep loop and returns the handle to stop it later.
// interval <= 0 returns nil (no goroutine started) so callers can pass a
// zero-value config field straight through without a branch of their
// own — the returned nil is safe to store and Close.
func Start(interval time.Duration, sweep func(now time.Time)) *Reaper {
	if interval <= 0 {
		return nil
	}
	r := &Reaper{stop: make(chan struct{}), done: make(chan struct{})}
	go r.run(interval, sweep)
	return r
}

func (r *Reaper) run(interval time.Duration, sweep func(time.Time)) {
	defer close(r.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case now := <-ticker.C:
			sweep(now)
		}
	}
}

// Close stops the sweep loop and waits for it to exit. Safe on a nil
// *Reaper (a store that never had one started) and safe to call more
// than once (e.g. an explicit shutdown followed by a test's t.Cleanup).
func (r *Reaper) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() { close(r.stop) })
	<-r.done
	return nil
}
