package servercache

import "sync"

// JWKSSingleFlight collapses concurrent JWKS document computations into a
// single one, reduced to one global key (the JWKS doc is not per-host).
// It is the classic single-flight pattern: callers that arrive while a
// computation is in flight block on it and share its result instead of
// each recomputing. Calls that arrive after the in-flight one completes
// recompute fresh — there is intentionally no result caching, so a key
// rotation is reflected on the very next poll.
type JWKSSingleFlight struct {
	mu     sync.Mutex
	active *jwksCall
}

type jwksCall struct {
	wg   sync.WaitGroup
	body []byte
	err  error
}

// Do runs compute, collapsing any concurrent invocations onto the first
// caller's result. compute must be safe to skip for the followers — it
// is, since the JWKS doc derives only from the (rotation-guarded) issuer
// key set, identical for every concurrent caller.
func (f *JWKSSingleFlight) Do(compute func() ([]byte, error)) ([]byte, error) {
	f.mu.Lock()
	if c := f.active; c != nil {
		f.mu.Unlock()
		c.wg.Wait()
		return c.body, c.err
	}
	c := &jwksCall{}
	c.wg.Add(1)
	f.active = c
	f.mu.Unlock()

	c.body, c.err = compute()

	f.mu.Lock()
	f.active = nil
	f.mu.Unlock()
	c.wg.Done()
	return c.body, c.err
}
