package modules

import (
	"context"
	"sync"
	"time"
)

type generation struct {
	id           string
	number       uint64
	instance     Instance
	digest       string
	activatedAt  time.Time
	dependencies []*Lease

	mu       sync.Mutex
	draining bool
	counts   map[LeaseClass]int64
	drained  chan struct{}
}

func newGeneration(id string, number uint64, instance Instance, digest string, dependencies []*Lease) *generation {
	return &generation{
		id: id, number: number, instance: instance, digest: digest,
		dependencies: dependencies, counts: make(map[LeaseClass]int64), drained: make(chan struct{}),
	}
}

func (g *generation) acquire(class LeaseClass) (*Lease, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.draining {
		return nil, false
	}
	g.counts[class]++
	return &Lease{generation: g, class: class}, true
}

func (g *generation) beginDrain() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.draining {
		return
	}
	g.draining = true
	if g.totalLeasesLocked() == 0 {
		close(g.drained)
	}
}

func (g *generation) release(class LeaseClass) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.counts[class] > 0 {
		g.counts[class]--
	}
	if g.draining && g.totalLeasesLocked() == 0 {
		select {
		case <-g.drained:
		default:
			close(g.drained)
		}
	}
}

func (g *generation) totalLeasesLocked() int64 {
	return g.counts[LeaseRequest] + g.counts[LeaseDependency] + g.counts[LeaseBackground]
}

func (g *generation) leaseCount(class LeaseClass) int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.counts[class]
}

func (g *generation) snapshot() (bool, map[LeaseClass]int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	counts := make(map[LeaseClass]int64, len(g.counts))
	for class, count := range g.counts {
		if count > 0 {
			counts[class] = count
		}
	}
	return g.draining, counts
}

func (g *generation) waitDrained(ctx context.Context) error {
	select {
	case <-g.drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type Lease struct {
	generation *generation
	class      LeaseClass
	once       sync.Once
}

func (l *Lease) Instance() Instance {
	if l == nil || l.generation == nil {
		return nil
	}
	return l.generation.instance
}

func (l *Lease) Generation() uint64 {
	if l == nil || l.generation == nil {
		return 0
	}
	return l.generation.number
}

func (l *Lease) Release() {
	if l == nil || l.generation == nil {
		return
	}
	l.once.Do(func() { l.generation.release(l.class) })
}

type backgroundLease struct {
	lease *Lease
}

func (l *backgroundLease) Generation() uint64 {
	if l == nil {
		return 0
	}
	return l.lease.Generation()
}

func (l *backgroundLease) Release() {
	if l != nil {
		l.lease.Release()
	}
}

type generationController struct {
	generation *generation
}

func (c *generationController) AcquireBackground() (BackgroundLease, error) {
	if c == nil || c.generation == nil {
		return nil, ErrModuleInactive
	}
	lease, acquired := c.generation.acquire(LeaseBackground)
	if !acquired {
		return nil, ErrModuleDraining
	}
	return &backgroundLease{lease: lease}, nil
}
