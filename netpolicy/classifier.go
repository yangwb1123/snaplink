package netpolicy

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
)

// Classifier keeps a priority-sorted snapshot of every policy in a Store and
// answers Classify() synchronously. The snapshot is hot — subscribing to the
// Store's Watch channel keeps it current without polling.
//
// Construction:
//
//	c := netpolicy.NewClassifier()
//	if err := c.Reload(ctx, store); err != nil { ... }
//	go c.Run(ctx, store)
//
// Reload performs the initial List; Run blocks on Watch and applies updates.
// Calling Run multiple times is undefined.
type Classifier struct {
	mu       sync.RWMutex
	snapshot []*compiledPolicy
}

// compiledPolicy is a Policy with its CIDRs pre-parsed into net.IPNets and
// hostnames lowercased — done once at Reload time so Classify is allocation-
// free on the hot path.
type compiledPolicy struct {
	policy    *Policy
	cidrs     []*net.IPNet
	hostnames map[string]struct{}
}

// NewClassifier returns an empty Classifier. Use Reload to populate.
func NewClassifier() *Classifier { return &Classifier{} }

// Classify returns the highest-priority policy that matches. host beats
// remoteAddr — see package doc. Returns nil when nothing matches; callers
// should treat that as "unknown / no advertised URLs available".
func (c *Classifier) Classify(remoteAddr, host string) *Policy {
	host = normalizeHost(host)
	ip := parseIP(remoteAddr)

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Pass 1: hostname matches.
	for _, cp := range c.snapshot {
		if host != "" {
			if _, ok := cp.hostnames[host]; ok {
				return cp.policy.Clone()
			}
		}
	}
	// Pass 2: CIDR matches.
	if ip != nil {
		for _, cp := range c.snapshot {
			for _, n := range cp.cidrs {
				if n.Contains(ip) {
					return cp.policy.Clone()
				}
			}
		}
	}
	return nil
}

// Snapshot returns a defensive copy of every policy currently in the
// classifier, sorted by descending priority. For introspection and HTTP
// /api/v1/netpolicy/policies listing.
func (c *Classifier) Snapshot() []*Policy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*Policy, 0, len(c.snapshot))
	for _, cp := range c.snapshot {
		out = append(out, cp.policy.Clone())
	}
	return out
}

// Reload re-pulls every policy from the store and rebuilds the index. Called
// at startup and as a safety-net after Watch reconnects.
func (c *Classifier) Reload(ctx context.Context, s Store) error {
	policies, err := s.List(ctx)
	if err != nil {
		return err
	}
	c.replace(policies)
	return nil
}

// Start subscribes to the store's Watch channel synchronously (so by the time
// Start returns, no events can be lost between Reload and the consumer loop),
// seeds the snapshot via Reload, then spawns a goroutine that applies updates
// until ctx is done or the watch closes. The returned done channel closes
// when the consumer loop exits — callers that want to block on shutdown can
// wait on it.
//
// Calling Start more than once on the same Classifier is undefined.
func (c *Classifier) Start(ctx context.Context, s Store) (<-chan struct{}, error) {
	ch, err := s.Watch(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.Reload(ctx, s); err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for evt := range ch {
			c.apply(evt)
		}
	}()
	return done, nil
}

func (c *Classifier) apply(evt Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch evt.Type {
	case EventAdded, EventUpdated:
		c.upsertLocked(evt.Policy)
	case EventRemoved:
		c.removeLocked(evt.Policy.Name)
	}
}

func (c *Classifier) upsertLocked(p *Policy) {
	cp := compile(p)
	for i, existing := range c.snapshot {
		if existing.policy.Name == p.Name {
			c.snapshot[i] = cp
			c.sortLocked()
			return
		}
	}
	c.snapshot = append(c.snapshot, cp)
	c.sortLocked()
}

func (c *Classifier) removeLocked(name string) {
	for i, cp := range c.snapshot {
		if cp.policy.Name == name {
			c.snapshot = append(c.snapshot[:i], c.snapshot[i+1:]...)
			return
		}
	}
}

func (c *Classifier) replace(policies []*Policy) {
	compiled := make([]*compiledPolicy, 0, len(policies))
	for _, p := range policies {
		compiled = append(compiled, compile(p))
	}
	c.mu.Lock()
	c.snapshot = compiled
	c.sortLocked()
	c.mu.Unlock()
}

func (c *Classifier) sortLocked() {
	sort.SliceStable(c.snapshot, func(i, j int) bool {
		return c.snapshot[i].policy.Priority > c.snapshot[j].policy.Priority
	})
}

func compile(p *Policy) *compiledPolicy {
	out := &compiledPolicy{policy: p.Clone()}
	if len(p.Hostnames) > 0 {
		out.hostnames = make(map[string]struct{}, len(p.Hostnames))
		for _, h := range p.Hostnames {
			out.hostnames[normalizeHost(h)] = struct{}{}
		}
	}
	for _, c := range p.CIDRs {
		// Allow bare IPs by upgrading to /32 or /128.
		if !strings.Contains(c, "/") {
			if ip := net.ParseIP(c); ip != nil {
				if ip.To4() != nil {
					c += "/32"
				} else {
					c += "/128"
				}
			}
		}
		if _, n, err := net.ParseCIDR(c); err == nil {
			out.cidrs = append(out.cidrs, n)
		}
		// Malformed CIDRs are silently dropped — the policy is still indexed
		// by hostname / other CIDRs. The /apply path SHOULD validate first;
		// this is a belt-and-suspenders pass for already-stored bad data.
	}
	return out
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	// Strip ":port" — Host header may include it.
	if i := strings.LastIndex(h, ":"); i >= 0 {
		// IPv6 literals look like [::1]:8080 — only strip when no closing bracket.
		if !strings.HasSuffix(h[:i], "]") && strings.Count(h, ":") == 1 {
			h = h[:i]
		}
	}
	return strings.ToLower(h)
}

func parseIP(remoteAddr string) net.IP {
	// Accept both "ip:port" and bare "ip" forms.
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteAddr = host
	}
	return net.ParseIP(remoteAddr)
}
