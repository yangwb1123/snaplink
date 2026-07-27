package memory

import (
	"context"
	"errors"
	"sort"
	"sync"

	"github.com/yangwb1123/snaplink/domains/tokenexchange"
)

// ErrMissingJTI is returned by ChainStore.RecordHop when hop.JTI is empty —
// it is the store's primary key, so an unkeyed hop can never be recorded or
// looked back up. RecordHopFailOpen already guards against this at the
// wiring call site; this is a defensive backstop for any OTHER caller.
var ErrMissingJTI = errors.New("tokenexchange/memory: ChainHop.JTI is required")

// ChainStore is the in-memory reference [tokenexchange.ChainStore]: suitable
// for development, testing, and single-replica deployments with no
// cross-restart chain-history persistence (domains/tokenexchange/sqlite is
// the durable, multi-replica peer). Safe for concurrent use.
type ChainStore struct {
	mu       sync.RWMutex
	hops     map[string]tokenexchange.ChainHop // keyed by JTI
	children map[string][]string               // parentJTI -> []JTI, insertion order
}

// NewChainStore builds an empty in-memory ChainStore.
func NewChainStore() *ChainStore {
	return &ChainStore{
		hops:     make(map[string]tokenexchange.ChainHop),
		children: make(map[string][]string),
	}
}

// RecordHop implements [tokenexchange.ChainStore]. Re-recording the same JTI
// (should never happen — JTIs are unique per mint) replaces the prior row
// rather than erroring, matching the upsert discipline sibling stores use.
func (s *ChainStore) RecordHop(_ context.Context, hop tokenexchange.ChainHop) error {
	if hop.JTI == "" {
		return ErrMissingJTI
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hops[hop.JTI] = hop
	if hop.ParentJTI != "" {
		s.children[hop.ParentJTI] = append(s.children[hop.ParentJTI], hop.JTI)
	}
	return nil
}

// GetChain implements [tokenexchange.ChainStore]: walks ParentJTI links
// backward from jti to the root, then reverses so the result reads oldest
// (root) first. A seen-set guards against a corrupted/cyclic parent chain
// (RecordHop never creates one, but a store populated by direct writes
// outside this package could) — such a cycle stops the walk rather than
// looping forever.
func (s *ChainStore) GetChain(_ context.Context, jti string) ([]tokenexchange.ChainHop, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var chain []tokenexchange.ChainHop
	seen := make(map[string]bool)
	for cur := jti; cur != "" && !seen[cur]; {
		seen[cur] = true
		hop, ok := s.hops[cur]
		if !ok {
			break
		}
		chain = append(chain, hop)
		cur = hop.ParentJTI
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain, nil
}

// GetDescendants implements [tokenexchange.ChainStore]: a breadth-first walk
// forward over the children index, collecting every hop transitively
// descended from jti, bounded by limit (<= 0 = no cap), newest-recorded
// first.
func (s *ChainStore) GetDescendants(_ context.Context, jti string, limit int) ([]tokenexchange.ChainHop, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	visited := map[string]bool{jti: true}
	queue := []string{jti}
	var out []tokenexchange.ChainHop
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, childJTI := range s.children[cur] {
			if visited[childJTI] {
				continue
			}
			visited[childJTI] = true
			if hop, ok := s.hops[childJTI]; ok {
				out = append(out, hop)
			}
			queue = append(queue, childJTI)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RecordedAt.After(out[j].RecordedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

var _ tokenexchange.ChainStore = (*ChainStore)(nil)
