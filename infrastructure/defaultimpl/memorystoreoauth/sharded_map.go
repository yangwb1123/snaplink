package memorystoreoauth

import (
	"hash/fnv"
	"sync"
)

// mapShardCount is the number of independent lock+map partitions inside a
// shardedMap. Must be a power of two so shardIndexFNV reduces to a cheap
// bitmask (matches interfaces/ratelimit.MemoryLimiter's numShards
// convention — same hash family, same shard-count shape). 16 shards
// caps worst-case lock contention at 1/16 of the single-mutex baseline
// for legitimate concurrent traffic, at negligible fixed memory cost
// (16 empty maps).
const mapShardCount = 16

// shardIndexFNV hashes key with FNV-32a and reduces it to a shard index.
// Allocation-free; the keys here (auth codes, PAR request_uris) are
// server-generated crypto/rand tokens, never attacker-chosen, so a
// non-cryptographic hash carries no hash-flooding risk.
func shardIndexFNV(key string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key)) // Write never errors for hash.Hash32
	return h.Sum32() & (mapShardCount - 1)
}

// mapShard is one lock-protected partition of a shardedMap's keyspace.
type mapShard[V any] struct {
	mu      sync.Mutex
	entries map[string]V
}

// shardedMap replaces a single "sync.Mutex + map[string]V" pair with
// mapShardCount independently-locked partitions, so two callers touching
// DIFFERENT keys never wait on each other's lock — the single global
// mutex the memory OAuth stores used before this type existed serialized
// EVERY Issue/Consume regardless of key, which is the dominant
// contention point under load (every login mints + consumes one).
//
// Deliberately narrow: every operation here keys off exactly ONE string
// and never needs a cross-key atomic view. MemoryDeviceCodeStore (two
// indices — device_code and user_code — sharing one *oauth.DeviceCode,
// where an unrelated-looking Approve(userCode) mutates a field Consume
// (deviceCode) reads) and MemoryRefreshTokenStore (family-keyed
// DeleteFamily scans across the WHOLE entries map, an OAuth Security BCP
// §4.13 fail-closed guarantee — see AGENTS.md §3 "Refresh family") are
// deliberately NOT converted to this type: splitting their single mutex
// into independent per-key shards would let a family-wide revoke or a
// second-index update run unsynchronized against a keyed op on the SAME
// logical entry, a genuine data race, not just a missed optimization.
type shardedMap[V any] struct {
	shards [mapShardCount]mapShard[V]
}

// newShardedMap returns a ready-to-use shardedMap with every shard's
// backing map already allocated, so the first Store into a given shard
// never needs a nil-map special case.
func newShardedMap[V any]() *shardedMap[V] {
	sm := &shardedMap[V]{}
	for i := range sm.shards {
		sm.shards[i].entries = make(map[string]V)
	}
	return sm
}

func (s *shardedMap[V]) shardFor(key string) *mapShard[V] {
	return &s.shards[shardIndexFNV(key)]
}

// Store sets key's value, replacing any existing entry.
func (s *shardedMap[V]) Store(key string, v V) {
	sh := s.shardFor(key)
	sh.mu.Lock()
	sh.entries[key] = v
	sh.mu.Unlock()
}

// LoadAndDelete returns key's value (and whether it was present) and
// removes it in the SAME critical section — the single-use "consume"
// idiom every store built on shardedMap needs, so a concurrent Store of
// the same key can never be observed as a partial update.
func (s *shardedMap[V]) LoadAndDelete(key string) (V, bool) {
	sh := s.shardFor(key)
	sh.mu.Lock()
	v, ok := sh.entries[key]
	if ok {
		delete(sh.entries, key)
	}
	sh.mu.Unlock()
	return v, ok
}
