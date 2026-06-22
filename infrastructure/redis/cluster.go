package redis

import (
	"context"
	"errors"

	goredis "github.com/redis/go-redis/v9"
)

// Redis Cluster slot-safety helpers.
//
// Redis Cluster shards the keyspace into 16384 hash slots and REJECTS any
// single command (or Lua script) whose keys do not all map to one slot
// (CROSSSLOT). The slot is CRC16 of the key, OR — when the key contains a
// "{...}" substring — CRC16 of the bytes between the first '{' and the next
// '}'. That brace substring is the "hash tag".
//
// Two patterns keep this package correct on a real cluster while behaving
// identically on a single node (and under the miniredis tests, which do not
// emulate slots — see slot_test.go for the static slot-equality guard):
//
//   - hashTag co-locates keys that one ATOMIC multi-key op must touch
//     together (e.g. the permissions Lua reads/writes a client's role hash,
//     every per-user assignment set, and the users index in one script — they
//     all carry {clientID} so they share a slot).
//   - mgetCompat replaces MGET across keys that genuinely span slots (a List
//     over all clients/users can never share a tag) with a per-key GET
//     pipeline, which the cluster client auto-routes per node.

// hashTag wraps s in Redis Cluster hash-tag braces so every key built with the
// same tag lands in one slot. Empty braces are ignored by Redis (the whole key
// hashes), so an empty s degrades to per-key hashing rather than colliding.
func hashTag(s string) string { return "{" + s + "}" }

// mgetCompat is the Redis-Cluster-safe equivalent of MGET: it issues one GET
// per key in a single pipeline (the cluster client routes each GET to its slot
// owner and batches per node), then returns the values positionally aligned
// with keys. A missing key yields a nil entry — exactly MGET's shape — so
// callers parse the result identically to s.rdb.MGet(...).Result().
func mgetCompat(ctx context.Context, rdb goredis.Cmdable, keys []string) ([]any, error) {
	if len(keys) == 0 {
		return []any{}, nil
	}
	pipe := rdb.Pipeline()
	cmds := make([]*goredis.StringCmd, len(keys))
	for i, k := range keys {
		cmds[i] = pipe.Get(ctx, k)
	}
	// A missing key surfaces as redis.Nil from Exec; that is expected (MGET
	// tolerates holes), so only a real transport/server error aborts.
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, goredis.Nil) {
		return nil, err
	}
	out := make([]any, len(keys))
	for i, c := range cmds {
		v, err := c.Result()
		if errors.Is(err, goredis.Nil) {
			out[i] = nil
			continue
		}
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}
