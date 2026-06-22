package redis

import (
	"context"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/snaplink/sso/protocols/oauth"
)

// rtRotWinPrefix namespaces the per-family fixed-window rotation counter. One
// key per family, touched only by RecordRotation, so it is inherently single-
// slot (no hash tag needed).
const rtRotWinPrefix = "sso:rt:rotwin:" // sso:rt:rotwin:<family_id> -> HASH {count, ws(ms)}

func rtRotWinKey(familyID string) string { return rtRotWinPrefix + familyID }

// rotationWindowScript is the atomic fixed-window bump: read (count, window
// start), roll the window over when elapsed, increment, write back, and bound
// the key's lifetime with EXPIRE — all server-side so concurrent rotations of
// one family cannot interleave their read-modify-write (the Redis analogue of
// the sqlite peer's BEGIN IMMEDIATE serialized RMW). Returns the post-increment
// count; the Go caller decides "exceeded".
//
// Time is in UNIX-MILLISECONDS, never nanoseconds: Lua numbers are float64,
// which holds ms exactly but not ns (1.7e18 > 2^53) — the same constraint
// session.go's refreshScript documents. Millisecond resolution is ample for a
// velocity window measured in seconds/minutes.
//
// KEYS[1] = rotation-window hash
// ARGV[1] = now (unix-ms)  ARGV[2] = window (ms, 0 = no rollover)  ARGV[3] = ttl seconds
var rotationWindowScript = goredis.NewScript(`
local h = redis.call('HMGET', KEYS[1], 'count', 'ws')
local count = tonumber(h[1]) or 0
local ws = tonumber(h[2]) or 0
local now = tonumber(ARGV[1])
local win = tonumber(ARGV[2])
if win > 0 and ws > 0 and (now - ws) >= win then
  count = 0
  ws = 0
end
count = count + 1
if ws == 0 then ws = now end
redis.call('HSET', KEYS[1], 'count', count, 'ws', ws)
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
return count
`)

// RecordRotation implements [oauth.RefreshTokenRotationLimiter]: it atomically
// bumps familyID's fixed-window counter and reports (count, exceeded, err),
// matching the memory + sqlite peers. An empty familyID is a no-op
// (0, false, nil). The window rolls over once rotationWindow has elapsed since
// the window start.
//
// Fail-open: a store error returns (0, false, err) — the caller treats that as
// non-exceeded per the §2 fail-open contract for the velocity cap. The hard
// reuse-detection gate (family-kill on a replayed token) is unaffected; the cap
// is the softer anti-abuse layer, so availability wins on a transient error.
func (s *RefreshTokenStore) RecordRotation(ctx context.Context, familyID string) (int, bool, error) {
	if familyID == "" {
		return 0, false, nil
	}
	// Window-key TTL: just past the window when one is configured (so the
	// counter self-GCs between bursts), else familyTTL so an uncapped counter
	// still cannot leak forever.
	ttl := s.familyTTL
	if s.rotationWindow > 0 {
		ttl = s.rotationWindow + time.Minute
	}
	ttlSecs := int64(ttl / time.Second)
	if ttlSecs < 1 {
		ttlSecs = 1
	}

	count, err := rotationWindowScript.Run(ctx, s.rdb,
		[]string{rtRotWinKey(familyID)},
		time.Now().UnixMilli(), s.rotationWindow.Milliseconds(), ttlSecs,
	).Int64()
	if err != nil {
		return 0, false, fmt.Errorf("redis: record rotation: %w", err)
	}

	exceeded := s.maxRotationsPerWindow > 0 && s.rotationWindow > 0 &&
		count > int64(s.maxRotationsPerWindow)
	return int(count), exceeded, nil
}

var _ oauth.RefreshTokenRotationLimiter = (*RefreshTokenStore)(nil)
