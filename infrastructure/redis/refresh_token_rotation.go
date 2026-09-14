package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

// rtRotWinPrefix namespaces the per-family fixed-window rotation counter. One
// key per family, touched only by RecordRotation, so it is inherently single-
// slot (no hash tag needed).
const rtRotWinPrefix = "sso:rt:rotwin:" // sso:rt:rotwin:<family_id> -> HASH {count, ws(ms)}

func rtRotWinKey(familyID string) string { return rtRotWinPrefix + familyID }

const rtFamilyRevokedMember = "\x00snaplink:refresh-family-revoked"

var errRefreshTokenFamilyRevoked = errors.New("redis: refresh token family is revoked")

var familyMemberScript = goredis.NewScript(`
if redis.call('SISMEMBER', KEYS[1], ARGV[1]) == 1 then return 0 end
redis.call('SADD', KEYS[1], ARGV[2])
local cur = redis.call('TTL', KEYS[1])
if cur < 0 or cur < tonumber(ARGV[3]) then
  redis.call('EXPIRE', KEYS[1], ARGV[3])
end
return 1
`)

var familyRevocationScript = goredis.NewScript(`
redis.call('SADD', KEYS[1], ARGV[1])
local cur = redis.call('TTL', KEYS[1])
if cur < 0 or cur < tonumber(ARGV[2]) then
  redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return 1
`)

func familyTTLSeconds(ttl time.Duration) int64 {
	seconds := int64((ttl + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

func (s *RefreshTokenStore) addFamilyMember(ctx context.Context, familyID, lookup string, ttl time.Duration) error {
	seconds := familyTTLSeconds(ttl)
	added, err := familyMemberScript.Run(ctx, s.rdb, []string{rtFamilyKey(familyID)},
		rtFamilyRevokedMember, lookup, seconds).Int64()
	if err != nil {
		return fmt.Errorf("redis: index refresh token family: %w", err)
	}
	if added == 0 {
		return errRefreshTokenFamilyRevoked
	}
	return nil
}

func (s *RefreshTokenStore) familyRevoked(ctx context.Context, familyID string) (bool, error) {
	if familyID == "" {
		return false, nil
	}
	revoked, err := s.rdb.SIsMember(ctx, rtFamilyKey(familyID), rtFamilyRevokedMember).Result()
	if err != nil {
		return false, fmt.Errorf("redis: check refresh family: %w", err)
	}
	return revoked, nil
}

func (s *RefreshTokenStore) markFamilyRevoked(ctx context.Context, familyID string) error {
	if err := familyRevocationScript.Run(ctx, s.rdb, []string{rtFamilyKey(familyID)},
		rtFamilyRevokedMember, familyTTLSeconds(s.familyTTL)).Err(); err != nil {
		return fmt.Errorf("redis: mark refresh family revoked: %w", err)
	}
	return nil
}

func (s *RefreshTokenStore) familyTokens(ctx context.Context, familyID string) ([]string, error) {
	tokens, err := s.rdb.SMembers(ctx, rtFamilyKey(familyID)).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: read family: %w", err)
	}
	return tokens, nil
}

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

func (s *RefreshTokenStore) consumedOrNotFound(ctx context.Context, token string) (*oauth.RefreshToken, error) {
	familyID, err := s.consumedFamily(ctx, token)
	if errors.Is(err, goredis.Nil) {
		return nil, oauth.ErrRefreshTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("redis: family lookup: %w", err)
	}
	return &oauth.RefreshToken{FamilyID: familyID}, oauth.ErrRefreshTokenReused
}

// Consume checks the family tombstone before and after GETDEL. The checks
// bracket the single-use removal so a concurrent family kill cannot mint a
// usable descendant after its tombstone is committed.
func (s *RefreshTokenStore) Consume(ctx context.Context, token string) (*oauth.RefreshToken, error) {
	blob, _, err := s.activeBlob(ctx, token, false)
	if errors.Is(err, goredis.Nil) {
		return s.consumedOrNotFound(ctx, token)
	}
	if err != nil {
		return nil, fmt.Errorf("redis: inspect before consume: %w", err)
	}
	var out oauth.RefreshToken
	if err := json.Unmarshal(blob, &out); err != nil {
		return nil, fmt.Errorf("redis: unmarshal refresh_token: %w", err)
	}
	if out.IsExpired() {
		return nil, oauth.ErrRefreshTokenNotFound
	}
	revoked, err := s.familyRevoked(ctx, out.FamilyID)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, oauth.ErrRefreshTokenNotFound
	}
	consumed, lookup, err := s.activeBlob(ctx, token, true)
	if errors.Is(err, goredis.Nil) {
		return s.consumedOrNotFound(ctx, token)
	}
	if err != nil {
		return nil, fmt.Errorf("redis: consume refresh_token: %w", err)
	}
	if err := json.Unmarshal(consumed, &out); err != nil {
		return nil, fmt.Errorf("redis: unmarshal refresh_token: %w", err)
	}
	if out.IsExpired() {
		return nil, oauth.ErrRefreshTokenNotFound
	}
	revoked, err = s.familyRevoked(ctx, out.FamilyID)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, oauth.ErrRefreshTokenNotFound
	}
	if out.FamilyID != "" {
		_ = s.rdb.Set(ctx, rtFamilyMemKey(lookup), out.FamilyID, s.familyTTL).Err()
	}
	return &out, nil
}

// DeleteFamily commits a cluster-safe logical tombstone before cleaning up
// member keys. A failed cleanup leaves the tombstone and index so retries can
// finish deletion while Inspect and Consume already reject every sibling.
func (s *RefreshTokenStore) DeleteFamily(ctx context.Context, familyID string) (int, error) {
	if familyID == "" {
		return 0, nil
	}
	exists, err := s.rdb.Exists(ctx, rtFamilyKey(familyID)).Result()
	if err != nil {
		return 0, fmt.Errorf("redis: check family index: %w", err)
	}
	if exists == 0 {
		return 0, nil
	}
	if err := s.markFamilyRevoked(ctx, familyID); err != nil {
		return 0, err
	}
	tokens, err := s.familyTokens(ctx, familyID)
	if err != nil {
		return 0, err
	}
	return s.cleanRevokedFamily(ctx, familyID, tokens)
}

func (s *RefreshTokenStore) cleanRevokedFamily(ctx context.Context, familyID string, tokens []string) (int, error) {
	familyKey := rtFamilyKey(familyID)
	deleted := 0
	for _, tokenID := range tokens {
		if tokenID == rtFamilyRevokedMember {
			continue
		}
		n, err := s.rdb.Del(ctx, rtKey(tokenID)).Result()
		if err != nil {
			return deleted, fmt.Errorf("redis: delete family token: %w", err)
		}
		deleted += int(n)
		if err := s.rdb.Del(ctx, rtFamilyMemKey(tokenID)).Err(); err != nil {
			return deleted, fmt.Errorf("redis: delete family replay marker: %w", err)
		}
		if err := s.rdb.SRem(ctx, familyKey, tokenID).Err(); err != nil {
			return deleted, fmt.Errorf("redis: prune family index: %w", err)
		}
	}
	return deleted, nil
}

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
