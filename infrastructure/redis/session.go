package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/snaplink/sso/interfaces/sso"
)

const sessionIDBytes = 32

// Key layout. Every key is namespaced so one Redis logical DB can host
// every store side by side without collision. The session value is a
// hash; ListByUser/ListAll ride a per-user + a global SET index so the
// admin "list active sessions" view (which a stateless JWT issuer can't
// answer) works on Redis too.
const (
	sessionKeyPrefix  = "sso:session:"      // sso:session:<id> -> hash
	sessionUserPrefix = "sso:session:user:" // sso:session:user:<uid> -> SET of ids
	sessionAllKey     = "sso:session:all"   // SET of every live session id
)

// SessionManager is the Redis-backed implementation of
// [sso.SessionManager]. Suitable for multi-replica deployments where a
// session minted on replica A must be redeemable on replica B.
type SessionManager struct {
	rdb goredis.Cmdable
	ttl time.Duration
}

// SessionOption configures the SessionManager.
type SessionOption func(*SessionManager)

// WithSessionTTL sets the lifetime applied on Create + Refresh. Zero or
// negative takes [sso.DefaultSessionDuration].
func WithSessionTTL(ttl time.Duration) SessionOption {
	return func(s *SessionManager) { s.ttl = ttl }
}

// NewSessionManager builds a SessionManager over an existing go-redis
// client (or cluster client — any goredis.Cmdable). The caller owns the
// client's lifecycle.
func NewSessionManager(rdb goredis.Cmdable, opts ...SessionOption) *SessionManager {
	s := &SessionManager{rdb: rdb, ttl: sso.DefaultSessionDuration}
	for _, o := range opts {
		o(s)
	}
	if s.ttl <= 0 {
		s.ttl = sso.DefaultSessionDuration
	}
	return s
}

// Ping reports Redis connection health for [sso.WithReadyCheck] wiring.
func (s *SessionManager) Ping(ctx context.Context) error {
	if s == nil || s.rdb == nil {
		return errors.New("redis: session manager not initialized")
	}
	return s.rdb.Ping(ctx).Err()
}

func sessionKey(id string) string    { return sessionKeyPrefix + id }
func sessionUserKey(u string) string { return sessionUserPrefix + u }

func (s *SessionManager) Create(ctx context.Context, userID string) (*sso.Session, error) {
	id, err := randomSessionID()
	if err != nil {
		return nil, fmt.Errorf("redis: random session id: %w", err)
	}
	now := time.Now().UTC()
	session := &sso.Session{
		ID:        id,
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
	}
	// The hash carries expires_at explicitly (in addition to the key
	// TTL) so Get/Refresh can read the deadline without trusting Redis'
	// eviction timing — an expired-but-not-yet-evicted key still reads
	// as expired. EXPIRE on the key plus a small grace bounds memory.
	//
	// Timestamps are stored as Unix MILLISECONDS, not nanoseconds: the
	// refresh script compares expires_at via Lua tonumber(), and Lua 5.1
	// numbers are IEEE-754 float64 (exact only for integers <= 2^53 ~=
	// 9e15). A Unix-ns value (~1.7e18) overflows that range by ~190x, so a
	// near-boundary comparison can be off by ~190ns and resurrect a just-
	// expired session (violates §2). Unix-ms (~1.7e12) sits well inside the
	// exact range; millisecond granularity is ample for session expiry.
	if err := s.rdb.HSet(ctx, sessionKey(id),
		"user_id", userID,
		"created_at", strconv.FormatInt(now.UnixMilli(), 10),
		"expires_at", strconv.FormatInt(session.ExpiresAt.UnixMilli(), 10),
		"revoked", "0",
	).Err(); err != nil {
		return nil, fmt.Errorf("redis: create session: %w", err)
	}
	if err := s.rdb.Expire(ctx, sessionKey(id), s.ttl).Err(); err != nil {
		// Roll back the just-written hash. Without this, a transient Expire
		// failure right after a successful HSet leaves the key installed with
		// NO TTL: Get/Refresh still treat it as expired via the explicit
		// expires_at field (so it can never be resurrected), but Redis would
		// never evict the hash itself — an unbounded, permanent leak that
		// accumulates one dead key per failed Create for the life of the
		// deployment. Best-effort; the caller already sees the error either
		// way. Mirrors the device_code store's Issue rollback for the same
		// half-written-record failure mode.
		_ = s.rdb.Del(ctx, sessionKey(id)).Err()
		return nil, fmt.Errorf("redis: session expire: %w", err)
	}
	// Index for ListByUser / ListAll. The index entries are pruned
	// lazily on read when their session key is gone (TTL evicted).
	_ = s.rdb.SAdd(ctx, sessionUserKey(userID), id).Err()
	_ = s.rdb.SAdd(ctx, sessionAllKey, id).Err()
	return session, nil
}

func (s *SessionManager) Get(ctx context.Context, sessionID string) (*sso.Session, error) {
	out, err := s.load(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	// Filter expired + revoked: the TTL handles most expiry, but an
	// explicit check closes the eviction-lag window and revoked rows
	// never carry a TTL semantics signal on their own.
	if out.Revoked || out.IsExpired() {
		return nil, sso.ErrSessionNotFound
	}
	return out, nil
}

// load reads the raw hash; ErrSessionNotFound when the key is gone.
func (s *SessionManager) load(ctx context.Context, sessionID string) (*sso.Session, error) {
	vals, err := s.rdb.HGetAll(ctx, sessionKey(sessionID)).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: get session: %w", err)
	}
	if len(vals) == 0 {
		return nil, sso.ErrSessionNotFound
	}
	return sessionFromHash(sessionID, vals)
}

func (s *SessionManager) Destroy(ctx context.Context, sessionID string) error {
	// Read the user id first so we can prune the per-user index; a miss
	// is fine (Destroy is idempotent).
	if out, err := s.load(ctx, sessionID); err == nil {
		_ = s.rdb.SRem(ctx, sessionUserKey(out.UserID), sessionID).Err()
	}
	_ = s.rdb.SRem(ctx, sessionAllKey, sessionID).Err()
	if err := s.rdb.Del(ctx, sessionKey(sessionID)).Err(); err != nil {
		return fmt.Errorf("redis: destroy session: %w", err)
	}
	return nil
}

// refreshScript is the atomic check-and-extend. It refuses to resurrect
// an expired or revoked session: it re-reads revoked + expires_at and
// only when revoked==0 AND expires_at>now does it write the new
// expires_at + bump the key TTL. Otherwise it returns -1 and changes
// nothing. Running this server-side as one script is the Redis analogue
// of SQLite's UPDATE ... WHERE expires_at>now AND revoked=0 RETURNING —
// without it, a read-modify-write in the client would race a concurrent
// Destroy/expiry and could extend a session that should be dead, which
// is the "captured expired session id resurrected" regression §2 forbids.
//
// KEYS[1] = session hash key
// ARGV[1] = now (unix-ms)  ARGV[2] = new expires_at (unix-ms)  ARGV[3] = ttl seconds
// Unix-MS (not ns): tonumber() yields a float64 that holds ms exactly but
// not ns (see Create) — so the <= boundary comparison is precise.
// Returns the new expires_at on success, -1 on refuse/missing.
var refreshScript = goredis.NewScript(`
local h = redis.call('HMGET', KEYS[1], 'revoked', 'expires_at')
if h[1] == false then
  return -1
end
if h[1] ~= '0' then
  return -1
end
if tonumber(h[2]) <= tonumber(ARGV[1]) then
  return -1
end
redis.call('HSET', KEYS[1], 'expires_at', ARGV[2])
redis.call('EXPIRE', KEYS[1], ARGV[3])
return ARGV[2]
`)

// Refresh extends ExpiresAt by ttl, refusing expired / revoked rows.
// Returns ErrSessionNotFound when the row is missing, revoked, or
// expired — matching the SQLite + memory contract exactly.
func (s *SessionManager) Refresh(ctx context.Context, sessionID string) (*sso.Session, error) {
	now := time.Now().UTC()
	newExp := now.Add(s.ttl)
	ttlSecs := int64(s.ttl/time.Second) + 1 // +1s grace so the explicit field, not eviction, governs
	res, err := refreshScript.Run(ctx, s.rdb,
		[]string{sessionKey(sessionID)},
		now.UnixMilli(), newExp.UnixMilli(), ttlSecs,
	).Int64()
	if err != nil {
		return nil, fmt.Errorf("redis: refresh session: %w", err)
	}
	if res < 0 {
		return nil, sso.ErrSessionNotFound
	}
	// Re-read the canonical row so created_at + user_id come straight
	// from storage (the script only touched expires_at).
	out, err := s.load(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *SessionManager) ListByUser(ctx context.Context, userID string) ([]*sso.Session, error) {
	ids, err := s.rdb.SMembers(ctx, sessionUserKey(userID)).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: list by user: %w", err)
	}
	return s.collect(ctx, sessionUserKey(userID), ids), nil
}

func (s *SessionManager) ListAll(ctx context.Context) ([]*sso.Session, error) {
	ids, err := s.rdb.SMembers(ctx, sessionAllKey).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: list all: %w", err)
	}
	return s.collect(ctx, sessionAllKey, ids), nil
}

// collect loads each id, dropping (and pruning from the index) any that
// have been TTL-evicted or are revoked/expired — so the index self-trims
// and a stale id never surfaces as a live session.
func (s *SessionManager) collect(ctx context.Context, indexKey string, ids []string) []*sso.Session {
	out := make([]*sso.Session, 0, len(ids))
	for _, id := range ids {
		sess, err := s.load(ctx, id)
		if err != nil {
			// Prune ONLY on a definitive "gone" signal. A transient transport or
			// decode error (e.g. a partially-written hash mid-Create) must NOT
			// remove a possibly-live session from the index — that would
			// permanently hide it from ListByUser/ListAll, so it could never be
			// surfaced or Destroyed via the admin path even though its key still
			// exists. Degrade to a momentarily-incomplete list instead.
			if errors.Is(err, sso.ErrSessionNotFound) {
				_ = s.rdb.SRem(ctx, indexKey, id).Err()
			}
			continue
		}
		if sess.Revoked || sess.IsExpired() {
			_ = s.rdb.SRem(ctx, indexKey, id).Err()
			continue
		}
		out = append(out, sess)
	}
	return out
}

func sessionFromHash(id string, vals map[string]string) (*sso.Session, error) {
	// Timestamps are Unix MILLISECONDS (see Create — ms stays in float64's
	// exact range so the refresh script's tonumber() comparison is precise).
	createdMs, err := strconv.ParseInt(vals["created_at"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("redis: parse created_at: %w", err)
	}
	expiresMs, err := strconv.ParseInt(vals["expires_at"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("redis: parse expires_at: %w", err)
	}
	return &sso.Session{
		ID:        id,
		UserID:    vals["user_id"],
		CreatedAt: time.UnixMilli(createdMs).UTC(),
		ExpiresAt: time.UnixMilli(expiresMs).UTC(),
		Revoked:   vals["revoked"] != "0" && vals["revoked"] != "",
	}, nil
}

func randomSessionID() (string, error) {
	b := make([]byte, sessionIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var _ sso.SessionManager = (*SessionManager)(nil)
