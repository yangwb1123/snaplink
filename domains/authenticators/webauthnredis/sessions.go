// Package redis provides a Redis-backed [webauthn.SessionStore] so passkey
// ceremony challenges survive the gap between the Begin* and Finish* HTTP
// requests when a no-affinity load balancer routes the two legs to different
// replicas. The memory store on replica A never sees the Finish* that lands on
// replica B, so the in-memory challenge misses and every passkey login or
// registration fails. Routing the challenge through shared Redis closes that
// hole — the same hot/ephemeral split-across-two-requests pattern already used
// for sessions, PAR, CIBA and the MFA challenge.
package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/domains/authenticators/webauthn"

	gw "github.com/go-webauthn/webauthn/webauthn"
	goredis "github.com/redis/go-redis/v9"
)

// sessKeyPrefix namespaces a ceremony session under one key per session
// (sso:webauthn:sess:<sessionID> -> JSON gw.SessionData). One session == one
// key means every operation touches a single key, so the store is inherently
// Redis-Cluster CROSSSLOT-safe: no MULTI/pipeline spans slots and no hash tag
// is needed.
const sessKeyPrefix = "sso:webauthn:sess:"

// SessionStore is the Redis-backed [webauthn.SessionStore]. Cluster-safe by
// construction (see sessKeyPrefix) and multi-replica safe: a challenge minted
// by Begin* on one replica is consumable by Finish* on any replica.
type SessionStore struct {
	rdb goredis.Cmdable
}

// NewSessionStore builds the store over an existing go-redis client. The cmd
// builder passes the shared Redis Cluster client so the hot ceremony state
// lands in the same backend as the other split-across-two-requests stores.
func NewSessionStore(rdb goredis.Cmdable) *SessionStore {
	return &SessionStore{rdb: rdb}
}

// Ping reports Redis health for [sso.WithReadyCheck] wiring. Nil-safe so a
// readiness probe on an unconfigured store reports a clear error rather than
// panicking.
func (s *SessionStore) Ping(ctx context.Context) error {
	if s == nil || s.rdb == nil {
		return errors.New("redis: webauthn session store not initialized")
	}
	return s.rdb.Ping(ctx).Err()
}

func sessKey(sessionID string) string { return sessKeyPrefix + sessionID }

// Put implements [webauthn.SessionStore]: marshal the session to JSON and SET
// it with an expiry of ttl. A non-positive ttl is skipped rather than stored —
// go-redis maps a zero expiration to a key that never expires, and a ceremony
// secret must never outlive its window; refusing the write makes the later
// Finish* miss (ErrSessionUnknown), which is the safe failure for an
// already-invalid TTL.
func (s *SessionStore) Put(ctx context.Context, sessionID string, data *gw.SessionData, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	blob, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("redis: marshal webauthn session: %w", err)
	}
	if err := s.rdb.Set(ctx, sessKey(sessionID), blob, ttl).Err(); err != nil {
		return fmt.Errorf("redis: put webauthn session: %w", err)
	}
	return nil
}

// Take atomically returns + consumes the session via GETDEL — the race-free
// single-use guarantee (Redis analogue of the sqlite peer's DELETE ...
// RETURNING). A repeat call after a prior Take, an ID that was never stored,
// and an entry already evicted by its TTL all surface identically as
// redis.Nil. They map to [webauthn.ErrSessionUnknown]: under Redis, TTL
// eviction deletes the key outright, so an expired session is simply gone and
// is indistinguishable from absent — and the ceremony helper treats unknown
// and expired the same (both fail Finish*), so no separate ErrSessionExpired
// sentinel is reachable here.
func (s *SessionStore) Take(ctx context.Context, sessionID string) (*gw.SessionData, error) {
	blob, err := s.rdb.GetDel(ctx, sessKey(sessionID)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, webauthn.ErrSessionUnknown
	}
	if err != nil {
		return nil, fmt.Errorf("redis: take webauthn session: %w", err)
	}
	var data gw.SessionData
	if err := json.Unmarshal(blob, &data); err != nil {
		return nil, fmt.Errorf("redis: unmarshal webauthn session: %w", err)
	}
	return &data, nil
}

var _ webauthn.SessionStore = (*SessionStore)(nil)
