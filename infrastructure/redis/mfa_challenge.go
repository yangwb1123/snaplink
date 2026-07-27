package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/shared/spi"
)

const mfaChallengeKeyPrefix = "sso:mfachallenge:" // sso:mfachallenge:<id> -> JSON

// MFAChallengeStore is the Redis-backed [spi.MFAChallengeStore]. The
// two-leg MFA step-up (/auth/login returns mfa_required + a challenge id,
// the client POSTs /auth/mfa to complete) survives a load balancer with
// no session affinity: the challenge issued by the replica that handled
// /auth/login is consumable by whichever replica the /auth/mfa POST hits.
type MFAChallengeStore struct {
	rdb goredis.Cmdable
}

// NewMFAChallengeStore builds the store over an existing go-redis client.
func NewMFAChallengeStore(rdb goredis.Cmdable) *MFAChallengeStore {
	return &MFAChallengeStore{rdb: rdb}
}

// Ping reports Redis health for [sso.WithReadyCheck].
func (s *MFAChallengeStore) Ping(ctx context.Context) error {
	if s == nil || s.rdb == nil {
		return errors.New("redis: mfa challenge store not initialized")
	}
	return s.rdb.Ping(ctx).Err()
}

func mfaChallengeKey(id string) string { return mfaChallengeKeyPrefix + id }

// Put persists a freshly-issued challenge as JSON with a TTL from its own
// expiry, so an un-consumed challenge self-evicts at the expiry boundary.
// Caller MUST set ID + ExpiresAt (default-TTL policy lives in the SSO
// server, keeping the backends schema-flat — same contract as the SQLite
// peer).
func (s *MFAChallengeStore) Put(ctx context.Context, c *spi.MFAChallenge) error {
	if c == nil || c.ID == "" {
		return spi.ErrMFAChallengeNotFound
	}
	blob, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("redis: marshal mfa_challenge: %w", err)
	}
	ttl := time.Until(c.ExpiresAt)
	if ttl <= 0 {
		// Already expired; a non-positive TTL persists forever. No-op
		// success — Consume would reject it as expired anyway.
		return nil
	}
	if err := s.rdb.Set(ctx, mfaChallengeKey(c.ID), blob, ttl).Err(); err != nil {
		return fmt.Errorf("redis: insert mfa_challenge: %w", err)
	}
	return nil
}

// Consume atomically returns + deletes the challenge via GETDEL — one
// server-side get-and-delete (Redis 6.2+), the analogue of SQLite's
// DELETE ... RETURNING. A second Consume of the same id finds nothing, so
// single-use is race-free even under concurrent /auth/mfa POSTs racing on
// one challenge. Missing / TTL-evicted / already-consumed / just-expired
// ALL collapse to ErrMFAChallengeNotFound — the §2 mfa_invalid oracle
// pattern: the SSO server returns one 400 mfa_invalid for every case so a
// probe can't tell "wrong/unknown id" from "expired" from "replayed".
func (s *MFAChallengeStore) Consume(ctx context.Context, id string) (*spi.MFAChallenge, error) {
	if id == "" {
		return nil, spi.ErrMFAChallengeNotFound
	}
	blob, err := s.rdb.GetDel(ctx, mfaChallengeKey(id)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, spi.ErrMFAChallengeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("redis: consume mfa_challenge: %w", err)
	}
	var out spi.MFAChallenge
	if err := json.Unmarshal(blob, &out); err != nil {
		return nil, fmt.Errorf("redis: unmarshal mfa_challenge: %w", err)
	}
	// Defense in depth against TTL eviction lag: the row is already
	// deleted (GETDEL), so we never restore it — collapsing missing +
	// expired to the same not-found result is sufficient for both
	// single-use and the expiry boundary, exactly like the SQLite peer.
	if time.Since(out.ExpiresAt) > 0 {
		return nil, spi.ErrMFAChallengeNotFound
	}
	return &out, nil
}

var _ spi.MFAChallengeStore = (*MFAChallengeStore)(nil)
