package redis

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// refreshGracePrefix -> the consumed refresh token's successor response, held
// for exactly the rotation-grace window (the key's TTL). One key per token, so
// Set/Get are single-key and inherently cluster-safe (no hash tag needed).
const refreshGracePrefix = "sso:rtgrace:"

func refreshGraceKey(token string) string { return refreshGracePrefix + token }

// refreshGraceOpTimeout bounds each grace op so a stalled Redis can never block
// the refresh request path; the grace check is best-effort and fails closed on
// timeout (no replay -> the caller proceeds to family-reuse detection).
const refreshGraceOpTimeout = 2 * time.Second

// RefreshGraceStore is the Redis-backed, cluster-shared double-submit grace
// store. It structurally satisfies tokengrant.RefreshGraceStore (same method
// set) WITHOUT importing the handler layer, so the dependency direction stays
// downward. The in-process *tokengrant.RefreshGraceCache caches the successor in
// one replica's memory; this stores it in the cluster, so a benign double-submit
// landing on ANY replica replays the same successor instead of tripping a false
// refresh-family reuse kill. The key's TTL IS the grace window: a genuine
// post-window replay finds the key gone and falls through to reuse detection, so
// BCP 4.13 is preserved (fail-closed on miss/expiry/error).
type RefreshGraceStore struct {
	rdb    goredis.Cmdable
	window time.Duration
}

// NewRefreshGraceStore builds the store over an existing go-redis client. window
// is the grace duration (= the key TTL); window <= 0 makes Remember a no-op.
func NewRefreshGraceStore(rdb goredis.Cmdable, window time.Duration) *RefreshGraceStore {
	return &RefreshGraceStore{rdb: rdb, window: window}
}

// Ping reports Redis health for [sso.WithReadyCheck].
func (s *RefreshGraceStore) Ping(ctx context.Context) error {
	if s == nil || s.rdb == nil {
		return errors.New("redis: refresh grace store not initialized")
	}
	return s.rdb.Ping(ctx).Err()
}

// Remember caches resp as the successor for the just-consumed token under the
// grace-window TTL. Best-effort: any marshal/Redis failure degrades to strict
// single-use (a later double-submit then trips reuse) — never weaker. The `now`
// argument is part of the shared interface but unused here: expiry is the key's
// Redis TTL, not a wall-clock comparison.
func (s *RefreshGraceStore) Remember(token string, resp map[string]any, _ time.Time) {
	if s == nil || s.rdb == nil || token == "" || s.window <= 0 {
		return
	}
	blob, err := json.Marshal(resp)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), refreshGraceOpTimeout)
	defer cancel()
	_ = s.rdb.Set(ctx, refreshGraceKey(token), blob, s.window).Err()
}

// Lookup returns the remembered successor for token, or (nil,false) on ANY
// uncertainty — miss, TTL expiry (key gone), backend error, or a decode failure.
// Returning false makes the caller fail closed to family-reuse detection, so a
// Redis hiccup can never cause a replay that masks a genuine token reuse.
func (s *RefreshGraceStore) Lookup(token string, _ time.Time) (map[string]any, bool) {
	if s == nil || s.rdb == nil || token == "" {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), refreshGraceOpTimeout)
	defer cancel()
	blob, err := s.rdb.Get(ctx, refreshGraceKey(token)).Bytes()
	if err != nil {
		return nil, false
	}
	var resp map[string]any
	if err := json.Unmarshal(blob, &resp); err != nil {
		return nil, false
	}
	return resp, true
}
