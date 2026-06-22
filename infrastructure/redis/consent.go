package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	goredis "github.com/redis/go-redis/v9"
	"github.com/snaplink/sso/interfaces/sso"
)

// Key layout. The grant JSON lives at one key per (user, client) pair; a
// per-user SET of client ids indexes them so ListByUser resolves without a
// SCAN. The SET is the Redis analogue of the SQLite peer's idx_consent_grants_
// user_id index: RecordConsent SADDs the client id, RevokeConsent SREMs it.
const (
	consentKeyPrefix  = "sso:consent:"      // sso:consent:<userID>:<clientID> -> grant JSON
	consentUserPrefix = "sso:consent:user:" // sso:consent:user:<userID>       -> SET of clientIDs
)

// ConsentStore is the Redis-backed [sso.ConsentStore]. It is the durable scale
// peer for the GetConsent every /auth/login performs when consent is enabled,
// so a multi-replica fleet shares one consent record set instead of each
// replica holding its own embedded copy. Semantics match the memory + SQLite
// peers: RecordConsent upserts (replacing the prior grant for the pair) and
// normalizes scopes to a sorted, deduplicated slice; ListByUser returns
// descending GrantedAt order.
type ConsentStore struct {
	rdb goredis.Cmdable
}

// NewConsentStore builds a ConsentStore over an existing go-redis client (or
// cluster client — any goredis.Cmdable). The caller owns the client lifecycle.
func NewConsentStore(rdb goredis.Cmdable) *ConsentStore {
	return &ConsentStore{rdb: rdb}
}

// Ping reports Redis connection health for [sso.WithReadyCheck] wiring.
func (s *ConsentStore) Ping(ctx context.Context) error {
	return s.rdb.Ping(ctx).Err()
}

func consentGrantKey(userID, clientID string) string {
	return consentKeyPrefix + userID + ":" + clientID
}

func consentUserKey(userID string) string { return consentUserPrefix + userID }

// RecordConsent upserts the grant for (userID, clientID), normalizing the scope
// list to a sorted, deduplicated slice (matching the memory + SQLite peers).
func (s *ConsentStore) RecordConsent(ctx context.Context, grant sso.ConsentGrant) error {
	grant.Scopes = normalizeConsentScopes(grant.Scopes)
	raw, err := json.Marshal(grant)
	if err != nil {
		return fmt.Errorf("redis: encode consent grant: %w", err)
	}
	if err := s.rdb.Set(ctx, consentGrantKey(grant.UserID, grant.ClientID), raw, 0).Err(); err != nil {
		return fmt.Errorf("redis: put consent grant: %w", err)
	}
	if err := s.rdb.SAdd(ctx, consentUserKey(grant.UserID), grant.ClientID).Err(); err != nil {
		return fmt.Errorf("redis: index consent grant: %w", err)
	}
	return nil
}

// GetConsent returns the stored grant for (userID, clientID), or
// ErrNoConsentGrant when none exists.
func (s *ConsentStore) GetConsent(ctx context.Context, userID, clientID string) (sso.ConsentGrant, error) {
	raw, err := s.rdb.Get(ctx, consentGrantKey(userID, clientID)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return sso.ConsentGrant{}, sso.ErrNoConsentGrant
	}
	if err != nil {
		return sso.ConsentGrant{}, fmt.Errorf("redis: get consent grant: %w", err)
	}
	var g sso.ConsentGrant
	if err := json.Unmarshal(raw, &g); err != nil {
		return sso.ConsentGrant{}, fmt.Errorf("redis: decode consent grant: %w", err)
	}
	return g, nil
}

// RevokeConsent removes the grant for (userID, clientID). Idempotent: a missing
// grant is a no-op so the self-service portal's revoke is safe to retry.
func (s *ConsentStore) RevokeConsent(ctx context.Context, userID, clientID string) error {
	if err := s.rdb.Del(ctx, consentGrantKey(userID, clientID)).Err(); err != nil {
		return fmt.Errorf("redis: delete consent grant: %w", err)
	}
	return s.rdb.SRem(ctx, consentUserKey(userID), clientID).Err()
}

// ListByUser returns all grants for userID in descending GrantedAt order.
// Returns an empty slice (not an error) when none exist.
func (s *ConsentStore) ListByUser(ctx context.Context, userID string) ([]sso.ConsentGrant, error) {
	clientIDs, err := s.rdb.SMembers(ctx, consentUserKey(userID)).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: list consent client ids: %w", err)
	}
	if len(clientIDs) == 0 {
		return []sso.ConsentGrant{}, nil
	}
	keys := make([]string, len(clientIDs))
	for i, cid := range clientIDs {
		keys[i] = consentGrantKey(userID, cid)
	}
	// Per-key GET pipeline, not MGET: a user's grant keys can span hash slots,
	// so a single MGET is a CROSSSLOT error on a real cluster. mgetCompat
	// returns the same positional []any (nil for misses) as MGET.
	vals, err := mgetCompat(ctx, s.rdb, keys)
	if err != nil {
		return nil, fmt.Errorf("redis: mget consent grants: %w", err)
	}
	out := make([]sso.ConsentGrant, 0, len(vals))
	for _, v := range vals {
		// A nil entry is an orphan index id whose grant key expired/was removed
		// out of band — skip rather than fail the whole list.
		str, ok := v.(string)
		if !ok {
			continue
		}
		var g sso.ConsentGrant
		if err := json.Unmarshal([]byte(str), &g); err != nil {
			return nil, fmt.Errorf("redis: decode consent grant in list: %w", err)
		}
		out = append(out, g)
	}
	// Descending GrantedAt (most recent first) for stable output — the SET has
	// no ordering, so sort after load (matches the memory peer).
	sort.Slice(out, func(i, j int) bool {
		return out[i].GrantedAt.After(out[j].GrantedAt)
	})
	return out, nil
}

// normalizeConsentScopes deduplicates and sorts a scope slice so the stored
// representation is canonical regardless of caller order, matching the memory
// peer's normalizeScopes.
func normalizeConsentScopes(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, sc := range in {
		if _, ok := seen[sc]; !ok {
			seen[sc] = struct{}{}
			out = append(out, sc)
		}
	}
	sort.Strings(out)
	return out
}

var _ sso.ConsentStore = (*ConsentStore)(nil)
