package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/snaplink/sso/oauth"
)

// Key layout. The active token is a JSON string with a TTL. Three
// auxiliary SETs index it for bulk operations, and a per-token consumed
// marker preserves the family link after the active key is deleted so a
// presented-after-rotation token can be recognized as a replay (OAuth
// Security BCP §4.13/§4.14) — the Redis analogue of SQLite's
// refresh_token_families ledger.
const (
	rtKeyPrefix         = "sso:rt:"          // sso:rt:<token> -> JSON (active)
	rtConsumedKeyPrefix = "sso:rt:consumed:" // sso:rt:consumed:<token> -> family_id (post-rotation marker)
	rtFamilyKeyPrefix   = "sso:rt:family:"   // sso:rt:family:<fid> -> SET of token ids
	rtSubjectKeyPrefix  = "sso:rt:subject:"  // sso:rt:subject:<uid>\x00<client> -> SET of token ids
	rtClientKeyPrefix   = "sso:rt:client:"   // sso:rt:client:<client> -> SET of token ids
)

// RefreshTokenStore is the Redis-backed implementation of
// [oauth.RefreshTokenStore] plus the optional Inspector / SubjectIndex /
// SubjectCounter / ClientPurger / FamilyTracker extensions — the same
// surface the SQLite peer exposes.
type RefreshTokenStore struct {
	rdb goredis.Cmdable
	// familyTTL bounds how long the consumed-marker + family index live
	// past a token's own TTL so reuse detection has a window. Defaults to
	// the longest refresh TTL the operator expects; a marker older than
	// this self-evicts (a replay that old can't redeem anyway).
	familyTTL time.Duration
}

// RefreshTokenOption configures the RefreshTokenStore.
type RefreshTokenOption func(*RefreshTokenStore)

// WithFamilyTTL sets how long reuse-detection bookkeeping (the consumed
// marker + family index entries) survives. SHOULD be >= the refresh
// token TTL; longer is better for audit. Default 30 days.
func WithFamilyTTL(ttl time.Duration) RefreshTokenOption {
	return func(s *RefreshTokenStore) { s.familyTTL = ttl }
}

// NewRefreshTokenStore builds the store over an existing go-redis client.
func NewRefreshTokenStore(rdb goredis.Cmdable, opts ...RefreshTokenOption) *RefreshTokenStore {
	s := &RefreshTokenStore{rdb: rdb, familyTTL: 30 * 24 * time.Hour}
	for _, o := range opts {
		o(s)
	}
	if s.familyTTL <= 0 {
		s.familyTTL = 30 * 24 * time.Hour
	}
	return s
}

// Ping reports Redis health for [sso.WithReadyCheck].
func (s *RefreshTokenStore) Ping(ctx context.Context) error {
	if s == nil || s.rdb == nil {
		return errors.New("redis: refresh token store not initialized")
	}
	return s.rdb.Ping(ctx).Err()
}

func rtKey(t string) string         { return rtKeyPrefix + t }
func rtConsumedKey(t string) string { return rtConsumedKeyPrefix + t }
func rtFamilyKey(f string) string   { return rtFamilyKeyPrefix + f }
func rtClientKey(c string) string   { return rtClientKeyPrefix + c }

// rtSubjectKey joins user + client with a NUL so two distinct (uid,
// client) pairs can never collide via concatenation.
func rtSubjectKey(uid, client string) string {
	return rtSubjectKeyPrefix + uid + "\x00" + client
}

// Issue persists the active token as JSON with a TTL from its own expiry,
// and registers it in the subject + client indexes. When FamilyID is set
// it also seeds the family SET (so a future DeleteFamily can find every
// member) — empty FamilyID opts out of family tracking entirely, exactly
// as the SQLite peer does.
func (s *RefreshTokenStore) Issue(ctx context.Context, token string, info *oauth.RefreshToken) error {
	if token == "" || info == nil {
		return oauth.ErrRefreshTokenNotFound
	}
	blob, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("redis: marshal refresh_token: %w", err)
	}
	ttl := time.Until(info.ExpiresAt)
	if ttl <= 0 {
		// Already expired; do not persist a no-TTL key.
		return nil
	}
	if err := s.rdb.Set(ctx, rtKey(token), blob, ttl).Err(); err != nil {
		return fmt.Errorf("redis: insert refresh_token: %w", err)
	}
	// Index for bulk revocation. Index TTL >= token TTL so the index
	// outlives the token; stale ids are pruned lazily on read.
	idxTTL := ttl
	if idxTTL < s.familyTTL {
		idxTTL = s.familyTTL
	}
	s.indexAdd(ctx, rtSubjectKey(info.UserID, info.ClientID), token, idxTTL)
	s.indexAdd(ctx, rtClientKey(info.ClientID), token, idxTTL)
	if info.FamilyID != "" {
		s.indexAdd(ctx, rtFamilyKey(info.FamilyID), token, s.familyTTL)
	}
	return nil
}

// indexAdd adds member to a SET index and (re)sets its TTL so the index
// can't outlive its usefulness unboundedly.
func (s *RefreshTokenStore) indexAdd(ctx context.Context, key, member string, ttl time.Duration) {
	_ = s.rdb.SAdd(ctx, key, member).Err()
	_ = s.rdb.Expire(ctx, key, ttl).Err()
}

// Consume atomically removes + returns the active token via GETDEL — one
// server-side get-and-delete (Redis 6.2+), the analogue of SQLite's
// DELETE ... RETURNING. The DEL is the single-use gate: a second Consume
// of the same token finds the active key gone and so cannot succeed,
// race-free regardless of concurrency.
//
// On a miss it consults the consumed marker: a token known there but not
// active is a reuse-after-rotation — return ErrRefreshTokenReused with the
// FamilyID stamped so the handler kills the whole family (BCP §4.13).
// Unknown / expired / already-consumed-without-a-family all collapse to
// ErrRefreshTokenNotFound (oracle-resistance §2).
//
// The consumed marker is written AFTER the atomic GETDEL, from the
// family_id we just decoded (the value carries it, so it can't be known
// before the read). This ordering is safe: the GETDEL already enforces
// single-use, so even a crash between the delete and the marker write only
// weakens reuse detection on THIS token to "vanilla invalid_grant" — it
// can never let a second redeem through.
func (s *RefreshTokenStore) Consume(ctx context.Context, token string) (*oauth.RefreshToken, error) {
	blob, err := s.rdb.GetDel(ctx, rtKey(token)).Bytes()
	if errors.Is(err, goredis.Nil) {
		// Active key gone — reuse-detection path.
		fid, ferr := s.rdb.Get(ctx, rtConsumedKey(token)).Result()
		if errors.Is(ferr, goredis.Nil) {
			return nil, oauth.ErrRefreshTokenNotFound
		}
		if ferr != nil {
			return nil, fmt.Errorf("redis: family lookup: %w", ferr)
		}
		return &oauth.RefreshToken{FamilyID: fid}, oauth.ErrRefreshTokenReused
	}
	if err != nil {
		return nil, fmt.Errorf("redis: consume refresh_token: %w", err)
	}
	var out oauth.RefreshToken
	if err := json.Unmarshal(blob, &out); err != nil {
		return nil, fmt.Errorf("redis: unmarshal refresh_token: %w", err)
	}
	// Stamp the consumed marker so a later replay of THIS token is caught
	// as reuse. Empty FamilyID = caller opted out of family tracking; skip
	// the marker (a replay then degrades to vanilla not-found, the
	// documented opt-out, identical to the SQLite peer).
	if out.FamilyID != "" {
		_ = s.rdb.Set(ctx, rtConsumedKey(token), out.FamilyID, s.familyTTL).Err()
	}
	if out.IsExpired() {
		return nil, oauth.ErrRefreshTokenNotFound
	}
	return &out, nil
}

// Inspect implements [oauth.RefreshTokenInspector] — non-destructive read.
func (s *RefreshTokenStore) Inspect(ctx context.Context, token string) (*oauth.RefreshToken, error) {
	blob, err := s.rdb.Get(ctx, rtKey(token)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, oauth.ErrRefreshTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("redis: inspect refresh_token: %w", err)
	}
	var out oauth.RefreshToken
	if err := json.Unmarshal(blob, &out); err != nil {
		return nil, fmt.Errorf("redis: unmarshal refresh_token: %w", err)
	}
	if out.IsExpired() {
		_ = s.rdb.Del(ctx, rtKey(token)).Err()
		return nil, oauth.ErrRefreshTokenNotFound
	}
	return &out, nil
}

// Delete implements [oauth.RefreshTokenInspector] — idempotent per RFC
// 7009 §2.2 (unknown token returns nil). Wipes the consumed marker too so
// an explicit revoke can't later mis-trigger a reuse event on the same
// token.
func (s *RefreshTokenStore) Delete(ctx context.Context, token string) error {
	if err := s.rdb.Del(ctx, rtKey(token), rtConsumedKey(token)).Err(); err != nil {
		return fmt.Errorf("redis: delete refresh_token: %w", err)
	}
	return nil
}

// DeleteAllForSubject implements [oauth.RefreshTokenSubjectIndex]. Empty
// clientID = every client the user has tokens for. Returns the count of
// ACTIVE tokens removed.
func (s *RefreshTokenStore) DeleteAllForSubject(ctx context.Context, userID, clientID string) (int, error) {
	if userID == "" {
		return 0, nil
	}
	var keys []string
	if clientID == "" {
		// Scan every per-(user,client) subject index for this user.
		var err error
		keys, err = s.subjectIndexKeysForUser(ctx, userID)
		if err != nil {
			return 0, err
		}
	} else {
		keys = []string{rtSubjectKey(userID, clientID)}
	}
	deleted := 0
	for _, k := range keys {
		n, err := s.deleteTokensInIndex(ctx, k)
		if err != nil {
			return deleted, err
		}
		deleted += n
	}
	return deleted, nil
}

// subjectIndexKeysForUser finds every subject index key for a user across
// all clients via a bounded SCAN over the namespaced prefix.
func (s *RefreshTokenStore) subjectIndexKeysForUser(ctx context.Context, userID string) ([]string, error) {
	pattern := rtSubjectKeyPrefix + userID + "\x00*"
	var keys []string
	var cursor uint64
	for {
		batch, next, err := s.rdb.Scan(ctx, cursor, pattern, 256).Result()
		if err != nil {
			return nil, fmt.Errorf("redis: scan subject index: %w", err)
		}
		keys = append(keys, batch...)
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return keys, nil
}

// deleteTokensInIndex removes every active token referenced by an index
// SET (plus the SET itself + each token's consumed marker), returning the
// count of active tokens that actually existed.
func (s *RefreshTokenStore) deleteTokensInIndex(ctx context.Context, indexKey string) (int, error) {
	tokens, err := s.rdb.SMembers(ctx, indexKey).Result()
	if err != nil {
		return 0, fmt.Errorf("redis: read index: %w", err)
	}
	deleted := 0
	for _, t := range tokens {
		n, err := s.rdb.Del(ctx, rtKey(t)).Result()
		if err != nil {
			return deleted, fmt.Errorf("redis: delete token: %w", err)
		}
		deleted += int(n)
		_ = s.rdb.Del(ctx, rtConsumedKey(t)).Err()
	}
	_ = s.rdb.Del(ctx, indexKey).Err()
	return deleted, nil
}

// CountForSubject implements [oauth.RefreshTokenSubjectCounter] — counts
// the subject's ACTIVE tokens without deleting them (erasure dry-run).
func (s *RefreshTokenStore) CountForSubject(ctx context.Context, userID, clientID string) (int, error) {
	if userID == "" {
		return 0, nil
	}
	var keys []string
	if clientID == "" {
		var err error
		keys, err = s.subjectIndexKeysForUser(ctx, userID)
		if err != nil {
			return 0, err
		}
	} else {
		keys = []string{rtSubjectKey(userID, clientID)}
	}
	count := 0
	for _, k := range keys {
		tokens, err := s.rdb.SMembers(ctx, k).Result()
		if err != nil {
			return 0, fmt.Errorf("redis: count subject index: %w", err)
		}
		for _, t := range tokens {
			n, err := s.rdb.Exists(ctx, rtKey(t)).Result()
			if err != nil {
				return 0, fmt.Errorf("redis: count exists: %w", err)
			}
			count += int(n)
		}
	}
	return count, nil
}

// DeleteAllForClient implements [oauth.RefreshTokenClientPurger] — removes
// every active token bound to clientID across all subjects. Empty clientID
// is a no-op (a blank client is not a wildcard — wiping the store on an
// empty argument would be a footgun).
func (s *RefreshTokenStore) DeleteAllForClient(ctx context.Context, clientID string) (int, error) {
	if clientID == "" {
		return 0, nil
	}
	return s.deleteTokensInIndex(ctx, rtClientKey(clientID))
}

// DeleteFamily implements [oauth.RefreshTokenFamilyTracker] — kills every
// active token sharing the FamilyID and wipes its reuse-detection
// bookkeeping. Returns the count of ACTIVE tokens removed; consumed-only
// markers are bookkeeping and don't add to the count. Idempotent.
func (s *RefreshTokenStore) DeleteFamily(ctx context.Context, familyID string) (int, error) {
	if familyID == "" {
		return 0, nil
	}
	tokens, err := s.rdb.SMembers(ctx, rtFamilyKey(familyID)).Result()
	if err != nil {
		return 0, fmt.Errorf("redis: read family: %w", err)
	}
	deleted := 0
	for _, t := range tokens {
		n, err := s.rdb.Del(ctx, rtKey(t)).Result()
		if err != nil {
			return deleted, fmt.Errorf("redis: delete family token: %w", err)
		}
		deleted += int(n)
		_ = s.rdb.Del(ctx, rtConsumedKey(t)).Err()
	}
	_ = s.rdb.Del(ctx, rtFamilyKey(familyID)).Err()
	return deleted, nil
}

var (
	_ oauth.RefreshTokenStore          = (*RefreshTokenStore)(nil)
	_ oauth.RefreshTokenInspector      = (*RefreshTokenStore)(nil)
	_ oauth.RefreshTokenSubjectIndex   = (*RefreshTokenStore)(nil)
	_ oauth.RefreshTokenSubjectCounter = (*RefreshTokenStore)(nil)
	_ oauth.RefreshTokenClientPurger   = (*RefreshTokenStore)(nil)
	_ oauth.RefreshTokenFamilyTracker  = (*RefreshTokenStore)(nil)
)
