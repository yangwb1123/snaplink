package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

// Key layout. The active token is a JSON string with a TTL. Three auxiliary
// SETs index it for bulk operations, and a per-token family-membership marker
// carries reuse-detection state.
//
// The marker is written at CONSUME time (NOT Issue): its presence means the
// token was actually rotated away, so a later replay of a consumed token is a
// reuse-after-rotation -> ErrRefreshTokenReused with the family stamped, and the
// handler kills the whole family (OAuth Security BCP §4.13/§4.14). A token that
// is NEVER consumed leaves no marker, so when its active key TTL-evicts at expiry
// its replay is a plain not-found, NOT a spurious family-kill.
//
// This matches the SQLite / memory peers, whose active record persists until
// consumed (a never-consumed token therefore always hits their IsExpired ->
// not-found path) so their reuse ledger only ever fires for a genuinely consumed
// token. The two wrong alternatives both fail: writing the marker at Issue (as
// this store previously did) misclassifies a naturally-expired never-consumed
// token as reuse; keying the marker off the token's own expiry instead MISSES a
// consumed token replayed AFTER expiry — and that family-kill revokes the
// attacker's still-live SIBLING, which outlives the stolen token under sliding
// TTLs. The CONSUME event, not the token's lifetime, is the correct reuse signal.
const (
	rtKeyPrefix        = "sso:rt:"         // sso:rt:<token> -> JSON (active)
	rtFamilyMemPrefix  = "sso:rt:famof:"   // sso:rt:famof:<token> -> family_id (written at CONSUME; reuse detection)
	rtFamilyKeyPrefix  = "sso:rt:family:"  // sso:rt:family:<fid> -> SET of token ids
	rtSubjectKeyPrefix = "sso:rt:subject:" // sso:rt:subject:<uid>\x00<client> -> SET of token ids
	rtClientKeyPrefix  = "sso:rt:client:"  // sso:rt:client:<client> -> SET of token ids
)

// RefreshTokenStore is the Redis-backed implementation of
// [oauth.RefreshTokenStore] plus the optional Inspector / SubjectIndex /
// SubjectCounter / ClientPurger / FamilyTracker extensions — the same
// surface the SQLite peer exposes.
type RefreshTokenStore struct {
	rdb            goredis.Cmdable
	lookupHMACKeys [][]byte
	// familyTTL bounds how long the family-membership marker + family index
	// live past a token's own TTL so reuse detection has a window. Defaults
	// to the longest refresh TTL the operator expects; a marker older than
	// this self-evicts (a replay that old can't redeem anyway).
	familyTTL time.Duration

	// maxRotationsPerWindow + rotationWindow configure the OPTIONAL per-family
	// rotation velocity cap (RefreshTokenRotationLimiter), matching the memory
	// and sqlite peers. BOTH must be > 0 for the cap to engage; either zero
	// disables it (RecordRotation still counts but never reports exceeded). See
	// refresh_token_rotation.go.
	maxRotationsPerWindow int
	rotationWindow        time.Duration
}

// RefreshTokenOption configures the RefreshTokenStore.
type RefreshTokenOption func(*RefreshTokenStore)

// WithFamilyTTL sets how long reuse-detection bookkeeping (the family
// membership marker + family index entries) survives. SHOULD be >= the
// refresh token TTL; longer is better for audit. Default 30 days.
func WithFamilyTTL(ttl time.Duration) RefreshTokenOption {
	return func(s *RefreshTokenStore) { s.familyTTL = ttl }
}

// WithRotationCap enables the per-family rotation velocity cap (anti-abuse):
// more than max rotations of one family within window is reported as exceeded,
// which the handler turns into a family-kill. Mirrors the memory/sqlite peers'
// MaxRotationsPerWindow + RotationWindow fields. Both must be > 0 to engage;
// zero/zero leaves the cap off (the redis peer's prior behaviour).
func WithRotationCap(max int, window time.Duration) RefreshTokenOption {
	return func(s *RefreshTokenStore) {
		s.maxRotationsPerWindow = max
		s.rotationWindow = window
	}
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

// SetLookupHMACKeys enables current-key writes plus previous-key and legacy
// plaintext reads for no-logout rotation.
func (s *RefreshTokenStore) SetLookupHMACKeys(keys ...[]byte) {
	s.lookupHMACKeys = cloneLookupKeys(keys...)
}

// Ping reports Redis health for [sso.WithReadyCheck].
func (s *RefreshTokenStore) Ping(ctx context.Context) error {
	if s == nil || s.rdb == nil {
		return errors.New("redis: refresh token store not initialized")
	}
	return s.rdb.Ping(ctx).Err()
}

func rtKey(t string) string          { return rtKeyPrefix + t }
func rtFamilyMemKey(t string) string { return rtFamilyMemPrefix + t }
func rtFamilyKey(f string) string    { return rtFamilyKeyPrefix + f }
func rtClientKey(c string) string    { return rtClientKeyPrefix + c }

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
	lookup := opaqueLookupKey(firstLookupKey(s.lookupHMACKeys), "refresh_token", token)
	if err := s.rdb.Set(ctx, rtKey(lookup), blob, ttl).Err(); err != nil {
		return fmt.Errorf("redis: insert refresh_token: %w", err)
	}
	// Index for bulk revocation. Index TTL >= token TTL so the index
	// outlives the token; stale ids are pruned lazily on read.
	idxTTL := ttl
	if idxTTL < s.familyTTL {
		idxTTL = s.familyTTL
	}
	s.indexAdd(ctx, rtSubjectKey(info.UserID, info.ClientID), lookup, idxTTL)
	s.indexAdd(ctx, rtClientKey(info.ClientID), lookup, idxTTL)
	if info.FamilyID != "" {
		// Only the family INDEX (for DeleteFamily) is seeded at Issue. The famof
		// reuse-detection marker is deliberately NOT written here — it is written
		// at Consume, so a never-consumed token leaves no marker and its post-expiry
		// replay reads as not-found rather than a spurious family-kill (see Consume).
		s.indexAdd(ctx, rtFamilyKey(info.FamilyID), lookup, s.familyTTL)
	}
	return nil
}

// indexAddScript is the atomic SADD + only-EXTEND EXPIRE. SADD and EXPIRE
// as two separate client ops race: concurrent Issues to the SAME index
// (same subject/client/family) can interleave so a SHORTER Expire lands
// last and wins, GC-ing the index early — DeleteAllForSubject /
// DeleteAllForClient would then MISS still-active tokens whose ids were in
// the prematurely-evicted SET, silently breaking bulk revocation and the
// compliance Eraser. Running both in one server-side script makes them
// atomic, and the TTL is only ever EXTENDED (never shortened) so the index
// always outlives its longest-lived member token. miniredis supports
// SADD/TTL/EXPIRE/EVAL, so this runs identically under test and real Redis.
//
// KEYS[1] = index SET key   ARGV[1] = member   ARGV[2] = ttl seconds
var indexAddScript = goredis.NewScript(`
redis.call('SADD', KEYS[1], ARGV[1])
local cur = redis.call('TTL', KEYS[1])
if cur < 0 or cur < tonumber(ARGV[2]) then
  redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return 1
`)

// indexAdd adds member to a SET index and atomically sets its TTL, only
// ever extending it (never shortening) — see indexAddScript.
func (s *RefreshTokenStore) indexAdd(ctx context.Context, key, member string, ttl time.Duration) {
	ttlSecs := int64(ttl / time.Second)
	if ttlSecs < 1 {
		ttlSecs = 1
	}
	_ = indexAddScript.Run(ctx, s.rdb, []string{key}, member, ttlSecs).Err()
}

func (s *RefreshTokenStore) activeBlob(ctx context.Context, token string, consume bool) ([]byte, string, error) {
	for _, lookup := range opaqueLookupCandidates(s.lookupHMACKeys, "refresh_token", token) {
		var blob []byte
		var err error
		if consume {
			blob, err = s.rdb.GetDel(ctx, rtKey(lookup)).Bytes()
		} else {
			blob, err = s.rdb.Get(ctx, rtKey(lookup)).Bytes()
		}
		if err == nil {
			return blob, lookup, nil
		}
		if !errors.Is(err, goredis.Nil) {
			return nil, "", err
		}
	}
	return nil, "", goredis.Nil
}

func (s *RefreshTokenStore) consumedFamily(ctx context.Context, token string) (string, error) {
	for _, lookup := range opaqueLookupCandidates(s.lookupHMACKeys, "refresh_token", token) {
		familyID, err := s.rdb.Get(ctx, rtFamilyMemKey(lookup)).Result()
		if err == nil {
			return familyID, nil
		}
		if !errors.Is(err, goredis.Nil) {
			return "", err
		}
	}
	return "", goredis.Nil
}

// Consume keeps GETDEL as the atomic single-use gate while trying current,
// previous, then legacy lookup identifiers.
func (s *RefreshTokenStore) Consume(ctx context.Context, token string) (*oauth.RefreshToken, error) {
	blob, lookup, err := s.activeBlob(ctx, token, true)
	if errors.Is(err, goredis.Nil) {
		fid, ferr := s.consumedFamily(ctx, token)
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
	if out.IsExpired() {
		// Expired token was never successfully rotated; do NOT stamp a reuse marker.
		return nil, oauth.ErrRefreshTokenNotFound
	}
	// Successful rotation: record that THIS token was consumed so its later replay
	// is detected as reuse, outliving the token's own TTL by familyTTL. Best-effort
	// (a crash before this Set degrades a later replay to not-found, never to a
	// false single-use win — GETDEL already deleted the key). Empty FamilyID opts
	// out of family tracking.
	if out.FamilyID != "" {
		_ = s.rdb.Set(ctx, rtFamilyMemKey(lookup), out.FamilyID, s.familyTTL).Err()
	}
	return &out, nil
}

// Inspect implements [oauth.RefreshTokenInspector] — non-destructive read.
func (s *RefreshTokenStore) Inspect(ctx context.Context, token string) (*oauth.RefreshToken, error) {
	blob, lookup, err := s.activeBlob(ctx, token, false)
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
		// Opportunistic GC of both the active key and its family-membership
		// marker, mirroring the SQLite peer (which deletes the row + ledger
		// on Inspect expiry) so an expired token can't later surface a stale
		// reuse event. Two single-key DELs (not one multi-key DEL) so the op
		// is Redis-Cluster-safe — the active key and marker hash to different
		// slots; the cleanup needs no cross-key atomicity (both are idempotent).
		_ = s.rdb.Del(ctx, rtKey(lookup)).Err()
		_ = s.rdb.Del(ctx, rtFamilyMemKey(lookup)).Err()
		return nil, oauth.ErrRefreshTokenNotFound
	}
	return &out, nil
}

// Delete implements [oauth.RefreshTokenInspector] — idempotent per RFC
// 7009 §2.2 (unknown token returns nil). Wipes the family-membership marker
// too so an explicit revoke can't later mis-trigger a reuse event on the
// same token.
func (s *RefreshTokenStore) Delete(ctx context.Context, token string) error {
	// Two single-key DELs (not one multi-key DEL): the active key and the
	// family marker hash to different slots, so a combined DEL is a CROSSSLOT
	// error on a real cluster. Revoke is idempotent (RFC 7009 §2.2), so the
	// two deletes need no cross-key atomicity — a retry cleans up either half.
	for _, lookup := range opaqueLookupCandidates(s.lookupHMACKeys, "refresh_token", token) {
		if err := s.rdb.Del(ctx, rtKey(lookup)).Err(); err != nil {
			return fmt.Errorf("redis: delete refresh_token: %w", err)
		}
		if err := s.rdb.Del(ctx, rtFamilyMemKey(lookup)).Err(); err != nil {
			return fmt.Errorf("redis: delete refresh_token family marker: %w", err)
		}
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

// subjectIndexKeysForUser finds every subject index key for a user across all
// clients via a bounded SCAN over the namespaced prefix.
//
// On Redis Cluster the per-(user,client) subject keys are spread across masters
// (they carry no hash-tag), and SCAN is keyless — go-redis routes a plain SCAN
// to ONE random master, so a cross-client revoke-all / erasure (empty clientID)
// would silently miss every token whose subject key lives on another shard. So
// on a *ClusterClient run the SCAN on EVERY master and union the results; a
// single-node client keeps the original single-node SCAN.
func (s *RefreshTokenStore) subjectIndexKeysForUser(ctx context.Context, userID string) ([]string, error) {
	pattern := rtSubjectKeyPrefix + userID + "\x00*"
	if cc, ok := s.rdb.(*goredis.ClusterClient); ok {
		return scanKeysAllMasters(ctx, cc, pattern)
	}
	return scanKeys(ctx, s.rdb, pattern)
}

// scanKeys runs a bounded cursor SCAN for pattern against a single node.
func scanKeys(ctx context.Context, c goredis.Cmdable, pattern string) ([]string, error) {
	var keys []string
	var cursor uint64
	for {
		batch, next, err := c.Scan(ctx, cursor, pattern, 256).Result()
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

// scanKeysAllMasters fans the SCAN across every cluster master (ForEachMaster is
// concurrent, hence the mutex) and unions the per-shard results.
func scanKeysAllMasters(ctx context.Context, cc *goredis.ClusterClient, pattern string) ([]string, error) {
	var (
		mu   sync.Mutex
		keys []string
	)
	err := cc.ForEachMaster(ctx, func(ctx context.Context, node *goredis.Client) error {
		k, serr := scanKeys(ctx, node, pattern)
		if serr != nil {
			return serr
		}
		mu.Lock()
		keys = append(keys, k...)
		mu.Unlock()
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("redis: scan subject index across masters: %w", err)
	}
	return keys, nil
}

// deleteTokensInIndex removes every active token referenced by an index
// SET (plus the SET itself + each token's family-membership marker),
// returning the count of active tokens that actually existed. Wiping the
// marker keeps future presentations of those tokens as vanilla not-found
// rather than stale reuse events (mirrors the SQLite ledger wipe).
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
		_ = s.rdb.Del(ctx, rtFamilyMemKey(t)).Err()
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
// bookkeeping. Returns the count of ACTIVE tokens removed; already-rotated
// tokens (membership marker present, active key gone) are bookkeeping and
// don't add to the count. Idempotent.
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
		_ = s.rdb.Del(ctx, rtFamilyMemKey(t)).Err()
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
