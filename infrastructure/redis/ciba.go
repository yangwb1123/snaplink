package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/protocols/oauth"
)

const cibaKeyPrefix = "sso:ciba:" // sso:ciba:<auth_req_id> -> JSON

// CIBAStore is the Redis-backed [oauth.CIBAStore] for poll-mode
// Client-Initiated Backchannel Authentication (OIDC CIBA Core 1.0). The
// three legs of the flow land on independent replicas: Issue (POST
// /backchannel-authentication), SetStatus (the out-of-band device
// callback), and the client's grant_type=ciba poll on /token. Shared
// Redis lets any replica serve any leg.
type CIBAStore struct {
	rdb goredis.Cmdable
}

// NewCIBAStore builds the store over an existing go-redis client.
func NewCIBAStore(rdb goredis.Cmdable) *CIBAStore {
	return &CIBAStore{rdb: rdb}
}

// Ping reports Redis health for [sso.WithReadyCheck].
func (s *CIBAStore) Ping(ctx context.Context) error {
	if s == nil || s.rdb == nil {
		return errors.New("redis: ciba store not initialized")
	}
	return s.rdb.Ping(ctx).Err()
}

func cibaKey(authReqID string) string { return cibaKeyPrefix + authReqID }

// Issue mints an auth_req_id, persists a PENDING request as JSON with a
// TTL from its own expiry (so an unconfirmed request self-evicts → poll
// sees expired_token), and returns the id. SubjectID + ClientID required;
// either empty → ErrCIBARequestInvalid.
func (s *CIBAStore) Issue(ctx context.Context, req *oauth.CIBARequest) (string, error) {
	if req == nil || req.SubjectID == "" || req.ClientID == "" {
		return "", oauth.ErrCIBARequestInvalid
	}
	id, err := defaultimpl.GenerateCIBAAuthReqID()
	if err != nil {
		return "", err
	}
	// Normalize the persisted record so Get round-trips the same shape
	// the SQLite peer does (status pending, id stamped).
	rec := *req
	rec.AuthReqID = id
	rec.Status = oauth.CIBAPending
	// Normalize empty-non-nil slices to nil so json.Marshal emits `null`, not
	// `[]`. SetStatus / UpdateLastPoll re-encode this record via lua-cjson, and
	// REAL Redis cjson rewrites an empty JSON array `[]` to an empty object `{}`
	// — which then fails json.Unmarshal back into []string on the next Get,
	// permanently killing the request (the poll maps the error to expired_token)
	// even after a valid out-of-band approval. `null` round-trips safely. This
	// is the load-bearing guard: miniredis's cjson encodes empty tables as `[]`,
	// so unit tests CANNOT observe the real-Redis corruption — keep it here.
	if len(rec.Resources) == 0 {
		rec.Resources = nil
	}
	if len(rec.Scopes) == 0 {
		rec.Scopes = nil
	}
	blob, err := json.Marshal(&rec)
	if err != nil {
		return "", fmt.Errorf("redis: marshal ciba_request: %w", err)
	}
	ttl := time.Until(req.ExpiresAt)
	if ttl <= 0 {
		ttl = oauth.DefaultCIBARequestTTL
	}
	if err := s.rdb.Set(ctx, cibaKey(id), blob, ttl).Err(); err != nil {
		return "", fmt.Errorf("redis: insert ciba_request: %w", err)
	}
	return id, nil
}

// Get returns the current request. Missing / TTL-evicted / just-expired
// all collapse to ErrCIBARequestNotFound (§2 anti-enumeration: the /token
// poll maps it to expired_token, so a poller can't tell "unknown" from
// "expired"). A just-expired record is opportunistically GCed.
func (s *CIBAStore) Get(ctx context.Context, authReqID string) (*oauth.CIBARequest, error) {
	if authReqID == "" {
		return nil, oauth.ErrCIBARequestNotFound
	}
	blob, err := s.rdb.Get(ctx, cibaKey(authReqID)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, oauth.ErrCIBARequestNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("redis: get ciba_request: %w", err)
	}
	var out oauth.CIBARequest
	if err := json.Unmarshal(blob, &out); err != nil {
		return nil, fmt.Errorf("redis: unmarshal ciba_request: %w", err)
	}
	if out.IsExpired() {
		_ = s.rdb.Del(ctx, cibaKey(authReqID)).Err()
		return nil, oauth.ErrCIBARequestNotFound
	}
	return &out, nil
}

// setStatusScript atomically reads the record, enforces the
// pending-only transition guard, and rewrites it KEEPTTL. The SQLite peer
// uses UPDATE ... WHERE status='pending' for the same race-free
// re-resolution guard; here the read-check-write must run as one
// server-side unit so two racing device callbacks (or a callback racing a
// legitimate poll) cannot both flip a pending request. Returns a result
// code the caller maps to the SPI's error contract:
//
//	0 = not found (key absent)
//	1 = transitioned pending -> new status (or no-op same status)
//	2 = already resolved to a DIFFERENT terminal status
//
// KEYS[1] = ciba key   ARGV[1] = new status string
var setStatusScript = goredis.NewScript(`
local blob = redis.call('GET', KEYS[1])
if not blob then
  return 0
end
local rec = cjson.decode(blob)
local cur = rec['Status']
local want = ARGV[1]
if cur == want then
  return 1
end
if cur ~= 'pending' then
  return 2
end
rec['Status'] = want
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return 1
`)

// SetStatus advances Pending -> terminal atomically (see
// setStatusScript). Same-status is an idempotent no-op; an
// already-resolved request rejects a different transition with
// ErrCIBARequestResolved; a missing / expired entry returns
// ErrCIBARequestNotFound. Wired by the operator's device-callback
// handler.
//
// An expired-but-not-yet-evicted record is caught by a pre-Get: the
// script keys off the raw JSON and has no clock, so the Get's expiry
// check is what enforces the TTL boundary on this path.
func (s *CIBAStore) SetStatus(ctx context.Context, authReqID string, status oauth.CIBAStatus) error {
	if authReqID == "" {
		return oauth.ErrCIBARequestNotFound
	}
	// Expiry boundary is clock-based; the Lua script has no time source,
	// so check + GC an expired record here before the atomic transition.
	if _, err := s.Get(ctx, authReqID); err != nil {
		return err
	}
	res, err := setStatusScript.Run(ctx, s.rdb, []string{cibaKey(authReqID)}, string(status)).Int()
	if err != nil {
		return fmt.Errorf("redis: set ciba_request status: %w", err)
	}
	switch res {
	case 0:
		return oauth.ErrCIBARequestNotFound
	case 2:
		return oauth.ErrCIBARequestResolved
	default:
		return nil
	}
}

// updateLastPollScript atomically sets ONLY the LastPoll field of the canonical
// record in one server-side op (mirrors setStatusScript's cjson round-trip).
// Returns 0 if the key is absent (expired/unknown -> no-op), 1 on update.
var updateLastPollScript = goredis.NewScript(`
local blob = redis.call('GET', KEYS[1])
if not blob then
  return 0
end
local rec = cjson.decode(blob)
rec['LastPoll'] = ARGV[1]
redis.call('SET', KEYS[1], cjson.encode(rec), 'KEEPTTL')
return 1
`)

// UpdateLastPoll records the most recent poll for slow_down enforcement,
// preserving the record's remaining TTL. It MUST be atomic: the device-approval
// callback flips Status on the SAME record via the atomic setStatusScript, and a
// non-atomic Get->mutate->Set here would clobber a concurrent SetStatus(approved)
// back to pending — silently losing the auth decision so the grant never
// completes (the out-of-band approval already returned success while the client
// keeps getting authorization_pending until expiry). So mutate only LastPoll
// server-side in one indivisible Lua op. Missing / expired -> no-op success. The
// time string round-trips Go's RFC3339Nano time.Time encoding through cjson,
// exactly as setStatusScript already round-trips the whole record.
func (s *CIBAStore) UpdateLastPoll(ctx context.Context, authReqID string, t time.Time) error {
	if err := updateLastPollScript.Run(ctx, s.rdb, []string{cibaKey(authReqID)}, t.Format(time.RFC3339Nano)).Err(); err != nil {
		return fmt.Errorf("redis: update ciba_request last_poll: %w", err)
	}
	return nil
}

// Delete drops the entry. Idempotent — a missing id is a no-op success.
func (s *CIBAStore) Delete(ctx context.Context, authReqID string) error {
	if authReqID == "" {
		return nil
	}
	if err := s.rdb.Del(ctx, cibaKey(authReqID)).Err(); err != nil {
		return fmt.Errorf("redis: delete ciba_request: %w", err)
	}
	return nil
}

// cibaConsumeIfApprovedScript atomically claims an APPROVED request in one
// server-side op: GET the record, and only when its Status is 'approved' DEL the
// key and return the ORIGINAL blob; otherwise return false (missing / pending /
// denied / undecodable). Single key (the auth_req_id) -> cluster-slot safe.
//
// It echoes the stored blob `v` verbatim rather than cjson.encode(obj). The
// empty-array corruption (real-Redis lua-cjson rewrites an empty JSON array `[]`
// to `{}`, which then fails json.Unmarshal back into []string) is already
// prevented upstream: Issue nil-normalizes empty Scopes/Resources so no `[]` is
// ever stored to be mangled (the approved blob this returns was last written by
// SetStatus's cjson round-trip, so `v` is not strictly Go-marshaled bytes —
// echoing it just avoids one redundant re-encode on the claim path). Mirrors the
// device-code consume script.
//
// KEYS[1] = ciba key
var cibaConsumeIfApprovedScript = goredis.NewScript(`
local v = redis.call('GET', KEYS[1])
if not v then return false end
local ok, obj = pcall(cjson.decode, v)
if not ok then return false end
if obj['Status'] == 'approved' then
  redis.call('DEL', KEYS[1])
  return v
end
return false
`)

// ConsumeIfApproved atomically deletes + returns the request iff approved (the
// Lua runs as one indivisible server-side op, so of N concurrent polls exactly
// one wins the blob). A pending/denied/unknown/expired request -> the script
// returns false -> ErrCIBARequestNotFound. A just-expired (but not TTL-evicted)
// record is caught by the post-decode IsExpired check.
func (s *CIBAStore) ConsumeIfApproved(ctx context.Context, authReqID string) (*oauth.CIBARequest, error) {
	if authReqID == "" {
		return nil, oauth.ErrCIBARequestNotFound
	}
	res, err := cibaConsumeIfApprovedScript.Run(ctx, s.rdb, []string{cibaKey(authReqID)}).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, oauth.ErrCIBARequestNotFound // script returned false/nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis: consume_if_approved ciba_request: %w", err)
	}
	blob, ok := res.(string)
	if !ok {
		return nil, oauth.ErrCIBARequestNotFound
	}
	var out oauth.CIBARequest
	if err := json.Unmarshal([]byte(blob), &out); err != nil {
		return nil, fmt.Errorf("redis: unmarshal ciba_request: %w", err)
	}
	if out.IsExpired() {
		return nil, oauth.ErrCIBARequestNotFound
	}
	return &out, nil
}

var _ oauth.CIBAStore = (*CIBAStore)(nil)
