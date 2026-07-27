package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

const (
	// sso:devicecode:<device_code> -> JSON record (canonical).
	deviceCodeKeyPrefix = "sso:devicecode:"
	// sso:usercode:<user_code> -> device_code (pointer to the canonical
	// record). The RFC 8628 flow queries by BOTH device_code (poll path)
	// and user_code (the user-facing /device/verify path); Redis has no
	// secondary index, so the user_code key is a thin pointer that both
	// lookups dereference into the same record. Both keys carry the SAME
	// TTL (the code's expiry), so they evict together — no dangling
	// pointer outlives its record.
	userCodeKeyPrefix = "sso:usercode:"
	// sso:devicecode:lastpoll:<device_code> -> unix-nanos of the most recent
	// poll. LastPoll lives in its OWN key (not the canonical JSON record) so
	// the device's high-frequency poll loop (UpdateLastPoll) never rewrites
	// the record the user's one-shot browser Approve/Deny owns. A whole-record
	// read-modify-write on the same key would otherwise let a poll whose read
	// predates Approve clobber Approved=true back to false on a real cluster
	// (poll and approve served by different replicas, no in-process
	// serialization). Carries the code's remaining TTL so it evicts with it.
	lastPollKeyPrefix = "sso:devicecode:lastpoll:"
)

// DeviceCodeStore is the Redis-backed [oauth.DeviceCodeStore] for the
// multi-replica device-authorization flow (RFC 8628): a code issued on
// the replica that served /device/code is approvable on the replica that
// served /device/verify and pollable on whichever replica the device's
// /token poll lands on.
type DeviceCodeStore struct {
	rdb goredis.Cmdable
}

// NewDeviceCodeStore builds the store over an existing go-redis client.
func NewDeviceCodeStore(rdb goredis.Cmdable) *DeviceCodeStore {
	return &DeviceCodeStore{rdb: rdb}
}

// Ping reports Redis health for [sso.WithReadyCheck].
func (s *DeviceCodeStore) Ping(ctx context.Context) error {
	if s == nil || s.rdb == nil {
		return errors.New("redis: device code store not initialized")
	}
	return s.rdb.Ping(ctx).Err()
}

func deviceCodeKey(code string) string { return deviceCodeKeyPrefix + code }
func userCodeKey(code string) string   { return userCodeKeyPrefix + code }
func lastPollKey(code string) string   { return lastPollKeyPrefix + code }

// Issue persists a pending device code as a JSON record keyed by
// device_code, plus a user_code -> device_code pointer key. Both keys get
// a TTL from the code's own expiry so an un-redeemed code self-evicts.
func (s *DeviceCodeStore) Issue(ctx context.Context, dc *oauth.DeviceCode) error {
	if dc == nil || dc.DeviceCode == "" || dc.UserCode == "" {
		return oauth.ErrDeviceCodeNotFound
	}
	blob, err := json.Marshal(dc)
	if err != nil {
		return fmt.Errorf("redis: marshal device_code: %w", err)
	}
	ttl := time.Until(dc.ExpiresAt)
	if ttl <= 0 {
		// Already expired; a non-positive Redis TTL would persist
		// forever. No-op success — a poll would reject it as expired
		// anyway. Mirrors the auth_code / par stores.
		return nil
	}
	if err := s.rdb.Set(ctx, deviceCodeKey(dc.DeviceCode), blob, ttl).Err(); err != nil {
		return fmt.Errorf("redis: insert device_code: %w", err)
	}
	if err := s.rdb.Set(ctx, userCodeKey(dc.UserCode), dc.DeviceCode, ttl).Err(); err != nil {
		// Roll back the record so a half-written code can't be polled by
		// device_code yet never found by user_code (the user could never
		// approve it). Best-effort; the record self-evicts at TTL anyway.
		_ = s.rdb.Del(ctx, deviceCodeKey(dc.DeviceCode)).Err()
		return fmt.Errorf("redis: insert user_code pointer: %w", err)
	}
	return nil
}

// GetByDeviceCode looks up by device_code. Unknown / TTL-evicted /
// just-expired all collapse to ErrDeviceCodeNotFound (§2 oracle-leak:
// the token endpoint maps it to expired_token without leaking the case).
func (s *DeviceCodeStore) GetByDeviceCode(ctx context.Context, deviceCode string) (*oauth.DeviceCode, error) {
	return s.getByDeviceCode(ctx, deviceCode)
}

// GetByUserCode dereferences the user_code pointer to the canonical
// record. Same ErrDeviceCodeNotFound collapse — a missing pointer (or a
// pointer to an already-evicted record) is indistinguishable from an
// unknown user_code.
func (s *DeviceCodeStore) GetByUserCode(ctx context.Context, userCode string) (*oauth.DeviceCode, error) {
	deviceCode, err := s.resolveUserCode(ctx, userCode)
	if err != nil {
		return nil, err
	}
	return s.getByDeviceCode(ctx, deviceCode)
}

// resolveUserCode reads the user_code -> device_code pointer.
func (s *DeviceCodeStore) resolveUserCode(ctx context.Context, userCode string) (string, error) {
	deviceCode, err := s.rdb.Get(ctx, userCodeKey(userCode)).Result()
	if errors.Is(err, goredis.Nil) {
		return "", oauth.ErrDeviceCodeNotFound
	}
	if err != nil {
		return "", fmt.Errorf("redis: resolve user_code: %w", err)
	}
	return deviceCode, nil
}

// getByDeviceCode reads + decodes the canonical record, collapsing
// missing / expired to ErrDeviceCodeNotFound and opportunistically GCing
// a just-expired record (and its pointer) so a retry sees clean state.
func (s *DeviceCodeStore) getByDeviceCode(ctx context.Context, deviceCode string) (*oauth.DeviceCode, error) {
	blob, err := s.rdb.Get(ctx, deviceCodeKey(deviceCode)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, oauth.ErrDeviceCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("redis: get device_code: %w", err)
	}
	var out oauth.DeviceCode
	if err := json.Unmarshal(blob, &out); err != nil {
		return nil, fmt.Errorf("redis: unmarshal device_code: %w", err)
	}
	if out.IsExpired() {
		// Eviction-lag window: the TTL hasn't fired yet but the code is
		// logically expired. Delete both keys and report not-found.
		s.deleteBoth(ctx, out.DeviceCode, out.UserCode)
		return nil, oauth.ErrDeviceCodeNotFound
	}
	// LastPoll lives in its own key; when present it is authoritative over the
	// vestigial value carried in the record blob. A missing key (never polled)
	// leaves the blob's zero value intact. Best-effort: a read error here only
	// affects a UX timestamp, never the auth decision.
	if lp, err := s.rdb.Get(ctx, lastPollKey(deviceCode)).Result(); err == nil {
		if ns, perr := strconv.ParseInt(lp, 10, 64); perr == nil {
			out.LastPoll = time.Unix(0, ns)
		}
	}
	return &out, nil
}

// Approve marks the code approved with the resolved user identity. The
// record is re-read, mutated, and re-written under its REMAINING TTL so
// approval does not extend the code's lifetime. Unknown / expired →
// ErrDeviceCodeNotFound.
func (s *DeviceCodeStore) Approve(ctx context.Context, userCode, userID, provider string, attributes map[string]string) error {
	return s.mutateByUserCode(ctx, userCode, func(dc *oauth.DeviceCode) {
		dc.Approved = true
		dc.UserID = userID
		dc.Provider = provider
		dc.Attributes = attributes
	})
}

// Deny marks the code explicitly denied. Same lifetime-preserving
// rewrite as Approve.
func (s *DeviceCodeStore) Deny(ctx context.Context, userCode string) error {
	return s.mutateByUserCode(ctx, userCode, func(dc *oauth.DeviceCode) {
		dc.Denied = true
	})
}

// UpdateLastPoll records the most recent poll for slow_down enforcement,
// preserving the code's remaining TTL. Keyed by device_code (the poll
// path).
func (s *DeviceCodeStore) UpdateLastPoll(ctx context.Context, deviceCode string, t time.Time) error {
	// Write to the dedicated last_poll key with the record's REMAINING TTL, so
	// the poll loop never rewrites the canonical record and thus can never
	// clobber a concurrent Approve. Unknown/expired code -> ErrDeviceCodeNotFound
	// (preserves the prior contract via the record key's PTTL).
	ttl, err := s.rdb.PTTL(ctx, deviceCodeKey(deviceCode)).Result()
	if err != nil {
		return fmt.Errorf("redis: device_code pttl: %w", err)
	}
	if ttl == -2 { // key absent: unknown or TTL-evicted
		return oauth.ErrDeviceCodeNotFound
	}
	// ttl == -1 (present, no expiry) clamps to 0 = no expiry on the poll key.
	exp := max(ttl, 0)
	if err := s.rdb.Set(ctx, lastPollKey(deviceCode), strconv.FormatInt(t.UnixNano(), 10), exp).Err(); err != nil {
		return fmt.Errorf("redis: update last_poll: %w", err)
	}
	return nil
}

// mutateByUserCode resolves the pointer then applies a read-modify-write
// to the canonical record.
func (s *DeviceCodeStore) mutateByUserCode(ctx context.Context, userCode string, mut func(*oauth.DeviceCode)) error {
	deviceCode, err := s.resolveUserCode(ctx, userCode)
	if err != nil {
		return err
	}
	return s.mutateByDeviceCode(ctx, deviceCode, mut)
}

// mutateByDeviceCode applies a read-modify-write to the canonical record,
// keeping its remaining TTL (KEEPTTL) so a mutation never resurrects an expired
// code nor extends a live one. Only Approve and Deny use this path — a single
// human one-shot per code (approve XOR deny) that cannot race itself, so the
// whole-record rewrite is safe. The high-frequency poll path (UpdateLastPoll)
// deliberately does NOT use it: it writes LastPoll to a separate key so it can
// never clobber a concurrent Approve on a real cluster (see lastPollKeyPrefix).
func (s *DeviceCodeStore) mutateByDeviceCode(ctx context.Context, deviceCode string, mut func(*oauth.DeviceCode)) error {
	dc, err := s.getByDeviceCode(ctx, deviceCode)
	if err != nil {
		return err
	}
	mut(dc)
	blob, err := json.Marshal(dc)
	if err != nil {
		return fmt.Errorf("redis: marshal device_code: %w", err)
	}
	// XX + KEEPTTL: write ONLY if the key still exists, preserving its window.
	// A plain SET KEEPTTL against a key that a concurrent Delete (token-exchange
	// consume) or the expiry-GC already removed would RESURRECT a consumed code
	// with NO TTL (KEEPTTL has nothing to keep) — pollable inside the original
	// window, a single-use violation. redis.Nil means the key was already gone,
	// so dropping the mutation is the correct idempotent outcome, not an error.
	err = s.rdb.SetArgs(ctx, deviceCodeKey(deviceCode), blob, goredis.SetArgs{Mode: "XX", KeepTTL: true}).Err()
	if err != nil && !errors.Is(err, goredis.Nil) {
		return fmt.Errorf("redis: update device_code: %w", err)
	}
	return nil
}

// Delete removes the record AND its user_code pointer. Single-use is
// enforced here (the token endpoint calls Delete after a successful
// exchange). Idempotent — a missing code is a no-op success.
func (s *DeviceCodeStore) Delete(ctx context.Context, deviceCode string) error {
	// Read the record first to learn the user_code so its pointer is
	// reaped too. A missing record still deletes the device_code key
	// (idempotent); the orphaned pointer, if any, self-evicts at TTL.
	blob, err := s.rdb.Get(ctx, deviceCodeKey(deviceCode)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("redis: delete device_code: %w", err)
	}
	var out oauth.DeviceCode
	if json.Unmarshal(blob, &out) == nil {
		s.deleteBoth(ctx, deviceCode, out.UserCode)
		return nil
	}
	// Unparseable record (shouldn't happen): drop the device_code key.
	if err := s.rdb.Del(ctx, deviceCodeKey(deviceCode)).Err(); err != nil {
		return fmt.Errorf("redis: delete device_code: %w", err)
	}
	return nil
}

// deleteBoth removes the record + pointer; best-effort (callers have
// already produced the correct caller-visible result).
func (s *DeviceCodeStore) deleteBoth(ctx context.Context, deviceCode, userCode string) {
	_ = s.rdb.Del(ctx, deviceCodeKey(deviceCode)).Err()
	_ = s.rdb.Del(ctx, lastPollKey(deviceCode)).Err()
	if userCode != "" {
		_ = s.rdb.Del(ctx, userCodeKey(userCode)).Err()
	}
}

// consumeIfApprovedScript atomically claims an APPROVED device code in one
// server-side op: GET the record, and only when its Approved field is true DEL
// the canonical key and return the blob; otherwise return false (missing /
// pending / denied / undecodable). Single key (the device_code) -> cluster-slot
// safe. The user_code pointer + last_poll key live in other slots and are reaped
// by the Go caller after the win.
var consumeIfApprovedScript = goredis.NewScript(`
local v = redis.call('GET', KEYS[1])
if not v then return false end
local ok, obj = pcall(cjson.decode, v)
if not ok then return false end
if obj.Approved == true then
  redis.call('DEL', KEYS[1])
  return v
end
return false
`)

// ConsumeIfApproved atomically deletes + returns the record iff approved (the
// Lua runs as one indivisible server-side op, so of N concurrent polls exactly
// one wins the blob). A pending/denied/unknown/expired code -> the script
// returns false -> ErrDeviceCodeNotFound.
func (s *DeviceCodeStore) ConsumeIfApproved(ctx context.Context, deviceCode string) (*oauth.DeviceCode, error) {
	res, err := consumeIfApprovedScript.Run(ctx, s.rdb, []string{deviceCodeKey(deviceCode)}).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, oauth.ErrDeviceCodeNotFound // script returned false/nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis: consume_if_approved device_code: %w", err)
	}
	blob, ok := res.(string)
	if !ok {
		return nil, oauth.ErrDeviceCodeNotFound
	}
	var out oauth.DeviceCode
	if err := json.Unmarshal([]byte(blob), &out); err != nil {
		return nil, fmt.Errorf("redis: unmarshal device_code: %w", err)
	}
	// Canonical key already deleted by the script; reap the pointer + last_poll
	// keys (different slots, so separate routed DELs) best-effort.
	_ = s.rdb.Del(ctx, userCodeKey(out.UserCode)).Err()
	_ = s.rdb.Del(ctx, lastPollKey(deviceCode)).Err()
	if out.IsExpired() {
		return nil, oauth.ErrDeviceCodeNotFound
	}
	return &out, nil
}

var _ oauth.DeviceCodeStore = (*DeviceCodeStore)(nil)
