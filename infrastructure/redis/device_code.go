package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/snaplink/sso/protocols/oauth"
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
	return s.mutateByDeviceCode(ctx, deviceCode, func(dc *oauth.DeviceCode) {
		dc.LastPoll = t
	})
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

// mutateByDeviceCode applies a read-modify-write to the record, keeping
// its remaining TTL (KEEPTTL) so a mutation never resurrects an expired
// code nor extends a live one. Read + write are not a single atomic op,
// but the device flow's writers don't contend: Approve / Deny are a
// human one-shot action and UpdateLastPoll is the polling device's own
// serial loop, so a lost-update race here has no security consequence (it
// would at worst drop one slow_down timestamp).
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
	// KEEPTTL preserves the existing window — the code must not outlive
	// its original expiry just because it was approved or polled.
	if err := s.rdb.Set(ctx, deviceCodeKey(deviceCode), blob, goredis.KeepTTL).Err(); err != nil {
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
	if userCode != "" {
		_ = s.rdb.Del(ctx, userCodeKey(userCode)).Err()
	}
}

var _ oauth.DeviceCodeStore = (*DeviceCodeStore)(nil)
