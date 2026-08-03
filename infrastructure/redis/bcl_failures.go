package redis

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/protocols/oidc/bcl"
)

const bclFailurePrefix = "sso:bcl:{failures}:"

type BackchannelFailureStore struct {
	rdb goredis.Cmdable
}

func NewBackchannelFailureStore(rdb goredis.Cmdable) *BackchannelFailureStore {
	return &BackchannelFailureStore{rdb: rdb}
}

func (s *BackchannelFailureStore) Ping(ctx context.Context) error {
	if s == nil || s.rdb == nil {
		return errors.New("redis: backchannel failure store not initialized")
	}
	return s.rdb.Ping(ctx).Err()
}

func bclGlobalIndex() string       { return bclFailurePrefix + "due" }
func bclEntryKey(id string) string { return bclFailurePrefix + "entry:" + id }
func bclLeaseKey(id string) string { return bclFailurePrefix + "lease:" + id }

func bclTenantIndex(tenantID string) string {
	if tenantID == "" {
		return bclGlobalIndex()
	}
	sum := sha256.Sum256([]byte(tenantID))
	return fmt.Sprintf("%stenant:%x", bclFailurePrefix, sum[:16])
}

func (s *BackchannelFailureStore) Enqueue(ctx context.Context, f bcl.Failure) (bcl.Failure, error) {
	if f.ID == "" {
		return f, errors.New("redis: backchannel failure id required")
	}
	attempts, err := enqueueBCLFailureScript.Run(ctx, s.rdb,
		[]string{bclGlobalIndex(), bclTenantIndex(f.TenantID), bclEntryKey(f.ID)},
		f.ID, f.TenantID, f.ClientID, f.Subject, f.TokenSubject, f.URI, f.SID,
		f.Attempts, f.LastError, millis(f.FirstFailedAt), millis(f.LastFailedAt), millis(f.NextAttemptAt), boolInt(f.Permanent)).Int()
	if err != nil {
		return f, fmt.Errorf("redis: enqueue backchannel failure: %w", err)
	}
	f.Attempts = attempts
	return f, nil
}

var enqueueBCLFailureScript = goredis.NewScript(`
local attempts = tonumber(ARGV[8])
local first = ARGV[10]
if redis.call('EXISTS', KEYS[3]) == 1 then
  attempts = tonumber(redis.call('HGET', KEYS[3], 'attempts') or '0') + attempts
  first = redis.call('HGET', KEYS[3], 'first_failed_at') or first
end
redis.call('HSET', KEYS[3],
  'id', ARGV[1], 'tenant_id', ARGV[2], 'client_id', ARGV[3],
  'subject', ARGV[4], 'token_subject', ARGV[5], 'uri', ARGV[6],
  'sid', ARGV[7], 'attempts', attempts, 'last_error', ARGV[9],
  'first_failed_at', first, 'last_failed_at', ARGV[11], 'next_attempt_at', ARGV[12],
  'permanent', ARGV[13])
redis.call('ZADD', KEYS[1], ARGV[12], ARGV[1])
redis.call('ZADD', KEYS[2], ARGV[12], ARGV[1])
return attempts
`)

func (s *BackchannelFailureStore) List(ctx context.Context, filter bcl.Filter) ([]bcl.Failure, error) {
	limit := redisBCLLimit(filter.Limit)
	var ids []string
	var err error
	index := bclTenantIndex(filter.TenantID)
	if filter.DueBefore.IsZero() {
		ids, err = s.rdb.ZRange(ctx, index, 0, int64(limit-1)).Result()
	} else {
		ids, err = s.rdb.ZRangeByScore(ctx, index, &goredis.ZRangeBy{
			Min: "-inf", Max: strconv.FormatInt(millis(filter.DueBefore), 10), Count: 1000,
		}).Result()
	}
	if err != nil {
		return nil, fmt.Errorf("redis: list backchannel failures: %w", err)
	}
	out := make([]bcl.Failure, 0, len(ids))
	for _, id := range ids {
		fields, getErr := s.rdb.HGetAll(ctx, bclEntryKey(id)).Result()
		if getErr != nil {
			return nil, fmt.Errorf("redis: read backchannel failure: %w", getErr)
		}
		if len(fields) > 0 {
			entry := decodeBCLFailure(fields)
			if !filter.DueBefore.IsZero() && entry.Permanent {
				continue
			}
			out = append(out, entry)
			if len(out) == limit {
				break
			}
		}
	}
	return out, nil
}

func (s *BackchannelFailureStore) Claim(ctx context.Context, id, tenantID string, lease time.Duration) (bcl.Failure, string, error) {
	token := redisBCLLeaseToken()
	ok, err := s.rdb.SetNX(ctx, bclLeaseKey(id), token, redisBCLLease(lease)).Result()
	if err != nil {
		return bcl.Failure{}, "", fmt.Errorf("redis: claim backchannel failure: %w", err)
	}
	if !ok {
		return bcl.Failure{}, "", bcl.ErrLeaseUnavailable
	}
	fields, err := s.rdb.HGetAll(ctx, bclEntryKey(id)).Result()
	if err != nil || len(fields) == 0 {
		_ = s.rdb.Del(ctx, bclLeaseKey(id)).Err()
		if err != nil {
			return bcl.Failure{}, "", fmt.Errorf("redis: read claimed backchannel failure: %w", err)
		}
		return bcl.Failure{}, "", bcl.ErrNotFound
	}
	f := decodeBCLFailure(fields)
	if tenantID != "" && f.TenantID != tenantID {
		_ = s.rdb.Del(ctx, bclLeaseKey(id)).Err()
		return bcl.Failure{}, "", bcl.ErrNotFound
	}
	return f, token, nil
}

func (s *BackchannelFailureStore) Ack(ctx context.Context, f bcl.Failure, token string) error {
	result, err := ackBCLFailureScript.Run(ctx, s.rdb,
		[]string{bclGlobalIndex(), bclTenantIndex(f.TenantID), bclEntryKey(f.ID), bclLeaseKey(f.ID)},
		token, f.ID).Int()
	if err != nil {
		return fmt.Errorf("redis: ack backchannel failure: %w", err)
	}
	if result != 1 {
		return bcl.ErrLeaseUnavailable
	}
	return nil
}

var ackBCLFailureScript = goredis.NewScript(`
if redis.call('GET', KEYS[4]) ~= ARGV[1] then return 0 end
redis.call('DEL', KEYS[3], KEYS[4])
redis.call('ZREM', KEYS[1], ARGV[2])
redis.call('ZREM', KEYS[2], ARGV[2])
return 1
`)

func (s *BackchannelFailureStore) Reschedule(ctx context.Context, f bcl.Failure, token string) error {
	result, err := rescheduleBCLFailureScript.Run(ctx, s.rdb,
		[]string{bclGlobalIndex(), bclTenantIndex(f.TenantID), bclEntryKey(f.ID), bclLeaseKey(f.ID)},
		token, f.ID, f.Attempts, f.LastError, millis(f.LastFailedAt), millis(f.NextAttemptAt)).Int()
	if err != nil {
		return fmt.Errorf("redis: reschedule backchannel failure: %w", err)
	}
	if result != 1 {
		return bcl.ErrLeaseUnavailable
	}
	return nil
}

var rescheduleBCLFailureScript = goredis.NewScript(`
if redis.call('GET', KEYS[4]) ~= ARGV[1] then return 0 end
redis.call('HSET', KEYS[3], 'attempts', ARGV[3], 'last_error', ARGV[4],
  'last_failed_at', ARGV[5], 'next_attempt_at', ARGV[6])
redis.call('ZADD', KEYS[1], ARGV[6], ARGV[2])
redis.call('ZADD', KEYS[2], ARGV[6], ARGV[2])
redis.call('DEL', KEYS[4])
return 1
`)

func decodeBCLFailure(fields map[string]string) bcl.Failure {
	return bcl.Failure{
		ID: fields["id"], TenantID: fields["tenant_id"], ClientID: fields["client_id"],
		Subject: fields["subject"], TokenSubject: fields["token_subject"], URI: fields["uri"], SID: fields["sid"],
		Attempts: atoi(fields["attempts"]), LastError: fields["last_error"],
		Permanent:     fields["permanent"] == "1",
		FirstFailedAt: fromMillis(fields["first_failed_at"]), LastFailedAt: fromMillis(fields["last_failed_at"]),
		NextAttemptAt: fromMillis(fields["next_attempt_at"]),
	}
}

func millis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromMillis(value string) time.Time {
	ms, _ := strconv.ParseInt(value, 10, 64)
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

func atoi(value string) int {
	n, _ := strconv.Atoi(value)
	return n
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func redisBCLLimit(limit int) int {
	if limit <= 0 || limit > 200 {
		return 100
	}
	return limit
}

func redisBCLLease(lease time.Duration) time.Duration {
	if lease <= 0 {
		return bcl.DefaultLeaseDuration
	}
	return lease
}

func redisBCLLeaseToken() string {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

var _ bcl.Store = (*BackchannelFailureStore)(nil)
