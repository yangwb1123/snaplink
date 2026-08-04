package redis

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

const authCodeKeyPrefix = "sso:authcode:" // sso:authcode:<code> -> JSON
const opaqueLookupPrefix = "h1:"

func opaqueLookupKey(key []byte, kind, raw string) string {
	if len(key) == 0 {
		return raw
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(kind))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(raw))
	return opaqueLookupPrefix + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func opaqueLookupCandidates(keys [][]byte, kind, raw string) []string {
	out := make([]string, 0, len(keys)+1)
	for _, key := range keys {
		out = append(out, opaqueLookupKey(key, kind, raw))
	}
	return append(out, raw)
}

func cloneLookupKeys(keys ...[]byte) [][]byte {
	out := make([][]byte, 0, len(keys))
	for _, key := range keys {
		if len(key) > 0 {
			out = append(out, append([]byte(nil), key...))
		}
	}
	return out
}

func firstLookupKey(keys [][]byte) []byte {
	if len(keys) == 0 {
		return nil
	}
	return keys[0]
}

// AuthCodeStore is the Redis-backed implementation of
// [oauth.AuthCodeStore]. Suitable for multi-replica deployments: every
// replica issues + consumes against the same Redis.
type AuthCodeStore struct {
	rdb            goredis.Cmdable
	lookupHMACKeys [][]byte
}

// NewAuthCodeStore builds the store over an existing go-redis client.
func NewAuthCodeStore(rdb goredis.Cmdable) *AuthCodeStore {
	return &AuthCodeStore{rdb: rdb}
}

// SetLookupHMACKeys enables current-key writes plus previous-key and legacy
// plaintext reads for no-logout rotation.
func (s *AuthCodeStore) SetLookupHMACKeys(keys ...[]byte) {
	s.lookupHMACKeys = cloneLookupKeys(keys...)
}

// Ping reports Redis health for [sso.WithReadyCheck].
func (s *AuthCodeStore) Ping(ctx context.Context) error {
	if s == nil || s.rdb == nil {
		return errors.New("redis: auth code store not initialized")
	}
	return s.rdb.Ping(ctx).Err()
}

func authCodeKey(code string) string { return authCodeKeyPrefix + code }

// Issue persists the code as a JSON blob with a key TTL set from the
// code's own expiry, so an unconsumed code self-evicts.
func (s *AuthCodeStore) Issue(ctx context.Context, code string, info *oauth.AuthCode) error {
	if code == "" || info == nil {
		return oauth.ErrAuthCodeNotFound
	}
	blob, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("redis: marshal auth_code: %w", err)
	}
	ttl := time.Until(info.ExpiresAt)
	if ttl <= 0 {
		// Already expired; storing with a non-positive TTL would persist
		// forever in Redis. Treat as a no-op success — the next Consume
		// would reject it as expired anyway.
		return nil
	}
	lookup := opaqueLookupKey(firstLookupKey(s.lookupHMACKeys), "auth_code", code)
	if err := s.rdb.Set(ctx, authCodeKey(lookup), blob, ttl).Err(); err != nil {
		return fmt.Errorf("redis: insert auth_code: %w", err)
	}
	return nil
}

// Consume atomically returns + deletes the code via GETDEL — a single
// server-side get-and-delete (Redis 6.2+). This is the Redis analogue of
// SQLite's DELETE ... RETURNING: a second Consume of the same code finds
// nothing, so single-use is race-free. Unknown / TTL-expired / already-
// consumed all collapse to ErrAuthCodeNotFound (oracle-resistance §2).
func (s *AuthCodeStore) Consume(ctx context.Context, code string) (*oauth.AuthCode, error) {
	var blob []byte
	for _, candidate := range opaqueLookupCandidates(s.lookupHMACKeys, "auth_code", code) {
		var err error
		blob, err = s.rdb.GetDel(ctx, authCodeKey(candidate)).Bytes()
		if err == nil {
			break
		}
		if !errors.Is(err, goredis.Nil) {
			return nil, fmt.Errorf("redis: consume auth_code: %w", err)
		}
	}
	if blob == nil {
		return nil, oauth.ErrAuthCodeNotFound
	}
	var out oauth.AuthCode
	if err := json.Unmarshal(blob, &out); err != nil {
		return nil, fmt.Errorf("redis: unmarshal auth_code: %w", err)
	}
	// Defense in depth: even though the key TTL evicts expired codes,
	// the eviction-lag window means a just-expired code could still be
	// read; collapse it to the same not-found result.
	if out.IsExpired() {
		return nil, oauth.ErrAuthCodeNotFound
	}
	return &out, nil
}

var _ oauth.AuthCodeStore = (*AuthCodeStore)(nil)
