package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

const parKeyPrefix = "sso:par:" // sso:par:<request_uri> -> JSON

// PARStore is the Redis-backed implementation of [oauth.PARStore].
// Multi-replica safe: a request_uri minted on one replica is consumable
// on the replica that handles the /auth/login redirect.
type PARStore struct {
	rdb            goredis.Cmdable
	lookupHMACKeys [][]byte
}

// NewPARStore builds the store over an existing go-redis client.
func NewPARStore(rdb goredis.Cmdable) *PARStore {
	return &PARStore{rdb: rdb}
}

// SetLookupHMACKeys enables current-key writes plus previous-key and legacy
// plaintext reads for no-logout rotation.
func (s *PARStore) SetLookupHMACKeys(keys ...[]byte) {
	s.lookupHMACKeys = cloneLookupKeys(keys...)
}

// Ping reports Redis health for [sso.WithReadyCheck].
func (s *PARStore) Ping(ctx context.Context) error {
	if s == nil || s.rdb == nil {
		return errors.New("redis: par store not initialized")
	}
	return s.rdb.Ping(ctx).Err()
}

func parKey(uri string) string { return parKeyPrefix + uri }

// Issue mints an opaque request_uri, stores the request as JSON with a
// TTL from its own expiry, and returns the URI for /auth/login.
func (s *PARStore) Issue(ctx context.Context, req *oauth.PARRequest) (string, error) {
	if req == nil {
		return "", oauth.ErrPARNotFound
	}
	tok, err := defaultimpl.GeneratePARToken()
	if err != nil {
		return "", err
	}
	uri := oauth.PARURIPrefix + tok
	blob, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("redis: marshal par_request: %w", err)
	}
	ttl := time.Until(req.ExpiresAt)
	if ttl <= 0 {
		ttl = oauth.DefaultPARTTL
	}
	lookup := opaqueLookupKey(firstLookupKey(s.lookupHMACKeys), "par", uri)
	if err := s.rdb.Set(ctx, parKey(lookup), blob, ttl).Err(); err != nil {
		return "", fmt.Errorf("redis: insert par_request: %w", err)
	}
	return uri, nil
}

// Consume atomically returns + deletes via GETDEL — single-use, race-
// free (the Redis analogue of DELETE ... RETURNING). Unknown / expired /
// already-consumed all map to ErrPARNotFound (RFC 9126 §2.2 oracle-
// resistance §2).
func (s *PARStore) Consume(ctx context.Context, requestURI string) (*oauth.PARRequest, error) {
	var blob []byte
	for _, candidate := range opaqueLookupCandidates(s.lookupHMACKeys, "par", requestURI) {
		var err error
		blob, err = s.rdb.GetDel(ctx, parKey(candidate)).Bytes()
		if err == nil {
			break
		}
		if !errors.Is(err, goredis.Nil) {
			return nil, fmt.Errorf("redis: consume par_request: %w", err)
		}
	}
	if blob == nil {
		return nil, oauth.ErrPARNotFound
	}
	var out oauth.PARRequest
	if err := json.Unmarshal(blob, &out); err != nil {
		return nil, fmt.Errorf("redis: unmarshal par_request: %w", err)
	}
	if out.IsExpired() {
		return nil, oauth.ErrPARNotFound
	}
	return &out, nil
}

var _ oauth.PARStore = (*PARStore)(nil)
