package redis

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// Key layout. The user JSON lives at one key per id; a global SET indexes
// every id for List(); and a per-(provider, external-id) pointer key backs
// GetByExternalID without a scan. The external id is base64url-encoded in the
// key so a provider-issued id containing a colon can't collide with the key
// delimiter.
const (
	userKeyPrefix = "sso:user:"     // sso:user:<id> -> JSON
	userExtPrefix = "sso:user:ext:" // sso:user:ext:<provider>:<b64(extID)> -> id
	userAllKey    = "sso:user:all"  // SET of every user id
)

// UserProvider is the Redis-backed [sso.UserProvider]. It is the durable scale
// peer for the per-login user upsert (CreateOrUpdate) + GetByID/GetByExternalID
// every /auth/login performs, so a multi-replica fleet shares one user
// directory instead of each replica holding an embedded copy.
type UserProvider struct {
	rdb goredis.Cmdable
}

// NewUserProvider builds a UserProvider over an existing go-redis client (or
// cluster client — any goredis.Cmdable). The caller owns the client lifecycle.
func NewUserProvider(rdb goredis.Cmdable) *UserProvider {
	return &UserProvider{rdb: rdb}
}

// Ping reports Redis connection health for [sso.WithReadyCheck] wiring.
func (p *UserProvider) Ping(ctx context.Context) error {
	return p.rdb.Ping(ctx).Err()
}

func userKey(id string) string { return userKeyPrefix + id }

func userExtKey(provider, externalID string) string {
	return userExtPrefix + provider + ":" + base64.RawURLEncoding.EncodeToString([]byte(externalID))
}

func (p *UserProvider) GetByID(ctx context.Context, id string) (*sso.User, error) {
	raw, err := p.rdb.Get(ctx, userKey(id)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, sso.ErrNoSuchUser
	}
	if err != nil {
		return nil, fmt.Errorf("redis: get user: %w", err)
	}
	var u sso.User
	if err := json.Unmarshal(raw, &u); err != nil {
		return nil, fmt.Errorf("redis: decode user: %w", err)
	}
	return &u, nil
}

func (p *UserProvider) GetByExternalID(ctx context.Context, provider, externalID string) (*sso.User, error) {
	if externalID == "" || provider == "" {
		return nil, sso.ErrNoSuchUser
	}
	id, err := p.rdb.Get(ctx, userExtKey(provider, externalID)).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, sso.ErrNoSuchUser
	}
	if err != nil {
		return nil, fmt.Errorf("redis: get user by external id: %w", err)
	}
	u, err := p.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	// Guard against a stale pointer key: only return the user if it still
	// carries this external identity (matches the memory peer's scan, which is
	// always consistent).
	if u.Provider != provider || u.ExternalID != externalID {
		return nil, sso.ErrNoSuchUser
	}
	return u, nil
}

func (p *UserProvider) CreateOrUpdate(ctx context.Context, user *sso.User) error {
	if user == nil || user.ID == "" {
		return errors.New("redis: user.ID required")
	}
	// If this is an update whose external identity changed, drop the stale
	// pointer key so GetByExternalID(old) stops resolving.
	if old, err := p.GetByID(ctx, user.ID); err == nil && old.ExternalID != "" && old.Provider != "" {
		if old.Provider != user.Provider || old.ExternalID != user.ExternalID {
			_ = p.rdb.Del(ctx, userExtKey(old.Provider, old.ExternalID)).Err()
		}
	}
	raw, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("redis: encode user: %w", err)
	}
	if err := p.rdb.Set(ctx, userKey(user.ID), raw, 0).Err(); err != nil {
		return fmt.Errorf("redis: put user: %w", err)
	}
	if err := p.rdb.SAdd(ctx, userAllKey, user.ID).Err(); err != nil {
		return fmt.Errorf("redis: index user: %w", err)
	}
	if user.ExternalID != "" && user.Provider != "" {
		if err := p.rdb.Set(ctx, userExtKey(user.Provider, user.ExternalID), user.ID, 0).Err(); err != nil {
			return fmt.Errorf("redis: index user external id: %w", err)
		}
	}
	return nil
}

func (p *UserProvider) List(ctx context.Context) ([]*sso.User, error) {
	ids, err := p.rdb.SMembers(ctx, userAllKey).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: list user ids: %w", err)
	}
	if len(ids) == 0 {
		return []*sso.User{}, nil
	}
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = userKey(id)
	}
	// Per-key GET pipeline, not MGET: user keys span every hash slot, so a
	// single MGET is a CROSSSLOT error on a real cluster. mgetCompat returns
	// the same positional []any (nil for misses) so the loop below is unchanged.
	vals, err := mgetCompat(ctx, p.rdb, keys)
	if err != nil {
		return nil, fmt.Errorf("redis: mget users: %w", err)
	}
	out := make([]*sso.User, 0, len(vals))
	for _, v := range vals {
		// A nil entry is an orphan index id whose JSON key expired/was removed
		// out of band — skip rather than fail the whole list.
		str, ok := v.(string)
		if !ok {
			continue
		}
		var u sso.User
		if err := json.Unmarshal([]byte(str), &u); err != nil {
			return nil, fmt.Errorf("redis: decode user in list: %w", err)
		}
		out = append(out, &u)
	}
	return out, nil
}

func (p *UserProvider) Delete(ctx context.Context, id string) error {
	// Clean up the external-id pointer key too. Best-effort: a missing user is
	// a no-op (idempotent) so reconciliation loops don't churn.
	if u, err := p.GetByID(ctx, id); err == nil && u.ExternalID != "" && u.Provider != "" {
		_ = p.rdb.Del(ctx, userExtKey(u.Provider, u.ExternalID)).Err()
	}
	if err := p.rdb.Del(ctx, userKey(id)).Err(); err != nil {
		return fmt.Errorf("redis: delete user: %w", err)
	}
	return p.rdb.SRem(ctx, userAllKey, id).Err()
}

var _ sso.UserProvider = (*UserProvider)(nil)
