package redis

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

// Key layout. The user JSON lives at one key per id; a global SET indexes
// every id for List(); and a per-(provider, external-id) pointer key backs
// GetByExternalID without a scan. The external id is base64url-encoded in the
// key so a provider-issued id containing a colon can't collide with the key
// delimiter.
const (
	userKeyPrefix     = "sso:user:"        // sso:user:<id> -> JSON
	userExtPrefix     = "sso:user:ext:"    // sso:user:ext:<provider>:<b64(extID)> -> id
	userAllKey        = "sso:user:all"     // legacy SET of every user id
	userPageKey       = "sso:user:page:v1" // ZSET score=0, lexicographic ids
	userPageReadyKey  = "sso:user:page:ready"
	userNamePrefix    = "sso:user:name:" // sso:user:name:<b64(lower(username))> -> id
	userPageBatchSize = 512
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

func userNameKey(username string) string {
	value := strings.ToLower(strings.TrimSpace(username))
	return userNamePrefix + base64.RawURLEncoding.EncodeToString([]byte(value))
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

func (p *UserProvider) GetByUsername(ctx context.Context, username string) (*sso.User, error) {
	if strings.TrimSpace(username) == "" {
		return nil, sso.ErrNoSuchUser
	}
	id, err := p.rdb.Get(ctx, userNameKey(username)).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, sso.ErrNoSuchUser
	}
	if err != nil {
		return nil, fmt.Errorf("redis: get user by username: %w", err)
	}
	u, err := p.GetByID(ctx, id)
	if err != nil || !strings.EqualFold(u.Username, username) {
		return nil, sso.ErrNoSuchUser
	}
	return u, nil
}

func (p *UserProvider) UsernameExists(ctx context.Context, username string) (bool, error) {
	_, err := p.GetByUsername(ctx, username)
	if errors.Is(err, sso.ErrNoSuchUser) {
		return false, nil
	}
	return err == nil, err
}

func (p *UserProvider) CreateOrUpdate(ctx context.Context, user *sso.User) error {
	if user == nil || user.ID == "" {
		return errors.New("redis: user.ID required")
	}
	old, _ := p.GetByID(ctx, user.ID)
	claimed, err := p.claimUsername(ctx, user.Username, user.ID)
	if err != nil {
		return err
	}
	// If this is an update whose external identity changed, drop the stale
	// pointer key so GetByExternalID(old) stops resolving.
	if old != nil && old.ExternalID != "" && old.Provider != "" {
		if old.Provider != user.Provider || old.ExternalID != user.ExternalID {
			_ = p.rdb.Del(ctx, userExtKey(old.Provider, old.ExternalID)).Err()
		}
	}
	raw, err := json.Marshal(user)
	if err != nil {
		p.rollbackUsernameClaim(ctx, user.Username, user.ID, claimed)
		return fmt.Errorf("redis: encode user: %w", err)
	}
	if err := p.rdb.Set(ctx, userKey(user.ID), raw, 0).Err(); err != nil {
		p.rollbackUsernameClaim(ctx, user.Username, user.ID, claimed)
		return fmt.Errorf("redis: put user: %w", err)
	}
	if err := p.rdb.SAdd(ctx, userAllKey, user.ID).Err(); err != nil {
		return fmt.Errorf("redis: index user: %w", err)
	}
	if err := p.rdb.ZAdd(ctx, userPageKey, goredis.Z{Score: 0, Member: user.ID}).Err(); err != nil {
		return fmt.Errorf("redis: page-index user: %w", err)
	}
	if user.ExternalID != "" && user.Provider != "" {
		if err := p.rdb.Set(ctx, userExtKey(user.Provider, user.ExternalID), user.ID, 0).Err(); err != nil {
			return fmt.Errorf("redis: index user external id: %w", err)
		}
	}
	if old != nil && old.Username != "" && !strings.EqualFold(old.Username, user.Username) {
		if err := p.releaseUsername(ctx, old.Username, user.ID); err != nil {
			return fmt.Errorf("redis: release old username: %w", err)
		}
	}
	return nil
}

func (p *UserProvider) claimUsername(ctx context.Context, username, id string) (bool, error) {
	if strings.TrimSpace(username) == "" {
		return false, nil
	}
	key := userNameKey(username)
	claimed, err := p.rdb.SetNX(ctx, key, id, 0).Result()
	if err != nil || claimed {
		return claimed, err
	}
	owner, err := p.rdb.Get(ctx, key).Result()
	if errors.Is(err, goredis.Nil) {
		return p.claimUsername(ctx, username, id)
	}
	if err != nil {
		return false, fmt.Errorf("redis: inspect username claim: %w", err)
	}
	if owner != id {
		return false, sso.ErrUserExists
	}
	return false, nil
}

func (p *UserProvider) rollbackUsernameClaim(ctx context.Context, username, id string, claimed bool) {
	if claimed {
		_ = p.releaseUsername(ctx, username, id)
	}
}

func (p *UserProvider) releaseUsername(ctx context.Context, username, id string) error {
	if strings.TrimSpace(username) == "" {
		return nil
	}
	const compareDelete = `if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("DEL", KEYS[1]) else return 0 end`
	return p.rdb.Eval(ctx, compareDelete, []string{userNameKey(username)}, id).Err()
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

// ListPaginated implements [core.UserPaginationProvider]. Redis performs the
// alphabetical sort and LIMIT server-side; only the current page's values
// cross the network.
func (p *UserProvider) ListPaginated(ctx context.Context, offset, limit int) ([]*sso.User, int, error) {
	if err := p.ensureUserPageIndex(ctx); err != nil {
		return nil, 0, err
	}
	total, err := p.rdb.ZCard(ctx, userPageKey).Result()
	if err != nil {
		return nil, 0, fmt.Errorf("redis: count users: %w", err)
	}
	offset, limit = normalizeUserPage(offset, limit)
	ids, err := p.rdb.ZRangeByLex(ctx, userPageKey, &goredis.ZRangeBy{
		Min:    "-",
		Max:    "+",
		Offset: int64(offset),
		Count:  int64(limit),
	}).Result()
	if err != nil {
		return nil, 0, fmt.Errorf("redis: page user ids: %w", err)
	}
	if len(ids) == 0 {
		return []*sso.User{}, int(total), nil
	}
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = userKey(id)
	}
	vals, err := mgetCompat(ctx, p.rdb, keys)
	if err != nil {
		return nil, 0, fmt.Errorf("redis: get paginated users: %w", err)
	}
	out, err := decodeUsers(vals)
	return out, int(total), err
}

// ensureUserPageIndex lazily upgrades installations created before the
// lexicographic ZSET index existed. The SET remains during the compatibility
// window; new writes update both indexes.
func (p *UserProvider) ensureUserPageIndex(ctx context.Context) error {
	ready, err := p.rdb.Exists(ctx, userPageReadyKey).Result()
	if err != nil {
		return fmt.Errorf("redis: inspect user page index: %w", err)
	}
	if ready > 0 {
		return nil
	}
	var cursor uint64
	for {
		ids, next, err := p.rdb.SScan(ctx, userAllKey, cursor, "*", userPageBatchSize).Result()
		if err != nil {
			return fmt.Errorf("redis: migrate user page index: %w", err)
		}
		members := make([]goredis.Z, 0, len(ids))
		for _, id := range ids {
			members = append(members, goredis.Z{Score: 0, Member: id})
		}
		if len(members) > 0 {
			if err := p.rdb.ZAdd(ctx, userPageKey, members...).Err(); err != nil {
				return fmt.Errorf("redis: write user page index: %w", err)
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("redis: migrate user page index: %w", err)
		}
	}
	if err := p.rdb.Set(ctx, userPageReadyKey, "1", 0).Err(); err != nil {
		return fmt.Errorf("redis: mark user page index ready: %w", err)
	}
	return nil
}

func decodeUsers(vals []any) ([]*sso.User, error) {
	out := make([]*sso.User, 0, len(vals))
	for _, v := range vals {
		str, ok := v.(string)
		if !ok {
			continue
		}
		var u sso.User
		if err := json.Unmarshal([]byte(str), &u); err != nil {
			return nil, fmt.Errorf("redis: decode paginated user: %w", err)
		}
		out = append(out, &u)
	}
	return out, nil
}

func normalizeUserPage(offset, limit int) (int, int) {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	return offset, limit
}

func (p *UserProvider) Delete(ctx context.Context, id string) error {
	// Clean up the external-id pointer key too. Best-effort: a missing user is
	// a no-op (idempotent) so reconciliation loops don't churn.
	u, _ := p.GetByID(ctx, id)
	if u != nil && u.ExternalID != "" && u.Provider != "" {
		_ = p.rdb.Del(ctx, userExtKey(u.Provider, u.ExternalID)).Err()
	}
	if err := p.rdb.Del(ctx, userKey(id)).Err(); err != nil {
		return fmt.Errorf("redis: delete user: %w", err)
	}
	if err := p.rdb.SRem(ctx, userAllKey, id).Err(); err != nil {
		return err
	}
	if err := p.rdb.ZRem(ctx, userPageKey, id).Err(); err != nil {
		return err
	}
	if u != nil {
		return p.releaseUsername(ctx, u.Username, id)
	}
	return nil
}

var _ sso.UserProvider = (*UserProvider)(nil)
var _ core.UserPaginationProvider = (*UserProvider)(nil)
var _ core.UserByUsernameProvider = (*UserProvider)(nil)
var _ core.UsernameCheckProvider = (*UserProvider)(nil)
