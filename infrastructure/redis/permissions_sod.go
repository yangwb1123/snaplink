package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/domains/permissions"
)

const (
	redisStaticSoDMode       = "static"
	redisDynamicSoDMode      = "dynamic"
	permSoDPrefix            = "sso:perm:sod:"
	permActivePrefix         = "sso:perm:active:"
	permActiveSessionsSuffix = ":active_sessions"
)

type activeSessionSettings struct {
	ttl time.Duration
}

// NewPermissionProviderWithActiveSessionTTL enables expiry for dynamic role
// projections. A non-positive TTL preserves the historical no-expiry mode.
func NewPermissionProviderWithActiveSessionTTL(rdb goredis.Cmdable, ttl time.Duration) *PermissionProvider {
	if ttl < 0 {
		ttl = 0
	}
	return &PermissionProvider{rdb: rdb, activeSessionSettings: activeSessionSettings{ttl: ttl}}
}

func (p *PermissionProvider) activeSessionTTL() time.Duration {
	return p.activeSessionSettings.ttl
}

// Every per-client key carries a {clientID} hash tag so role, assignment, and
// active-session keys share one Redis Cluster slot for lifecycle scripts.
func permRolesKey(clientID string) string { return permRolesPrefix + hashTag(clientID) }
func permMenusKey(clientID string) string { return permMenusPrefix + hashTag(clientID) }
func permUsersKey(clientID string) string {
	return permAssignPrefix + hashTag(clientID) + permUsersSuffix
}
func permAssignKey(clientID, userID string) string {
	return permAssignPrefix + hashTag(clientID) + ":" + userID
}

func permSoDKey(clientID, mode string) string {
	return permSoDPrefix + hashTag(clientID) + ":" + mode
}

func permActiveKey(clientID, userID, sessionID string) string {
	return permActivePrefix + hashTag(clientID) + ":" + userID + ":" + sessionID
}

func permActiveSessionsKey(clientID, userID string) string {
	return permActivePrefix + hashTag(clientID) + ":" + userID + permActiveSessionsSuffix
}

func permActiveKeyPrefix(clientID string) string {
	return permActivePrefix + hashTag(clientID) + ":"
}

var deactivateSessionScript = goredis.NewScript(`
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[1])
if redis.call('SCARD', KEYS[2]) == 0 then
  redis.call('DEL', KEYS[2])
end
return 1
`)

func (p *PermissionProvider) SetConflictSets(ctx context.Context, clientID string, sets [][]string) error {
	return p.replaceConflictSets(ctx, clientID, redisStaticSoDMode, sets)
}

func (p *PermissionProvider) ConflictSets(ctx context.Context, clientID string) ([][]string, error) {
	return p.loadConflictSets(ctx, clientID, redisStaticSoDMode)
}

func (p *PermissionProvider) SetActivationConflictSets(ctx context.Context, clientID string, sets [][]string) error {
	return p.replaceConflictSets(ctx, clientID, redisDynamicSoDMode, sets)
}

func (p *PermissionProvider) ActivationConflictSets(ctx context.Context, clientID string) ([][]string, error) {
	return p.loadConflictSets(ctx, clientID, redisDynamicSoDMode)
}

func (p *PermissionProvider) replaceConflictSets(ctx context.Context, clientID, mode string, sets [][]string) error {
	if err := permissions.ValidateConflictSets(sets); err != nil {
		return err
	}
	key := permSoDKey(clientID, mode)
	if len(sets) == 0 {
		if err := p.rdb.Del(ctx, key).Err(); err != nil {
			return fmt.Errorf("redis: clear conflict sets: %w", err)
		}
		return nil
	}
	raw, err := json.Marshal(sets)
	if err != nil {
		return fmt.Errorf("redis: marshal conflict sets: %w", err)
	}
	if err := p.rdb.Set(ctx, key, raw, 0).Err(); err != nil {
		return fmt.Errorf("redis: store conflict sets: %w", err)
	}
	return nil
}

func (p *PermissionProvider) loadConflictSets(ctx context.Context, clientID, mode string) ([][]string, error) {
	raw, err := p.rdb.Get(ctx, permSoDKey(clientID, mode)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis: load conflict sets: %w", err)
	}
	var sets [][]string
	if err := json.Unmarshal(raw, &sets); err != nil {
		return nil, fmt.Errorf("redis: decode conflict sets: %w", err)
	}
	return sets, nil
}

func (p *PermissionProvider) checkStaticConflict(ctx context.Context, clientID string, roles []string) error {
	sets, err := p.loadConflictSets(ctx, clientID, redisStaticSoDMode)
	if err != nil {
		return err
	}
	return permissions.CheckRoleConflict(clientID, sets, roles)
}

// ActivateRoles validates assigned ownership and both conflict tables before
// replacing the session's active role subset. The active projection is stored
// as one JSON value so readers never observe a partially written set.
func (p *PermissionProvider) ActivateRoles(ctx context.Context, userID, clientID, sessionID string, roles []string) error {
	if len(roles) > 0 {
		held, err := p.rdb.SMembers(ctx, permAssignKey(clientID, userID)).Result()
		if err != nil {
			return fmt.Errorf("redis: load assigned roles: %w", err)
		}
		for _, code := range roles {
			if !containsCode(held, code) {
				return fmt.Errorf("%w: %q", permissions.ErrRoleNotAssigned, code)
			}
		}
	}
	static, err := p.loadConflictSets(ctx, clientID, redisStaticSoDMode)
	if err != nil {
		return err
	}
	dynamic, err := p.loadConflictSets(ctx, clientID, redisDynamicSoDMode)
	if err != nil {
		return err
	}
	if conflict := permissions.CheckRoleConflict(clientID, append(static, dynamic...), roles); conflict != nil {
		return conflict
	}
	raw, err := json.Marshal(roles)
	if err != nil {
		return fmt.Errorf("redis: marshal active roles: %w", err)
	}
	pipe := p.rdb.TxPipeline()
	index := permActiveSessionsKey(clientID, userID)
	pipe.Set(ctx, permActiveKey(clientID, userID, sessionID), raw, p.activeSessionTTL())
	pipe.SAdd(ctx, index, sessionID)
	if ttl := p.activeSessionTTL(); ttl > 0 {
		pipe.Expire(ctx, index, ttl)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis: store active roles: %w", err)
	}
	return nil
}

func (p *PermissionProvider) ActiveRoles(ctx context.Context, userID, clientID, sessionID string) ([]permissions.Role, error) {
	raw, err := p.rdb.Get(ctx, permActiveKey(clientID, userID, sessionID)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis: load active roles: %w", err)
	}
	var codes []string
	if err := json.Unmarshal(raw, &codes); err != nil {
		return nil, fmt.Errorf("redis: decode active roles: %w", err)
	}
	if len(codes) == 0 {
		return nil, nil
	}
	assigned, err := p.Roles(ctx, userID, clientID)
	if errors.Is(err, permissions.ErrUserNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	byCode := make(map[string]permissions.Role, len(assigned))
	for _, role := range assigned {
		byCode[role.Code] = role
	}
	out := make([]permissions.Role, 0, len(codes))
	for _, code := range codes {
		if role, ok := byCode[code]; ok {
			out = append(out, role)
		}
	}
	return out, nil
}

func (p *PermissionProvider) DeactivateSession(ctx context.Context, userID, clientID, sessionID string) error {
	if err := deactivateSessionScript.Run(ctx, p.rdb, []string{
		permActiveKey(clientID, userID, sessionID),
		permActiveSessionsKey(clientID, userID),
	}, sessionID).Err(); err != nil {
		return fmt.Errorf("redis: deactivate session: %w", err)
	}
	return nil
}

func containsCode(codes []string, want string) bool {
	for _, code := range codes {
		if code == want {
			return true
		}
	}
	return false
}
