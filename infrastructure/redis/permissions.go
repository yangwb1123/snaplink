package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	goredis "github.com/redis/go-redis/v9"
	"github.com/snaplink/sso/domains/permissions"
)

// Key layout. Every key is namespaced under sso:perm: so one Redis logical
// DB can host this peer beside the client/session/token stores. The
// decomposition mirrors the SQLite peer's three tables:
//
//	sso:perm:roles:<client>           HASH  field=roleCode -> Role JSON
//	sso:perm:assign:<client>:<user>   SET   of role codes held by that user
//	sso:perm:assign:<client>:users    SET   of user ids with an assignment row
//	sso:perm:menus:<client>           STRING JSON-encoded MenuTree
//
// The per-client users index is the Redis analogue of the SQLite
// permissions_assignments client index: RemoveRole strips a role code out of
// every user's SET in one pass, and ListAssignments enumerates without a
// SCAN. Empty assignment SETs (every role removed) are deleted and pruned
// from the index lazily so ListAssignments' empty-roles filter holds.
const (
	permRolesPrefix  = "sso:perm:roles:"  // + <client>            -> HASH code->Role JSON
	permAssignPrefix = "sso:perm:assign:" // + <client>:<user>     -> SET of role codes
	permMenusPrefix  = "sso:perm:menus:"  // + <client>            -> MenuTree JSON
	permUsersSuffix  = ":users"           // sso:perm:assign:<client>:users SET of user ids
)

// PermissionProvider is the Redis-backed [permissions.Provider]. The memory
// peer loses state on restart and forks per-replica; the SQLite peer shares
// state through one file. This peer is the durable scale alternative: a
// multi-replica fleet shares one role/assignment/menu registry so an admin
// AddRole/AssignRoles/SetMenus on replica A surfaces on replica B's next
// /permissions/me lookup, without funnelling every replica through a single
// SQLite writer.
//
// Semantics are pinned to the memory peer via
// permissionstest.ConformanceSuite: AssignRoles is a SET (not a merge),
// RemoveRole strips the code from every assignment, Permissions deduplicates
// the union across assigned roles, Menus filters the tree by the resolved
// permission set, and the unknown-user lookups return ErrUserNotFound.
type PermissionProvider struct {
	rdb goredis.Cmdable
}

// NewPermissionProvider builds a PermissionProvider over an existing go-redis
// client (or cluster client — any goredis.Cmdable). The caller owns the
// client lifecycle.
func NewPermissionProvider(rdb goredis.Cmdable) *PermissionProvider {
	return &PermissionProvider{rdb: rdb}
}

// Ping reports Redis connection health for [sso.WithReadyCheck] wiring.
func (p *PermissionProvider) Ping(ctx context.Context) error {
	if p == nil || p.rdb == nil {
		return errors.New("redis: permission provider not initialized")
	}
	return p.rdb.Ping(ctx).Err()
}

func permRolesKey(clientID string) string { return permRolesPrefix + clientID }
func permMenusKey(clientID string) string { return permMenusPrefix + clientID }
func permUsersKey(clientID string) string { return permAssignPrefix + clientID + permUsersSuffix }
func permAssignKey(clientID, userID string) string {
	return permAssignPrefix + clientID + ":" + userID
}

// --- Role CRUD ---

// AddRole inserts a role into the client's role hash. Returns
// [permissions.ErrRoleExists] when the code is already present — HSETNX is
// the atomic existence gate (matches the SQLite PK collision contract), so a
// concurrent double-create maps to the sentinel exactly once.
func (p *PermissionProvider) AddRole(ctx context.Context, clientID string, role permissions.Role) error {
	raw, err := json.Marshal(role)
	if err != nil {
		return fmt.Errorf("redis: marshal role: %w", err)
	}
	ok, err := p.rdb.HSetNX(ctx, permRolesKey(clientID), role.Code, raw).Result()
	if err != nil {
		return fmt.Errorf("redis: add role: %w", err)
	}
	if !ok {
		return permissions.ErrRoleExists
	}
	return nil
}

// updateRoleScript overwrites an existing role field, refusing to create a
// missing one. HSET would happily insert a new field, so a plain HSET can't
// distinguish update from create — the script gates on HEXISTS first and
// returns 0 when absent (caller maps to ErrRoleNotFound), matching the SQLite
// peer's RowsAffected==0 contract. Running it server-side closes the check-
// then-write race a client-side HEXISTS+HSET would open against a concurrent
// RemoveRole.
//
// KEYS[1] = roles hash   ARGV[1] = role code   ARGV[2] = Role JSON
// Returns 1 on update, 0 when the role was absent.
var updateRoleScript = goredis.NewScript(`
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 0 then
  return 0
end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
return 1
`)

// UpdateRole overwrites an existing role. Returns
// [permissions.ErrRoleNotFound] when the code is absent.
func (p *PermissionProvider) UpdateRole(ctx context.Context, clientID string, role permissions.Role) error {
	raw, err := json.Marshal(role)
	if err != nil {
		return fmt.Errorf("redis: marshal role: %w", err)
	}
	res, err := updateRoleScript.Run(ctx, p.rdb,
		[]string{permRolesKey(clientID)}, role.Code, raw,
	).Int64()
	if err != nil {
		return fmt.Errorf("redis: update role: %w", err)
	}
	if res == 0 {
		return permissions.ErrRoleNotFound
	}
	return nil
}

// removeRoleScript drops a role definition AND strips its code from every
// user's assignment SET under the same client, atomically. It is the Redis
// analogue of the SQLite peer's transactional RemoveRole: without the single
// server-side script, a concurrent AssignRoles could re-introduce the code
// between the HDEL and the per-user SREM pass, leaving a dangling assignment
// the memory peer would never produce.
//
// KEYS[1] = roles hash   KEYS[2] = users index set
// ARGV[1] = role code    ARGV[2] = assignment key prefix ("sso:perm:assign:<client>:")
// Returns 1 on delete, 0 when the role was absent (caller maps to
// ErrRoleNotFound). An assignment SET emptied by the strip is deleted and its
// user pruned from the index so ListAssignments' empty-roles filter holds.
var removeRoleScript = goredis.NewScript(`
if redis.call('HDEL', KEYS[1], ARGV[1]) == 0 then
  return 0
end
local users = redis.call('SMEMBERS', KEYS[2])
for i = 1, #users do
  local akey = ARGV[2] .. users[i]
  redis.call('SREM', akey, ARGV[1])
  if redis.call('SCARD', akey) == 0 then
    redis.call('DEL', akey)
    redis.call('SREM', KEYS[2], users[i])
  end
end
return 1
`)

// RemoveRole drops the role definition and rips it out of every user's
// assignment list under the same client.
func (p *PermissionProvider) RemoveRole(ctx context.Context, clientID, roleCode string) error {
	res, err := removeRoleScript.Run(ctx, p.rdb,
		[]string{permRolesKey(clientID), permUsersKey(clientID)},
		roleCode, permAssignPrefix+clientID+":",
	).Int64()
	if err != nil {
		return fmt.Errorf("redis: remove role: %w", err)
	}
	if res == 0 {
		return permissions.ErrRoleNotFound
	}
	return nil
}

// ListAllRoles returns every role under clientID.
func (p *PermissionProvider) ListAllRoles(ctx context.Context, clientID string) ([]permissions.Role, error) {
	vals, err := p.rdb.HVals(ctx, permRolesKey(clientID)).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: list roles: %w", err)
	}
	out := make([]permissions.Role, 0, len(vals))
	for _, v := range vals {
		var r permissions.Role
		if err := json.Unmarshal([]byte(v), &r); err != nil {
			return nil, fmt.Errorf("redis: decode role: %w", err)
		}
		out = append(out, r)
	}
	return out, nil
}

// --- Assignments ---

// assignScript replaces the user's role SET (drop-then-repopulate so the SET
// semantics hold — a removed code must not survive a re-assign, which a bare
// SADD can't guarantee). An empty new set deletes the row and prunes the user
// from the client index so ListAssignments' empty-roles filter holds. All one
// server-side script so a concurrent reader never sees the half-written
// intermediate state between DEL and SADD.
//
// KEYS[1] = assignment set   KEYS[2] = users index set
// ARGV[1] = user id          ARGV[2..] = role codes (empty => clear)
var assignScript = goredis.NewScript(`
redis.call('DEL', KEYS[1])
if #ARGV < 2 then
  redis.call('SREM', KEYS[2], ARGV[1])
  return 0
end
for i = 2, #ARGV do
  redis.call('SADD', KEYS[1], ARGV[i])
end
redis.call('SADD', KEYS[2], ARGV[1])
return 1
`)

// AssignRoles replaces the user's role set under clientID. The memory peer
// treats this as a SET (not a merge); same here. An empty set deletes the
// assignment row and prunes the user from the client index so
// ListAssignments' empty-roles filter holds.
func (p *PermissionProvider) AssignRoles(ctx context.Context, userID, clientID string, roles []string) error {
	argv := make([]any, 0, len(roles)+1)
	argv = append(argv, userID)
	for _, r := range roles {
		argv = append(argv, r)
	}
	if err := assignScript.Run(ctx, p.rdb,
		[]string{permAssignKey(clientID, userID), permUsersKey(clientID)},
		argv...,
	).Err(); err != nil {
		return fmt.Errorf("redis: assign roles: %w", err)
	}
	return nil
}

// unassignScript removes the listed codes from the user's assignment SET and,
// when the SET is left empty, deletes it and prunes the user from the client
// index — all server-side so the SREM + emptiness check + index prune can't
// be split by a concurrent writer. ARGV[1..] are the codes to drop.
//
// KEYS[1] = assignment set   KEYS[2] = users index set
// ARGV[1] = user id          ARGV[2..] = role codes to remove
var unassignScript = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 0
end
for i = 2, #ARGV do
  redis.call('SREM', KEYS[1], ARGV[i])
end
if redis.call('SCARD', KEYS[1]) == 0 then
  redis.call('DEL', KEYS[1])
  redis.call('SREM', KEYS[2], ARGV[1])
end
return 1
`)

// UnassignRoles removes the listed role codes from the user's assignment
// under clientID. Codes not currently assigned are silently ignored; an
// assignment emptied by the removal is deleted and the user pruned from the
// client index (matches the memory + SQLite peers).
func (p *PermissionProvider) UnassignRoles(ctx context.Context, userID, clientID string, roles []string) error {
	if len(roles) == 0 {
		return nil
	}
	argv := make([]any, 0, len(roles)+1)
	argv = append(argv, userID)
	for _, r := range roles {
		argv = append(argv, r)
	}
	if err := unassignScript.Run(ctx, p.rdb,
		[]string{permAssignKey(clientID, userID), permUsersKey(clientID)},
		argv...,
	).Err(); err != nil {
		return fmt.Errorf("redis: unassign roles: %w", err)
	}
	return nil
}

// addRoleToUserScript grants roleCode without touching the user's other
// roles, keeping the assignment SET and the users index in lock-step. SADD is
// already idempotent (a present member is a no-op), so the SCIM "re-send a
// membership delta" case can't duplicate. One script so a crash can't add the
// code without indexing the user (which would hide them from ListAssignments).
//
// KEYS[1] = assignment set   KEYS[2] = users index set
// ARGV[1] = user id          ARGV[2] = role code
var addRoleToUserScript = goredis.NewScript(`
redis.call('SADD', KEYS[1], ARGV[2])
redis.call('SADD', KEYS[2], ARGV[1])
return 1
`)

// AddRoleToUser grants roleCode to userID under clientID without disturbing
// the user's other roles. Idempotent: re-adding an already-held role is a
// no-op. Implements [permissions.GroupMembershipWriter] (SCIM Group
// add-member).
func (p *PermissionProvider) AddRoleToUser(ctx context.Context, userID, clientID, roleCode string) error {
	if err := addRoleToUserScript.Run(ctx, p.rdb,
		[]string{permAssignKey(clientID, userID), permUsersKey(clientID)},
		userID, roleCode,
	).Err(); err != nil {
		return fmt.Errorf("redis: add role to user: %w", err)
	}
	return nil
}

// RemoveRoleFromUser revokes roleCode from userID under clientID, leaving the
// user's other roles intact. Idempotent: removing a role the user doesn't
// hold is a no-op. Implements [permissions.GroupMembershipWriter] (SCIM Group
// remove-member). Delegates to UnassignRoles so the emptied-assignment prune
// stays in one place.
func (p *PermissionProvider) RemoveRoleFromUser(ctx context.Context, userID, clientID, roleCode string) error {
	return p.UnassignRoles(ctx, userID, clientID, []string{roleCode})
}

// ListAssignments returns every (user, []roleCodes) tuple under clientID with
// at least one role. The users index is the enumeration source; an index
// entry whose assignment SET is gone (TTL/eviction can't apply here, but a
// crash between the SREM passes could orphan one) is pruned lazily and
// skipped so empty rows never surface.
func (p *PermissionProvider) ListAssignments(ctx context.Context, clientID string) ([]permissions.Assignment, error) {
	users, err := p.rdb.SMembers(ctx, permUsersKey(clientID)).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: list assignment users: %w", err)
	}
	out := make([]permissions.Assignment, 0, len(users))
	for _, u := range users {
		codes, err := p.rdb.SMembers(ctx, permAssignKey(clientID, u)).Result()
		if err != nil {
			return nil, fmt.Errorf("redis: list assignment roles: %w", err)
		}
		if len(codes) == 0 {
			// Orphan index entry — self-trim and skip the empty tuple.
			_ = p.rdb.SRem(ctx, permUsersKey(clientID), u).Err()
			continue
		}
		out = append(out, permissions.Assignment{UserID: u, Roles: codes})
	}
	return out, nil
}

// --- Menus ---

// SetMenus replaces the client's menu tree. Empty tree is a valid
// "no navigation" state.
func (p *PermissionProvider) SetMenus(ctx context.Context, clientID string, menus permissions.MenuTree) error {
	if menus == nil {
		menus = permissions.MenuTree{}
	}
	raw, err := json.Marshal(menus)
	if err != nil {
		return fmt.Errorf("redis: marshal menus: %w", err)
	}
	if err := p.rdb.Set(ctx, permMenusKey(clientID), raw, 0).Err(); err != nil {
		return fmt.Errorf("redis: store menus: %w", err)
	}
	return nil
}

// GetMenus returns the unfiltered menu tree for clientID. Implements
// [permissions.MenuLister] so snapshot/admin tooling can round-trip the tree
// without the per-user filter.
func (p *PermissionProvider) GetMenus(ctx context.Context, clientID string) (permissions.MenuTree, error) {
	raw, err := p.rdb.Get(ctx, permMenusKey(clientID)).Bytes()
	if errors.Is(err, goredis.Nil) {
		return permissions.MenuTree{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis: load menus: %w", err)
	}
	var out permissions.MenuTree
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("redis: decode menus: %w", err)
	}
	if out == nil {
		out = permissions.MenuTree{}
	}
	return out, nil
}

// --- Runtime queries ---

// Roles returns every Role object assigned to userID under clientID.
// Resolves the assigned code SET against the client's role hash; codes with
// no surviving definition (a role removed out of band) are skipped, matching
// the memory peer's "lookup-and-keep-present" behaviour. Returns
// [permissions.ErrUserNotFound] when the user holds no roles.
func (p *PermissionProvider) Roles(ctx context.Context, userID, clientID string) ([]permissions.Role, error) {
	codes, err := p.rdb.SMembers(ctx, permAssignKey(clientID, userID)).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: load assigned roles: %w", err)
	}
	if len(codes) == 0 {
		return nil, permissions.ErrUserNotFound
	}
	// MGet the definitions by field in one round trip.
	raws, err := p.rdb.HMGet(ctx, permRolesKey(clientID), codes...).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: load role defs: %w", err)
	}
	out := make([]permissions.Role, 0, len(raws))
	for _, v := range raws {
		// A nil entry is an assigned code whose definition no longer exists
		// (RemoveRole strips assignments, but a defensive skip keeps Roles
		// total against any drift) — skip rather than fail the lookup.
		s, ok := v.(string)
		if !ok {
			continue
		}
		var r permissions.Role
		if err := json.Unmarshal([]byte(s), &r); err != nil {
			return nil, fmt.Errorf("redis: decode role def: %w", err)
		}
		out = append(out, r)
	}
	return out, nil
}

// Permissions returns the union of permission codes from the user's assigned
// roles under clientID, deduplicated.
func (p *PermissionProvider) Permissions(ctx context.Context, userID, clientID string) ([]permissions.Permission, error) {
	roles, err := p.Roles(ctx, userID, clientID)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	out := make([]permissions.Permission, 0)
	for _, r := range roles {
		for _, code := range r.Permissions {
			if _, dup := seen[code]; dup {
				continue
			}
			seen[code] = struct{}{}
			out = append(out, permissions.Permission{Code: code})
		}
	}
	return out, nil
}

// Menus returns the per-user-filtered menu tree. Reuses the shared
// [permissions.FilterMenuTree] so the wire shape is byte-identical to the
// memory + SQLite peers.
func (p *PermissionProvider) Menus(ctx context.Context, userID, clientID string) (permissions.MenuTree, error) {
	full, err := p.GetMenus(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if len(full) == 0 {
		return permissions.MenuTree{}, nil
	}
	perms, err := p.Permissions(ctx, userID, clientID)
	if err != nil {
		// User has no roles -> empty filtered menu (the other peers return
		// the same — UIs render nothing rather than break).
		return permissions.MenuTree{}, nil
	}
	return permissions.FilterMenuTree(full, perms), nil
}

// Compile-time interface assertions.
var (
	_ permissions.Provider              = (*PermissionProvider)(nil)
	_ permissions.MenuLister            = (*PermissionProvider)(nil)
	_ permissions.GroupMembershipWriter = (*PermissionProvider)(nil)
)
