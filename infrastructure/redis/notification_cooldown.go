package redis

import (
	"context"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/platform/lifecycle/notification"
)

// cooldownKeyPrefix scopes the notification-cooldown keys.
const cooldownKeyPrefix = "sso:notifcooldown:" // sso:notifcooldown:<key> -> unix-nano until

// NotificationCooldown is the Redis-backed [notification.CooldownStore] —
// the cluster-shared peer of the router's in-process map. Two replicas
// seeing the same audit event agree on the suppression window, so a
// per-{subject,type} cooldown is no longer per-replica. The check-and-set
// is one Lua op, and the key's TTL equals the cooldown so a silent subject
// leaves no residue.
type NotificationCooldown struct {
	rdb goredis.Cmdable
}

// NewNotificationCooldown builds the store over an existing go-redis client
// (or cluster client — any goredis.Cmdable). The caller owns the client
// lifecycle.
func NewNotificationCooldown(rdb goredis.Cmdable) *NotificationCooldown {
	return &NotificationCooldown{rdb: rdb}
}

// cooldownScript is the atomic check-and-set: suppressed when the stored
// until is in the future; otherwise record until = now+cooldown with a TTL
// of exactly cooldown (the key can never outlive its window).
//
// KEYS[1] = cooldown key
// ARGV[1] = now unix-nano  ARGV[2] = until unix-nano  ARGV[3] = ttl ms
// returns 1 (suppressed) or 0 (proceed)
var cooldownScript = goredis.NewScript(`
local deadline = redis.call('GET', KEYS[1])
if deadline and tonumber(deadline) > tonumber(ARGV[1]) then
  return 1
end
redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3])
return 0
`)

// Suppressed implements notification.CooldownStore. Errors are returned for
// Redis failures only — the router fails open on them.
func (s *NotificationCooldown) Suppressed(ctx context.Context, key string, now time.Time, cooldown time.Duration) (bool, error) {
	if cooldown <= 0 {
		return false, nil
	}
	until := now.Add(cooldown)
	res, err := cooldownScript.Run(ctx, s.rdb, []string{cooldownKeyPrefix + key},
		now.UnixNano(), until.UnixNano(), cooldown.Milliseconds()).Int64()
	if err != nil {
		return false, fmt.Errorf("redis: notification cooldown: %w", err)
	}
	return res == 1, nil
}

var _ notification.CooldownStore = (*NotificationCooldown)(nil)
