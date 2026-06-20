package redis

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
)

// newTestClient spins up an in-process miniredis fake and a go-redis
// client wired to it — no real Redis daemon needed in CI. The fake is
// torn down with the test. miniredis implements GET/SET/DEL/GETDEL/
// EXPIRE/SETNX/SADD/SREM/SMEMBERS/HSET/HMGET/SCAN/EXISTS and EVAL of the
// Lua we use, so the stores run against it exactly as against real Redis.
func newTestClient(t *testing.T) (*miniredis.Miniredis, *goredis.Client) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return mr, rdb
}
