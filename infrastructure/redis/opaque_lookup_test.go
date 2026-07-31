package redis

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

var (
	redisLookupCurrent  = []byte("0123456789abcdef0123456789abcdef")
	redisLookupPrevious = []byte("abcdef0123456789abcdef0123456789")
)

func TestOpaqueLookupHMACProtectsRedisArtifacts(t *testing.T) {
	t.Run("authorization code", testRedisAuthCodeHMAC)
	t.Run("refresh token", testRedisRefreshTokenHMAC)
	t.Run("device codes", testRedisDeviceCodeHMAC)
	t.Run("PAR request URI", testRedisPARHMAC)
}

func testRedisAuthCodeHMAC(t *testing.T) {
	_, rdb := newTestClient(t)
	store := NewAuthCodeStore(rdb)
	store.SetLookupHMACKeys(redisLookupCurrent)
	raw := "authorization-code-raw-secret"
	mustRedisLookup(t, store.Issue(context.Background(), raw, &oauth.AuthCode{
		ClientID: "app", ExpiresAt: time.Now().Add(time.Minute),
	}))
	assertRedisDumpExcludes(t, rdb, raw)
	_, err := store.Consume(context.Background(), raw)
	mustRedisLookup(t, err)
}

func testRedisRefreshTokenHMAC(t *testing.T) {
	_, rdb := newTestClient(t)
	store := NewRefreshTokenStore(rdb)
	store.SetLookupHMACKeys(redisLookupCurrent)
	raw := "refresh-token-raw-secret"
	mustRedisLookup(t, store.Issue(context.Background(), raw, newRTInfo("alice", "app", "family")))
	assertRedisDumpExcludes(t, rdb, raw)
	_, err := store.Consume(context.Background(), raw)
	mustRedisLookup(t, err)
	assertRedisDumpExcludes(t, rdb, raw)
	if _, err := store.Consume(context.Background(), raw); !errors.Is(err, oauth.ErrRefreshTokenReused) {
		t.Fatalf("replay err = %v, want ErrRefreshTokenReused", err)
	}
}

func testRedisDeviceCodeHMAC(t *testing.T) {
	_, rdb := newTestClient(t)
	store := NewDeviceCodeStore(rdb)
	store.SetLookupHMACKeys(redisLookupCurrent)
	deviceRaw, userRaw := "device-code-raw-secret", "user-code-raw-secret"
	mustRedisLookup(t, store.Issue(context.Background(), &oauth.DeviceCode{
		DeviceCode: deviceRaw, UserCode: userRaw, ClientID: "app",
		ExpiresAt: time.Now().Add(time.Minute),
	}))
	assertRedisDumpExcludes(t, rdb, deviceRaw, userRaw)
	byDevice, err := store.GetByDeviceCode(context.Background(), deviceRaw)
	mustRedisLookup(t, err)
	if byDevice.DeviceCode != deviceRaw {
		t.Fatalf("device lookup lost caller-facing code: %+v", byDevice)
	}
	byUser, err := store.GetByUserCode(context.Background(), userRaw)
	mustRedisLookup(t, err)
	if byUser.UserCode != userRaw {
		t.Fatalf("user lookup lost caller-facing code: %+v", byUser)
	}
	mustRedisLookup(t, store.Approve(context.Background(), userRaw, "alice", "password", nil))
	assertRedisDumpExcludes(t, rdb, deviceRaw, userRaw)
	consumed, err := store.ConsumeIfApproved(context.Background(), deviceRaw)
	mustRedisLookup(t, err)
	if consumed.UserID != "alice" {
		t.Fatalf("approved identity lost: %+v", consumed)
	}
}

func testRedisPARHMAC(t *testing.T) {
	_, rdb := newTestClient(t)
	store := NewPARStore(rdb)
	store.SetLookupHMACKeys(redisLookupCurrent)
	uri, err := store.Issue(context.Background(), &oauth.PARRequest{
		ClientID: "app", ExpiresAt: time.Now().Add(time.Minute),
	})
	mustRedisLookup(t, err)
	assertRedisDumpExcludes(t, rdb, uri)
	_, err = store.Consume(context.Background(), uri)
	mustRedisLookup(t, err)
}

func TestOpaqueLookupHMACReadsPreviousAndLegacyRedisRecords(t *testing.T) {
	_, rdb := newTestClient(t)
	old := NewAuthCodeStore(rdb)
	old.SetLookupHMACKeys(redisLookupPrevious)
	mustRedisLookup(t, old.Issue(context.Background(), "previous-code", &oauth.AuthCode{
		ClientID: "app", ExpiresAt: time.Now().Add(time.Minute),
	}))
	rotated := NewAuthCodeStore(rdb)
	rotated.SetLookupHMACKeys(redisLookupCurrent, redisLookupPrevious)
	_, err := rotated.Consume(context.Background(), "previous-code")
	mustRedisLookup(t, err)

	legacy := NewPARStore(rdb)
	uri, err := legacy.Issue(context.Background(), &oauth.PARRequest{
		ClientID: "app", ExpiresAt: time.Now().Add(time.Minute),
	})
	mustRedisLookup(t, err)
	legacy.SetLookupHMACKeys(redisLookupCurrent, redisLookupPrevious)
	_, err = legacy.Consume(context.Background(), uri)
	mustRedisLookup(t, err)
}

func assertRedisDumpExcludes(t *testing.T, rdb goredis.Cmdable, raw ...string) {
	t.Helper()
	ctx := context.Background()
	keys, err := rdb.Keys(ctx, "*").Result()
	mustRedisLookup(t, err)
	for _, key := range keys {
		assertNoRaw(t, key, raw)
		kind, err := rdb.Type(ctx, key).Result()
		mustRedisLookup(t, err)
		switch kind {
		case "string":
			value, err := rdb.Get(ctx, key).Result()
			mustRedisLookup(t, err)
			assertNoRaw(t, value, raw)
		case "set":
			values, err := rdb.SMembers(ctx, key).Result()
			mustRedisLookup(t, err)
			for _, value := range values {
				assertNoRaw(t, value, raw)
			}
		}
	}
}

func assertNoRaw(t *testing.T, value string, raw []string) {
	t.Helper()
	for _, secret := range raw {
		if strings.Contains(value, secret) {
			t.Fatalf("raw OAuth artifact %q survived in Redis data %q", secret, value)
		}
	}
}

func mustRedisLookup(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
