package redis

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

type markerFailureClient struct {
	goredis.Cmdable
	fail bool
}

func (c *markerFailureClient) Set(ctx context.Context, key string, value any, ttl time.Duration) *goredis.StatusCmd {
	if c.fail && strings.HasPrefix(key, rtFamilyMemPrefix) {
		return goredis.NewStatusResult("", errors.New("injected reuse-marker write failure"))
	}
	return c.Cmdable.Set(ctx, key, value, ttl)
}

func TestRefreshConsumeRequiresDurableReuseMarker(t *testing.T) {
	_, client := newTestClient(t)
	fault := &markerFailureClient{Cmdable: client, fail: true}
	store := NewRefreshTokenStore(fault)
	ctx := context.Background()
	info := newRTInfo("alice", "app", "family")
	if err := store.Issue(ctx, "original", info); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Consume(ctx, "original"); err == nil || got != nil {
		t.Fatalf("marker uncertainty returned a grant: %v %v", got, err)
	}
	if _, err := store.Inspect(ctx, "original"); err != nil {
		t.Fatalf("failed marker write deleted the active token: %v", err)
	}
	fault.fail = false
	if _, err := store.Consume(ctx, "original"); err != nil {
		t.Fatal(err)
	}
	if err := store.Issue(ctx, "successor", info); err != nil {
		t.Fatal(err)
	}
	reused, err := store.Consume(ctx, "original")
	if !errors.Is(err, oauth.ErrRefreshTokenReused) || reused == nil || reused.FamilyID != info.FamilyID {
		t.Fatalf("reuse evidence lost: %v %v", reused, err)
	}
	if _, err := store.DeleteFamily(ctx, reused.FamilyID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Inspect(ctx, "successor"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Fatalf("descendant survived family kill: %v", err)
	}
}

func TestRefreshConsumeMarkerCoversRemainingGrantLifetime(t *testing.T) {
	server, client := newTestClient(t)
	store := NewRefreshTokenStore(client, WithFamilyTTL(time.Second))
	info := newRTInfo("alice", "app", "family")
	info.ExpiresAt = time.Now().Add(time.Hour)
	if err := store.Issue(context.Background(), "original", info); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(context.Background(), "original"); err != nil {
		t.Fatal(err)
	}
	if ttl := server.TTL(rtFamilyMemKey("original")); ttl < 59*time.Minute {
		t.Fatalf("reuse evidence expires before original grant: %v", ttl)
	}
}

func TestRefreshGraceRedisKeysDoNotExposeConsumedCredentials(t *testing.T) {
	_, client := newTestClient(t)
	store := NewRefreshGraceStore(client, time.Minute)
	raw := "consumed-credential-that-must-not-be-a-key"
	body := map[string]any{core.KeyAccessToken: "access", core.KeyRefreshToken: "successor"}
	store.Remember(raw, body, time.Now())
	assertRedisDumpExcludes(t, client, raw)
	if got, ok := store.Lookup(raw, time.Now()); !ok || got[core.KeyRefreshToken] != "successor" {
		t.Fatalf("hashed lookup failed: %v %v", got, ok)
	}
}

func TestRefreshGraceDoesNotReadLegacyPlaintextKeys(t *testing.T) {
	_, client := newTestClient(t)
	if err := client.Set(context.Background(), "sso:rtgrace:legacy-secret", `{"refresh_token":"successor"}`, time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	store := NewRefreshGraceStore(client, time.Minute)
	if _, ok := store.Lookup("legacy-secret", time.Now()); ok {
		t.Fatal("legacy plaintext-key cache was replayed")
	}
}
