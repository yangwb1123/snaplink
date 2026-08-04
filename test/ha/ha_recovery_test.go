package ha_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	redisbackend "github.com/yangwb1123/snaplink/infrastructure/redis"
	"github.com/yangwb1123/snaplink/platform/cluster"
	clusteretcd "github.com/yangwb1123/snaplink/platform/cluster/etcd"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

const (
	redisAddr   = "127.0.0.1:26379"
	postgresDSN = "postgres://snaplink:snaplink-test@127.0.0.1:25432/snaplink?sslmode=disable&connect_timeout=1"
	etcdAddr    = "127.0.0.1:22379"
)

func TestRealMultiReplicaFailureRecovery(t *testing.T) {
	if os.Getenv("SNAPLINK_HA_TEST") != "1" {
		t.Skip("set SNAPLINK_HA_TEST=1 and start ops/deploy/ha-test/compose.yaml")
	}
	redisProxy := newTCPProxy(t, redisAddr, "127.0.0.1:26380")
	postgresProxy := newTCPProxy(t, "127.0.0.1:25432", "127.0.0.1:25433")
	etcdProxy := newTCPProxy(t, etcdAddr, "127.0.0.1:22380")
	t.Run("redis hot stores", func(t *testing.T) { testRedisReplicaRecovery(t, redisProxy) })
	t.Run("postgres durable store", func(t *testing.T) { testPostgresReplicaRecovery(t, postgresProxy) })
	t.Run("etcd invalidation bus", func(t *testing.T) { testEtcdReplicaRecovery(t, etcdProxy) })
}

func testRedisReplicaRecovery(t *testing.T, proxy *tcpProxy) {
	ctx := context.Background()
	clientA := newRedisClient(t)
	clientB := newRedisClient(t)
	mustHA(t, clientA.FlushDB(ctx).Err())
	authA, authB := redisbackend.NewAuthCodeStore(clientA), redisbackend.NewAuthCodeStore(clientB)
	authA.SetLookupHMACKeys([]byte("0123456789abcdef0123456789abcdef"))
	authB.SetLookupHMACKeys([]byte("0123456789abcdef0123456789abcdef"))
	mustHA(t, authA.Issue(ctx, "cross-replica-code", &oauth.AuthCode{
		UserID: "admin", ClientID: "app", ExpiresAt: time.Now().Add(time.Minute),
	}))
	_, err := authB.Consume(ctx, "cross-replica-code")
	mustHA(t, err)
	testRefreshFamilyAcrossRedisReplicas(t, clientA, clientB)

	proxy.SetEnabled(false)
	assertFailsWithin(t, redisPing(clientA))
	proxy.SetEnabled(true)
	waitHealthy(t, redisPing(clientB))
	mustHA(t, authB.Issue(ctx, "after-recovery", &oauth.AuthCode{
		UserID: "admin", ClientID: "app", ExpiresAt: time.Now().Add(time.Minute),
	}))
	_, err = authA.Consume(ctx, "after-recovery")
	mustHA(t, err)
}

func testRefreshFamilyAcrossRedisReplicas(t *testing.T, clientA, clientB goredis.Cmdable) {
	ctx := context.Background()
	storeA := redisbackend.NewRefreshTokenStore(clientA)
	storeB := redisbackend.NewRefreshTokenStore(clientB)
	info := &oauth.RefreshToken{
		UserID: "admin", ClientID: "app", FamilyID: "family-ha",
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}
	mustHA(t, storeA.Issue(ctx, "refresh-parent", info))
	_, err := storeB.Consume(ctx, "refresh-parent")
	mustHA(t, err)
	mustHA(t, storeB.Issue(ctx, "refresh-leaf", info))
	reused, err := storeA.Consume(ctx, "refresh-parent")
	if !errors.Is(err, oauth.ErrRefreshTokenReused) || reused.FamilyID != "family-ha" {
		t.Fatalf("cross-replica reuse = (%+v, %v)", reused, err)
	}
	deleted, err := storeA.DeleteFamily(ctx, "family-ha")
	if err != nil || deleted != 1 {
		t.Fatalf("cross-replica family delete = (%d, %v)", deleted, err)
	}
	if _, err := storeB.Inspect(ctx, "refresh-leaf"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Fatalf("family leaf survived cross-replica delete: %v", err)
	}
}

func testPostgresReplicaRecovery(t *testing.T, proxy *tcpProxy) {
	cfg := postgresbackend.Config{DSN: postgresDSN, Dialect: postgresbackend.DialectPostgres}
	storeA, err := postgresbackend.NewPairwiseSubjectStore(cfg)
	mustHA(t, err)
	t.Cleanup(func() { _ = storeA.Close() })
	storeB, err := postgresbackend.NewPairwiseSubjectStore(cfg)
	mustHA(t, err)
	t.Cleanup(func() { _ = storeB.Close() })
	ctx := context.Background()
	mustHA(t, storeA.MapPairwise(ctx, "pairwise-ha", "admin"))
	local, err := storeB.LocalSubject(ctx, "pairwise-ha")
	if err != nil || local != "admin" {
		t.Fatalf("cross-replica durable read = (%q, %v)", local, err)
	}
	proxy.SetEnabled(false)
	assertFailsWithin(t, storeA.Ping)
	proxy.SetEnabled(true)
	waitHealthy(t, storeB.Ping)
	mustHA(t, storeB.MapPairwise(ctx, "pairwise-ha-2", "admin"))
	_, err = storeA.LocalSubject(ctx, "pairwise-ha-2")
	mustHA(t, err)
}

func testEtcdReplicaRecovery(t *testing.T, proxy *tcpProxy) {
	cfg := clusteretcd.Config{
		Endpoints: []string{etcdAddr}, Prefix: "/snaplink/ha-test",
		DialTimeout: time.Second, EventTTL: 5 * time.Second,
	}
	busA, err := clusteretcd.New(cfg)
	mustHA(t, err)
	t.Cleanup(func() { _ = busA.Close() })
	busB, err := clusteretcd.New(cfg)
	mustHA(t, err)
	t.Cleanup(func() { _ = busB.Close() })
	assertBusEvent(t, busA, busB, "before-failure")

	proxy.SetEnabled(false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	err = busA.Publish(ctx, cluster.Event{Kind: cluster.KindClientChange, Key: "during-failure"})
	cancel()
	if err == nil {
		t.Fatal("etcd publish succeeded while transport was disabled")
	}
	proxy.SetEnabled(true)
	assertBusEvent(t, busA, busB, "after-recovery")
}

func assertBusEvent(t *testing.T, publisher, subscriber cluster.Bus, key string) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	events, err := subscriber.Subscribe(ctx)
	mustHA(t, err)
	time.Sleep(150 * time.Millisecond)
	mustHA(t, publisher.Publish(ctx, cluster.Event{Kind: cluster.KindClientChange, Key: key}))
	select {
	case event := <-events:
		if event.Key != key || event.Kind != cluster.KindClientChange {
			t.Fatalf("event = %+v, want key %q", event, key)
		}
	case <-ctx.Done():
		t.Fatalf("event %q not delivered after recovery", key)
	}
}

func newRedisClient(t *testing.T) *goredis.Client {
	t.Helper()
	client := goredis.NewClient(&goredis.Options{
		Addr: redisAddr, DialTimeout: 500 * time.Millisecond,
		ReadTimeout: 500 * time.Millisecond, WriteTimeout: 500 * time.Millisecond,
		MaxRetries: 0,
	})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func redisPing(client goredis.Cmdable) func(context.Context) error {
	return func(ctx context.Context) error { return client.Ping(ctx).Err() }
}

func assertFailsWithin(t *testing.T, ping func(context.Context) error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := ping(ctx); err == nil {
		t.Fatal("backend remained reachable while proxy was disabled")
	}
}

func waitHealthy(t *testing.T, ping func(context.Context) error) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := ping(ctx)
		cancel()
		if err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("backend did not recover before deadline")
}

func mustHA(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
