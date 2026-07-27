package ssotest

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/permissions"
	tenantmemory "github.com/yangwb1123/snaplink/domains/tenant/memory"
	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/grpcserver/grpcadmin"
	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	snapstorage "github.com/yangwb1123/snaplink/interfaces/snapshot/storageinline"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/releases"
	"github.com/yangwb1123/snaplink/platform/releases/pinnernoop"
	releasememory "github.com/yangwb1123/snaplink/platform/releases/storememory"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

// adminGRPCHarness bundles all stores and the gRPC connection so individual
// tests can call RPCs and assert on side effects.
type adminGRPCHarness struct {
	Conn       *grpc.ClientConn
	Clients    *defaultimpl.MemoryClientStore
	Users      *defaultimpl.MemoryUserProvider
	Sessions   *defaultimpl.MemorySessionManager
	Perms      *permissions.MemoryProvider
	Tenants    *tenantmemory.Store
	SnapStore  *snapstorage.Storage
	SnapPipe   *snapshot.Pipeline
	Snapper    *snapshot.Snapshotter
	Restorer   *snapshot.Restorer
	RelStore   *releasememory.Store
	Sink       *audit.MemorySink
	Recorder   *audit.Recorder
	TempTokens authenticators.TempTokenStore

	ctx        context.Context // pre-populated with admin bearer metadata
	adminToken string
}

// buildAdminGRPC spins up a bufconn-backed gRPC server with all 7 admin
// services registered behind the AdminMiddleware interceptor.
//
// The admin user "user-alice" is seeded with the admin:* scope (via
// adminProvider from admin_middleware_test.go) so every test can use
// h.ctx (which carries a "Bearer good" token) for authenticated calls.
//
// For unauthenticated / PermissionDenied tests, use context.Background()
// or mdCtx("wrong") from admin_middleware_test.go.
func buildAdminGRPC(t *testing.T) *adminGRPCHarness {
	t.Helper()

	// ----- in-memory stores -----
	clients := defaultimpl.NewMemoryClientStore()
	users := defaultimpl.NewMemoryUserProvider()
	sessions := defaultimpl.NewMemorySessionManager()
	perms := permissions.NewMemoryProvider()
	tenants := tenantmemory.New()
	snapStore := snapstorage.New()
	snapPipe := &snapshot.Pipeline{}
	relStore := releasememory.New()
	tempTokens := authenticators.NewMemoryTempTokenStore()
	sink := audit.NewMemorySink(100)
	rec := audit.New(sink)

	// Seed a client so users can log in (needed for client-admin tests
	// that reference existing clients).
	clients.AddSeed(&sso.Client{
		ID:                    "test-client",
		Secret:                "test-secret",
		Name:                  "Test Client",
		AllowedScopes:         []string{"openid"},
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
		Active:                true,
	})

	// ----- snapshotter + restorer (wire to the same stores) -----
	snapper := &snapshot.Snapshotter{
		Clients:     clients,
		Users:       users,
		Permissions: perms,
		Namespace:   "sso-server",
	}
	restorer := &snapshot.Restorer{
		Clients:     clients,
		Users:       users,
		Permissions: perms,
		Namespace:   "sso-server",
	}

	// ----- release registry -----
	registry := &releases.Registry{
		Store:  relStore,
		Pinner: noop.Pinner{},
	}

	// ----- admin middleware -----
	mw := sso.NewAdminMiddleware(
		stubValidator{good: "good", claims: &sso.TokenClaims{Subject: "user-alice"}},
		adminProvider(t),
	)

	// ----- gRPC server -----
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(
		grpc.UnaryInterceptor(mw.UnaryServerInterceptor()),
	)

	adminv1.RegisterClientAdminServiceServer(srv,
		grpcadmin.NewClientAdminService(clients, rec, nil, nil))
	adminv1.RegisterUserAdminServiceServer(srv,
		grpcadmin.NewUserAdminService(users, sessions, rec))
	adminv1.RegisterTokenAdminServiceServer(srv,
		grpcadmin.NewTokenAdminService(grpcadmin.TokenAdminConfig{
			Sessions:  sessions,
			TempStore: tempTokens,
			Recorder:  rec,
		}))
	adminv1.RegisterPermissionAdminServiceServer(srv,
		grpcadmin.NewPermissionAdminService(perms, rec, nil))
	adminv1.RegisterTenantAdminServiceServer(srv,
		grpcadmin.NewTenantAdminService(tenants, rec, nil, nil, nil))
	adminv1.RegisterSnapshotAdminServiceServer(srv,
		grpcadmin.NewSnapshotAdminService(snapPipe, snapStore, snapper, restorer, rec))
	adminv1.RegisterReleaseAdminServiceServer(srv,
		grpcadmin.NewReleaseAdminService(registry, relStore, rec))

	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	})

	// Pre-build an authenticated context so tests don't repeat this.
	adminCtx := metadata.NewOutgoingContext(
		context.Background(),
		metadata.Pairs("authorization", "Bearer good"),
	)

	return &adminGRPCHarness{
		Conn:       conn,
		Clients:    clients,
		Users:      users,
		Sessions:   sessions,
		Perms:      perms,
		Tenants:    tenants,
		SnapStore:  snapStore,
		SnapPipe:   snapPipe,
		Snapper:    snapper,
		Restorer:   restorer,
		RelStore:   relStore,
		Sink:       sink,
		Recorder:   rec,
		TempTokens: tempTokens,
		ctx:        adminCtx,
		adminToken: "good",
	}
}

// validClientProto returns a minimal proto Client for tests.
func validClientProto(id, name string) *adminv1.Client {
	return &adminv1.Client{
		Id:                    id,
		Name:                  name,
		Active:                true,
		AllowedAuthenticators: []string{"password"},
	}
}

// validUserProto returns a minimal proto User for tests.
func validUserProto(id string) *adminv1.User {
	return &adminv1.User{Id: id}
}

// validTenantProto returns a minimal proto Tenant for tests.
func validTenantProto(id, slug, name string) *adminv1.Tenant {
	return &adminv1.Tenant{
		Id:   id,
		Slug: slug,
		Name: name,
	}
}

// validReleaseProto returns a minimal proto Release for tests.
func validReleaseProto(id string, schema int32) *adminv1.Release {
	return &adminv1.Release{
		Id:            id,
		Channel:       releases.ChannelStable,
		SchemaVersion: schema,
		Frontend:      &adminv1.Artifact{GitRef: "v" + id},
		Backend:       &adminv1.Artifact{GitRef: "v" + id},
	}
}

// durationPtr is a helper for optional time.Duration fields.
func durationPtr(d time.Duration) *time.Duration { return &d }
