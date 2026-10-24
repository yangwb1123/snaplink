package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/domains/permissions/permissionstest"
	permsqlite "github.com/yangwb1123/snaplink/domains/permissions/sqlite"
	"github.com/yangwb1123/snaplink/internal/pgtest"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

func resourcePeers(t *testing.T) (map[string]permissions.ResourceProvider, *PermissionProvider) {
	t.Helper()
	if os.Getenv("SSO_TEST_POSTGRES_DSN") == "" {
		t.Fatal("owned PostgreSQL fixture required; catalog coverage may not skip")
	}
	p, err := NewPermissionProvider(Config{DSN: pgtest.Schema(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	s, err := permsqlite.New("file:" + filepath.Join(t.TempDir(), "permissions.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return map[string]permissions.ResourceProvider{"memory": permissions.NewMemoryProvider(), "sqlite": s, "postgres": p}, p
}

func TestPostgresResourceConformance(t *testing.T) {
	permissionstest.ResourceConformanceSuite{Factory: func(t *testing.T) permissions.ResourceProvider {
		_, p := resourcePeers(t)
		return p
	}}.Run(t)
}

func resourceFixtures() []permissions.Resource {
	return []permissions.Resource{
		{ID: "http", Type: permissions.ResourceTypeHTTPAPI, Attributes: map[string]string{"method": "post", "path": "/users/:id"}},
		{ID: "grpc", Type: permissions.ResourceTypeGRPCAPI, Attributes: map[string]string{"service": "用户.v1.Service", "method": "Read"}},
		{ID: "graphql", Type: permissions.ResourceTypeGraphQLAPI, Attributes: map[string]string{"op": "query", "field": "readUser"}},
		{ID: "page", Type: permissions.ResourceTypePage, Attributes: map[string]string{"route": "/用户"}},
		{ID: "js", Type: permissions.ResourceTypeJSFn, Attributes: map[string]string{"route": "/用户", "symbol": "button.click"}},
		{ID: "ui", Type: permissions.ResourceTypeUIElement, Attributes: map[string]string{"page_id": "page", "selector": "#button", "element_kind": "button"}},
	}
}

func TestResourceCatalogTypeMatchingAcrossPeers(t *testing.T) {
	peers, pg := resourcePeers(t)
	for name, peer := range peers {
		t.Run(name, func(t *testing.T) { exerciseResources(t, peer) })
	}
	var key string
	if err := pg.db.QueryRowContext(t.Context(), "SELECT encode(dispatch_key,'hex') FROM permissions_resources WHERE id='grpc'").Scan(&key); err != nil {
		t.Fatal(err)
	}
	if key != hex.EncodeToString([]byte("用户.v1.Service\x00Read")) {
		t.Fatal("NUL-separated dispatch tuple bytes changed")
	}
}

func exerciseResources(t *testing.T, peer permissions.ResourceProvider) {
	t.Helper()
	for _, r := range resourceFixtures() {
		r.Name, r.TenantID, r.ClientID = r.ID, "tenant-a", "client-a"
		r.RequiresAuth, r.RequireMode = true, permissions.RequireAll
		r.RequiredPermissions = []string{"users:read", "audit:read"}
		if err := peer.RegisterResource(t.Context(), &r); err != nil {
			t.Fatal(err)
		}
		lookup := permissions.ResourceLookup{TenantID: r.TenantID, ClientID: r.ClientID, Type: r.Type, Match: r.Attributes}
		if r.Type == permissions.ResourceTypeHTTPAPI {
			lookup.Match = map[string]string{"method": "POST", "path": "/users/42"}
		}
		decision, err := peer.ResolveResource(t.Context(), lookup)
		if err != nil || !decision.Found || decision.ResourceID != r.ID || !decision.RequiresAuth || decision.RequireMode != permissions.RequireAll || !reflect.DeepEqual(decision.RequiredPermissions, r.RequiredPermissions) {
			t.Fatalf("%s decision=%+v err=%v", r.Type, decision, err)
		}
		lookup.TenantID = "tenant-b"
		if got, err := peer.ResolveResource(t.Context(), lookup); err != nil || got.Found {
			t.Fatal("tenant scope leaked", err)
		}
	}
}

func TestResourceCatalogUpsertConflictsScopeOrderAndTimestamp(t *testing.T) {
	peers, _ := resourcePeers(t)
	for name, peer := range peers {
		t.Run(name, func(t *testing.T) { exerciseResourceWrites(t, peer) })
	}
}

func exerciseResourceWrites(t *testing.T, peer permissions.ResourceProvider) {
	t.Helper()
	created := time.Unix(0, 9007199254740993).UTC()
	r := permissions.Resource{ID: "é", Name: "Key ", Type: permissions.ResourceTypePage, Attributes: map[string]string{"route": "/a"}, CreatedAt: created}
	if err := peer.RegisterResource(t.Context(), &r); err != nil {
		t.Fatal(err)
	}
	r.CreatedAt, r.Description, r.Attributes["route"] = time.Now(), "updated", "/b"
	if err := peer.RegisterResource(t.Context(), &r); err != nil {
		t.Fatal(err)
	}
	got, err := peer.GetResource(t.Context(), r.ID)
	if err != nil || !got.CreatedAt.Equal(created) || got.Description != "updated" || got.Attributes["route"] != "/b" {
		t.Fatal("upsert changed created time or lost fields", err)
	}
	r.ID = "conflict"
	if err := peer.RegisterResource(t.Context(), &r); !errors.Is(err, permissions.ErrResourceExists) {
		t.Fatal("scope/name conflict not classified", err)
	}
	r.ID, r.Name = "a", "Key"
	if err := peer.RegisterResource(t.Context(), &r); err != nil {
		t.Fatal("trailing-space name collapsed", err)
	}
	list, err := peer.ListResources(t.Context(), "", "")
	if err != nil || len(list) != 2 || list[0].ID != "a" || list[1].ID != "é" {
		t.Fatal("empty scope or byte-wise order changed", err)
	}
	if err := peer.DeleteResource(t.Context(), "missing"); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.GetResource(t.Context(), "missing"); !errors.Is(err, permissions.ErrResourceNotFound) {
		t.Fatal("missing resource not classified", err)
	}
}

func TestPostgresCatalogMalformedJSONCancelAndAheadFailClosed(t *testing.T) {
	_, p := resourcePeers(t)
	r := permissions.Resource{ID: "invalid-json", Name: "test", Type: permissions.ResourceTypePage, Attributes: map[string]string{"route": "/a"}}
	if err := p.RegisterResource(t.Context(), &r); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.ExecContext(t.Context(), "UPDATE permissions_resources SET attributes_json='{' WHERE id=$1", r.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := p.GetResource(t.Context(), r.ID); err == nil || got != nil {
		t.Fatal("malformed JSON became a valid resource")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := p.ResolveResource(ctx, permissions.ResourceLookup{Type: r.Type}); err == nil {
		t.Fatal("cancelled resolution returned a public miss")
	}
	if _, err := p.db.ExecContext(t.Context(), "UPDATE schema_migrations_permissions SET version=4 WHERE version=3"); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPermissionProviderWithDB(p.db, p.dialect); !errors.Is(err, migrate.ErrSchemaTooNew) {
		t.Fatal("ahead permissions schema accepted", err)
	}
}
