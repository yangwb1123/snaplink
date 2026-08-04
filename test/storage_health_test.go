package ssotest

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
	permsqlite "github.com/yangwb1123/snaplink/domains/permissions/sqlite"
	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

// memDSN returns a unique in-memory SQLite DSN. mode=memory + cache=shared
// keeps the schema alive across the pool's connections for the store's
// lifetime; the unique name keeps each store's namespace isolated so its
// migrate.Status reports only its own table.
func memDSN(name string) string {
	return "file:storage_health_" + name + "?mode=memory&cache=shared"
}

// pingDBStore is the contract a real SQLite store satisfies for the report:
// reachability (Ping) plus the underlying *sql.DB (DB) the cmd reaches for
// migrate.Status. This is exactly what cmd's appendStorageHealthSource type-
// asserts.
type pingDBStore interface {
	Ping(context.Context) error
	DB() *sql.DB
}

// pingDBSource adapts a real SQLite store into a StorageHealthSource the same
// way cmd's appendStorageHealthSource does: Ping for reachability, and a
// SchemaVersions closure over the store's *sql.DB driving migrate.Status.
func pingDBSource(name string, store pingDBStore) sso.StorageHealthSource {
	return sso.StorageHealthSource{
		Name: name,
		Ping: store.Ping,
		SchemaVersions: func(ctx context.Context) (map[string]int, error) {
			st, err := migrate.Status(ctx, store.DB())
			if err != nil {
				return nil, err
			}
			out := make(map[string]int, len(st))
			for _, ns := range st {
				out[ns.Namespace] = ns.Version
			}
			return out, nil
		},
	}
}

// twoRealStores spins up two real SQLite stores (clients + permissions) on
// distinct in-memory DBs and returns their storage-health sources plus a
// cleanup. Each store's migrate namespace ("clients" / "permissions") sits at
// the baseline version 1.
func twoRealStores(t *testing.T) []sso.StorageHealthSource {
	t.Helper()
	clients, err := sqlitestores.NewClientStore(memDSN("clients"))
	if err != nil {
		t.Fatalf("client store: %v", err)
	}
	t.Cleanup(func() { _ = clients.Close() })

	perms, err := permsqlite.New(memDSN("perms"))
	if err != nil {
		t.Fatalf("permissions store: %v", err)
	}
	t.Cleanup(func() { _ = perms.Close() })

	return []sso.StorageHealthSource{
		pingDBSource("sqlite-identity-clients", clients),
		pingDBSource("sqlite-permissions", perms),
	}
}

// storageHealthGET issues an unauthenticated GET against the bare server
// handler (no admin middleware) and decodes the JSON body.
func storageHealthGET(t *testing.T, srv *sso.Server) (int, map[string]any) {
	t.Helper()
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	resp, err := http.Get(httpSrv.URL + "/api/v1/admin/storage-health")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(body) > 0 {
		_ = json.Unmarshal(body, &out)
	}
	return resp.StatusCode, out
}

// storeByName indexes the report's stores array by name for assertions.
func storeByName(t *testing.T, body map[string]any) map[string]map[string]any {
	t.Helper()
	raw, ok := body["stores"].([]any)
	if !ok {
		t.Fatalf("missing stores array: %v", body)
	}
	byName := make(map[string]map[string]any, len(raw))
	for _, s := range raw {
		m, ok := s.(map[string]any)
		if !ok {
			t.Fatalf("store entry not an object: %v", s)
		}
		name, _ := m["name"].(string)
		byName[name] = m
	}
	return byName
}

// TestStorageHealth_ReportsReachableWithSchema wires two real SQLite stores
// and asserts the report shows both reachable with their baseline (v1)
// migrate namespaces.
func TestStorageHealth_ReportsReachableWithSchema(t *testing.T) {
	srv := sso.NewServer(sso.WithStorageHealth(twoRealStores(t)...))
	code, body := storageHealthGET(t, srv)
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	if _, ok := body["generated_at"].(string); !ok {
		t.Errorf("missing generated_at: %v", body)
	}
	byName := storeByName(t, body)

	clients, ok := byName["sqlite-identity-clients"]
	if !ok {
		t.Fatalf("missing clients store in report: %v", byName)
	}
	if r, _ := clients["reachable"].(bool); !r {
		t.Errorf("clients reachable = %v, want true", clients["reachable"])
	}
	sv, _ := clients["schema_versions"].(map[string]any)
	// clients sits at v6: v2 added the security-load-bearing fields (JWKS /
	// AllowedResources / AllowedRequestURIs / RegistrationAccessToken / JWE
	// alg-enc / Federation / PostLogoutRedirectURIs); v3 added
	// secret_rotated_at backing scheduled client-secret rotation; v4 added
	// client_trust_score / client_trust_set_at backing OAuth client trust
	// scoring; v5 added previous-secret overlap; v6 added secret expiry.
	if v, _ := sv["clients"].(float64); int(v) != 6 {
		t.Errorf("clients schema_versions[clients] = %v, want 6", sv)
	}
	if _, ok := clients["ping_latency_ms"]; !ok {
		t.Errorf("clients missing ping_latency_ms: %v", clients)
	}

	perms, ok := byName["sqlite-permissions"]
	if !ok {
		t.Fatalf("missing permissions store in report: %v", byName)
	}
	if r, _ := perms["reachable"].(bool); !r {
		t.Errorf("permissions reachable = %v, want true", perms["reachable"])
	}
	psv, _ := perms["schema_versions"].(map[string]any)
	if v, _ := psv["permissions"].(float64); int(v) != 1 {
		t.Errorf("permissions schema_versions[permissions] = %v, want 1", psv)
	}
}

// TestStorageHealth_OneStoreDownDoesNotFailReport closes one store's DB so
// its Ping fails; the endpoint must still return 200 with that store
// reachable:false + an error, while the healthy store still reports fine.
func TestStorageHealth_OneStoreDownDoesNotFailReport(t *testing.T) {
	healthy, err := sqlitestores.NewClientStore(memDSN("healthy"))
	if err != nil {
		t.Fatalf("healthy store: %v", err)
	}
	t.Cleanup(func() { _ = healthy.Close() })

	broken, err := sqlitestores.NewAuthCodeStore(memDSN("broken"))
	if err != nil {
		t.Fatalf("broken store: %v", err)
	}
	// Close the broken store's DB BEFORE serving so its Ping returns an
	// error — simulating a wedged/unreachable backend mid-DR-drill.
	if err := broken.Close(); err != nil {
		t.Fatalf("close broken: %v", err)
	}

	srv := sso.NewServer(sso.WithStorageHealth(
		pingDBSource("sqlite-identity-clients", healthy),
		pingDBSource("sqlite-oauth-auth-codes", broken),
	))
	code, body := storageHealthGET(t, srv)
	if code != http.StatusOK {
		t.Fatalf("status = %d (one store down must NOT 500 the report), body = %v", code, body)
	}
	byName := storeByName(t, body)

	h := byName["sqlite-identity-clients"]
	if r, _ := h["reachable"].(bool); !r {
		t.Errorf("healthy store reachable = %v, want true", h["reachable"])
	}

	b := byName["sqlite-oauth-auth-codes"]
	if r, _ := b["reachable"].(bool); r {
		t.Errorf("broken store reachable = %v, want false", b["reachable"])
	}
	if e, _ := b["error"].(string); e == "" {
		t.Errorf("broken store missing error string: %v", b)
	}
}

// newStorageHealthAdminHarness mounts the storage-health endpoint behind the
// real AdminMiddleware so the gating tests exercise the production
// /api/v1/admin/ prefix rule.
func newStorageHealthAdminHarness(t *testing.T, validClaims *sso.TokenClaims, prov permissions.Provider) *httptest.Server {
	t.Helper()
	srv := sso.NewServer(sso.WithStorageHealth(twoRealStores(t)...))
	mw := sso.NewAdminMiddleware(stubValidator{good: "good", claims: validClaims}, prov)
	httpSrv := httptest.NewServer(mw.HTTPMiddleware(srv.Handler()))
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func TestStorageHealth_AdminGated_NoToken401(t *testing.T) {
	srv := newStorageHealthAdminHarness(t, &sso.TokenClaims{Subject: "user-alice"}, adminProvider(t))
	resp := httpDo(t, "GET", srv.URL+"/api/v1/admin/storage-health", "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("missing WWW-Authenticate challenge on 401")
	}
}

func TestStorageHealth_AdminGated_NoScope403(t *testing.T) {
	srv := newStorageHealthAdminHarness(t, &sso.TokenClaims{Subject: "user-bob"}, nonAdminProvider(t))
	resp := httpDo(t, "GET", srv.URL+"/api/v1/admin/storage-health", "good")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestStorageHealth_AdminGated_WithScope200(t *testing.T) {
	srv := newStorageHealthAdminHarness(t, &sso.TokenClaims{Subject: "user-alice"}, adminProvider(t))
	resp := httpDo(t, "GET", srv.URL+"/api/v1/admin/storage-health", "good")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	if _, ok := out["stores"]; !ok {
		t.Errorf("missing stores in body: %v", out)
	}
}

// TestStorageHealth_OptInOff404 proves that without WithStorageHealth the
// route is not mounted (byte-identical to a build without the feature).
func TestStorageHealth_OptInOff404(t *testing.T) {
	srv := sso.NewServer() // no WithStorageHealth
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	resp, err := http.Get(httpSrv.URL + "/api/v1/admin/storage-health")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (route must not mount without WithStorageHealth)", resp.StatusCode)
	}
}
