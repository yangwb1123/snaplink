package sso_test

// rootcov_recovery_test.go drives the MFA recovery-code self-service endpoints
// (POST/GET /me/mfa/recovery-codes) and the admin reset
// (POST /api/v1/admin/users/:id/mfa/recovery-codes) in-directory so they count
// toward root unit coverage. Uses the shared rcov* helpers.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
)

// TestRcov_RecoveryCodes_SelfService covers generate (once), regenerate
// (revoke-then-generate, so the pool stays at N — not 2N), the count-only GET
// (never leaks codes), and the unauthenticated 401.
func TestRcov_RecoveryCodes_SelfService(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithRecoveryCodeStore(defaultimpl.NewMemoryRecoveryCodeStore()))
	access, _ := rcovDirectLogin(t, s)

	status, out := rcovPostJSON(t, s.http.URL+sso.PathMyMFARecoveryCodes, access, nil)
	if status != http.StatusCreated {
		t.Fatalf("generate = %d body=%v, want 201", status, out)
	}
	first, _ := out["recovery_codes"].([]any)
	if len(first) != core.DefaultRecoveryCodeCount {
		t.Fatalf("codes=%d want %d", len(first), core.DefaultRecoveryCodeCount)
	}
	if cnt, _ := out["count"].(float64); int(cnt) != core.DefaultRecoveryCodeCount {
		t.Fatalf("count=%v want %d", out["count"], core.DefaultRecoveryCodeCount)
	}

	// Regenerate: a fresh batch, and the pool stays at N (revoke-then-generate,
	// not append). Codes differ from the first batch.
	status, out2 := rcovPostJSON(t, s.http.URL+sso.PathMyMFARecoveryCodes, access, nil)
	if status != http.StatusCreated {
		t.Fatalf("regenerate = %d body=%v, want 201", status, out2)
	}
	second, _ := out2["recovery_codes"].([]any)
	if firstStr, secondStr := first[0].(string), second[0].(string); firstStr == secondStr {
		t.Fatalf("regenerate returned an identical first code %q — not a fresh batch", firstStr)
	}

	// GET returns the remaining count only, never the codes.
	status, cnt := rcovDo(t, http.MethodGet, s.http.URL+sso.PathMyMFARecoveryCodes, access, nil)
	if status != http.StatusOK {
		t.Fatalf("count GET = %d body=%v, want 200", status, cnt)
	}
	if _, leaked := cnt["recovery_codes"]; leaked {
		t.Fatalf("GET leaked recovery_codes: %v", cnt)
	}
	if rem, _ := cnt["remaining"].(float64); int(rem) != core.DefaultRecoveryCodeCount {
		t.Fatalf("remaining=%v want %d (revoke-then-generate keeps the pool at N)", cnt["remaining"], core.DefaultRecoveryCodeCount)
	}

	// Unauthenticated → 401 on both verbs (credential endpoint, oracle-safe).
	if status, _ := rcovPostJSON(t, s.http.URL+sso.PathMyMFARecoveryCodes, "", nil); status != http.StatusUnauthorized {
		t.Errorf("unauth POST = %d, want 401", status)
	}
	if status, _ := rcovDo(t, http.MethodGet, s.http.URL+sso.PathMyMFARecoveryCodes, "", nil); status != http.StatusUnauthorized {
		t.Errorf("unauth GET = %d, want 401", status)
	}

	// Audit: the regeneration event fired (twice), codes never recorded.
	if !hasRcovEvent(t, s.sink, audit.EventRecoveryCodesRegenerated) {
		t.Errorf("missing %q audit event", audit.EventRecoveryCodesRegenerated)
	}
}

// TestRcov_RecoveryCodes_AdminReset covers the helpdesk reset: it revokes the
// user's remaining codes (204, no body), and GET remaining then reads 0.
func TestRcov_RecoveryCodes_AdminReset(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryRecoveryCodeStore()
	env := rcovNewRecoveryAdminServer(t, store)

	// Seed a batch for the target user (the admin is rcovUser too, so the same
	// token both authorizes the reset and reads the post-reset count).
	if _, err := store.Generate(context.Background(), rcovUser, core.DefaultRecoveryCodeCount); err != nil {
		t.Fatalf("seed: %v", err)
	}

	status, _ := rcovDo(t, http.MethodPost, env.url+"/api/v1/admin/users/"+rcovUser+"/mfa/recovery-codes", env.token, nil)
	if status != http.StatusNoContent {
		t.Fatalf("admin reset = %d, want 204", status)
	}
	if n, _ := store.CountRemaining(context.Background(), rcovUser); n != 0 {
		t.Fatalf("remaining after admin reset = %d, want 0", n)
	}
	// Confirm via the user-facing count endpoint too.
	status, cnt := rcovDo(t, http.MethodGet, env.url+sso.PathMyMFARecoveryCodes, env.token, nil)
	if status != http.StatusOK {
		t.Fatalf("count GET = %d body=%v, want 200", status, cnt)
	}
	if rem, _ := cnt["remaining"].(float64); int(rem) != 0 {
		t.Fatalf("remaining=%v want 0", cnt["remaining"])
	}
}

// rcovRecoveryAdminEnv bundles the admin-gated server URL + a logged-in
// admin:* token for rcovUser.
type rcovRecoveryAdminEnv struct {
	url   string
	token string
}

// rcovNewRecoveryAdminServer builds a server wired with the recovery-code store
// behind AdminMiddleware authorizing rcovUser as admin:*, and returns a
// logged-in token. Mirrors rcovNewAdminServer (rootcov_admin_test.go).
func rcovNewRecoveryAdminServer(t *testing.T, store *defaultimpl.MemoryRecoveryCodeStore) *rcovRecoveryAdminEnv {
	t.Helper()
	ctx := context.Background()

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, AllowedAuthenticators: []string{"password"},
		TokenStrategy: "jwt", Active: true, SkipConsent: true,
	})

	prov := permissions.NewMemoryProvider()
	_ = prov.AddRole(ctx, "", permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, rcovUser, "", []string{"root"})
	_ = prov.AddRole(ctx, rcovClient, permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, rcovUser, rcovClient, []string{"root"})

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(rcovPasswordAuthAccepting()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPermissionProvider(prov),
		sso.WithRecoveryCodeStore(store),
	)

	mw := sso.NewAdminMiddleware(srv, prov)
	httpSrv := httptest.NewServer(mw.HTTPMiddleware(srv.Handler()))
	t.Cleanup(httpSrv.Close)

	status, out := rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	if status != http.StatusOK {
		t.Fatalf("admin login status=%d body=%v", status, out)
	}
	token, _ := out["access_token"].(string)
	if token == "" {
		t.Fatalf("no admin token: %v", out)
	}
	return &rcovRecoveryAdminEnv{url: httpSrv.URL, token: token}
}

// hasRcovEvent reports whether the sink holds an event of type et.
func hasRcovEvent(t *testing.T, sink *audit.MemorySink, et audit.EventType) bool {
	t.Helper()
	events, err := sink.Query(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("query sink: %v", err)
	}
	for _, e := range events {
		if e.Type == et {
			return true
		}
	}
	return false
}
