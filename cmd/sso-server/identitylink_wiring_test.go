package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildplatform"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/identitylink"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// identitylink_wiring_test.go proves the cmd/sso-server composition-root
// wiring for domains/identitylink (wireIdentityLink, build_stores.go):
// self_service.identity_link.enabled mounts GET/DELETE /me/identities, an
// explicit merge_policy: link_only opts into the auto-merge strategy, and —
// before this wiring existed — cmd/sso-server never called
// sso.WithIdentityLinkStore regardless of config (build_authenticators.go's
// UserLinker param was hard-coded nil with a "no identitylink.Store is built
// here yet" comment).

const (
	idLinkUser     = "identitylink-e2e-user"
	idLinkClientID = "identitylink-e2e-client"
	idLinkPassword = "e2e-password"
)

// TestWireIdentityLink_DisabledIsNoOp proves the default (Enabled=false)
// appends nothing — byte-identical to a build predating the feature.
func TestWireIdentityLink_DisabledIsNoOp(t *testing.T) {
	t.Parallel()
	b := &appBuilder{cfg: &config.Config{}, logger: quietLogger()}
	if err := b.wireIdentityLink(); err != nil {
		t.Fatalf("wireIdentityLink: %v", err)
	}
	if len(b.opts) != 0 {
		t.Fatalf("opts = %d, want 0 (identity_link.enabled=false must wire nothing)", len(b.opts))
	}
}

// TestWireIdentityLink_DefaultMergePolicyWiresStoreOnly proves that Enabled
// with an unset (or explicit "reject") merge_policy appends ONLY
// WithIdentityLinkStore — the package's own safe default (RejectPolicy) is
// achieved by NOT wiring a MergePolicy Option at all, matching
// identitylink.Resolve's "nil is treated as RejectPolicy" contract.
func TestWireIdentityLink_DefaultMergePolicyWiresStoreOnly(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.SelfService.IdentityLink.Enabled = true
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	if err := b.wireIdentityLink(); err != nil {
		t.Fatalf("wireIdentityLink: %v", err)
	}
	if len(b.opts) != 1 {
		t.Fatalf("opts = %d, want 1 (WithIdentityLinkStore only; unset merge_policy adds no MergePolicy Option)", len(b.opts))
	}
}

// TestWireIdentityLink_LinkOnlyMergePolicyAppendsBothOptions proves the
// explicit opt-in wires both Options.
func TestWireIdentityLink_LinkOnlyMergePolicyAppendsBothOptions(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.SelfService.IdentityLink.Enabled = true
	cfg.SelfService.IdentityLink.MergePolicy = "link_only"
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	if err := b.wireIdentityLink(); err != nil {
		t.Fatalf("wireIdentityLink: %v", err)
	}
	if len(b.opts) != 2 {
		t.Fatalf("opts = %d, want 2 (WithIdentityLinkStore + WithIdentityMergePolicy)", len(b.opts))
	}
}

// TestWireIdentityLink_UnknownMergePolicyFailsLoud proves an unrecognized
// merge_policy value is a boot-time error, never a silent fallback.
func TestWireIdentityLink_UnknownMergePolicyFailsLoud(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.SelfService.IdentityLink.Enabled = true
	cfg.SelfService.IdentityLink.MergePolicy = "auto_merge_everything"
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	if err := b.wireIdentityLink(); err == nil {
		t.Fatal("wireIdentityLink: want error for unrecognized merge_policy")
	}
}

// buildIdentityLinkTestServer wires a minimal password-auth server around
// whatever Options extra supplies, mirroring consent_ttl_test.go's
// buildConsentTTLServer pattern so /me/identities can be exercised over real
// HTTP without the full buildApp machinery.
func buildIdentityLinkTestServer(t *testing.T, extra ...sso.Option) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(context.Background(), &sso.User{ID: idLinkUser}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: idLinkClientID, Secret: "unused", Active: true,
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt", SkipConsent: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != idLinkPassword {
				return nil, errors.New("bad credentials")
			}
			return &sso.AuthResult{UserID: idLinkUser, Provider: authenticators.MethodPassword}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(5 * time.Minute))

	opts := append([]sso.Option{
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	}, extra...)

	srv := sso.NewServer(opts...)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs
}

// idLinkLogin logs the fixed test user in and returns their access token.
func idLinkLogin(t *testing.T, hs *httptest.Server) string {
	t.Helper()
	status, out := ulJSON(t, http.MethodPost, hs.URL+"/auth/login", map[string]any{
		"provider":   authenticators.MethodPassword,
		"client_id":  idLinkClientID,
		"credential": map[string]string{"username": "anyone", "password": idLinkPassword},
	})
	if status != http.StatusOK {
		t.Fatalf("login = %d body=%v", status, out)
	}
	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("login response missing access_token: %v", out)
	}
	return access
}

// ulAuthedJSON is ulJSON (userlifecycle_wiring_test.go) with a bearer header.
func ulAuthedJSON(t *testing.T, method, url, bearer string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, url, err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do %s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestIdentityLink_EndToEnd drives the REAL composition-root build function
// (serverbuildplatform.BuildIdentityLink — the SAME function wireIdentityLink
// calls) with self_service.identity_link.enabled, wires its Options around a
// real password-auth server, and proves a genuine /me/identities round trip:
// a seeded link is visible over real HTTP and DELETE actually revokes it.
func TestIdentityLink_EndToEnd(t *testing.T) {
	t.Parallel()
	idLinkCfg := config.IdentityLinkConfig{Enabled: true}
	store, policy, err := serverbuildplatform.BuildIdentityLink(idLinkCfg)
	if err != nil || store == nil {
		t.Fatalf("BuildIdentityLink: store=%v err=%v", store, err)
	}
	if policy != nil {
		t.Fatalf("policy = %v, want nil (unset merge_policy = safe RejectPolicy default, no MergePolicy Option)", policy)
	}

	hs := buildIdentityLinkTestServer(t, sso.WithIdentityLinkStore(store))
	access := idLinkLogin(t, hs)

	// Seed TWO links: no password credential store is wired for this minimal
	// server, so unlinking a user's SOLE identity would be refused by the
	// last-auth-method guard (see domains/identitylink.GuardUnlink) — seeding
	// a second link keeps this test focused on proving the round trip itself.
	ctx := context.Background()
	link, err := store.Link(ctx, idLinkUser, "google", "sub-e2e")
	if err != nil {
		t.Fatalf("seed link: %v", err)
	}
	if _, err := store.Link(ctx, idLinkUser, "github", "sub-e2e-2"); err != nil {
		t.Fatalf("seed second link: %v", err)
	}

	status, out := ulAuthedJSON(t, http.MethodGet, hs.URL+"/me/identities", access)
	if status != http.StatusOK {
		t.Fatalf("GET /me/identities = %d body=%v", status, out)
	}
	ids, _ := out["identities"].([]any)
	if len(ids) != 2 {
		t.Fatalf("identities = %v, want 2 entries", out["identities"])
	}

	// Unauthenticated => 401 (matches every other /me/* surface — proves this
	// is the real self-service handler, not a stub).
	if status, _ := ulAuthedJSON(t, http.MethodGet, hs.URL+"/me/identities", ""); status != http.StatusUnauthorized {
		t.Errorf("unauth GET /me/identities = %d, want 401", status)
	}

	status, out = ulAuthedJSON(t, http.MethodDelete, hs.URL+"/me/identities/"+link.ID, access)
	if status != http.StatusNoContent {
		t.Fatalf("DELETE /me/identities/:id = %d body=%v, want 204", status, out)
	}

	status, out = ulAuthedJSON(t, http.MethodGet, hs.URL+"/me/identities", access)
	if status != http.StatusOK {
		t.Fatalf("GET after unlink = %d body=%v", status, out)
	}
	if ids, _ := out["identities"].([]any); len(ids) != 1 {
		t.Errorf("identities after unlink = %v, want 1 remaining", out["identities"])
	}
}

// TestIdentityLink_LinkOnlyMergePolicy_ResolvesConflictToExistingAccount
// proves merge_policy: link_only actually reaches a wired identitylink.Resolve
// call (the extension-point shape a custom login integration would use) and
// merges the losing account's links onto the winner — the security-relevant
// config knob this wiring introduces actually changes MergePolicy behavior,
// not just the store option.
func TestIdentityLink_LinkOnlyMergePolicy_ResolvesConflictToExistingAccount(t *testing.T) {
	t.Parallel()
	idLinkCfg := config.IdentityLinkConfig{Enabled: true, MergePolicy: "link_only"}
	store, policy, err := serverbuildplatform.BuildIdentityLink(idLinkCfg)
	if err != nil || store == nil || policy == nil {
		t.Fatalf("BuildIdentityLink: store=%v policy=%v err=%v", store, policy, err)
	}

	ctx := context.Background()
	const existingUser, incomingUser = "winner", "loser"
	if _, err := store.Link(ctx, existingUser, "google", "shared-sub"); err != nil {
		t.Fatalf("seed existing link: %v", err)
	}
	if _, err := store.Link(ctx, incomingUser, "github", "other-sub"); err != nil {
		t.Fatalf("seed losing-account link: %v", err)
	}

	finalUser, err := identitylink.Resolve(ctx, store, policy, "google", "shared-sub", incomingUser)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if finalUser != existingUser {
		t.Errorf("resolved user = %q, want %q (existing account wins)", finalUser, existingUser)
	}
	// The losing account's OTHER link (github) must now be merged onto winner.
	links, err := store.ListByUser(ctx, existingUser)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(links) != 2 {
		t.Errorf("winner's links after merge = %v, want 2 (google + merged github)", links)
	}
}

// TestIdentityLink_DefaultOff_RouteNotMounted proves /me/identities stays a
// router-native 404 when identity_link is absent.
func TestIdentityLink_DefaultOff_RouteNotMounted(t *testing.T) {
	t.Parallel()
	hs := buildIdentityLinkTestServer(t)
	if code := getStatus(t, hs.URL+"/me/identities"); code != http.StatusNotFound {
		t.Errorf("GET /me/identities (feature off) = %d, want 404", code)
	}
}
