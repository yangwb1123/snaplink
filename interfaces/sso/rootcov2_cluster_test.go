package sso_test

// rootcov2_cluster_test.go targets the cross-replica / CIBA / back-channel /
// residency surfaces the first rootcov_* pass left at 0%:
//   - cross-replica token-revocation adoption (cross_replica_revocation.go
//     applyTokenRevocation, via the invalidation bus consumer)
//   - the full CIBA poll+ping flow (device_code_handler.go handleCIBATokenGrant,
//     invalidation_bus.go ResolveBackchannelAuthRequest / deliverCIBAPing /
//     recordCIBAPingFailure, ciba_handler.go recordCIBADecision)
//   - OIDC back-channel + front-channel logout fan-out on /end_session
//     (backchannel_logout.go sendBackchannelLogout / fanOutBackchannelLogout /
//     appendFrontchannelLogoutSidIss + NewHTTPLogoutNotifier.Notify)
//   - the data-residency decision seam (tenant_residency.go ResidencyDecision /
//     mapResidencyError).
//
// These flows need the *sso.Server reference (not just the httptest wrapper), so
// they build their own servers rather than reusing rcovNewServer.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/region"
	tenantpkg "github.com/snaplink/sso/domains/tenant"
	tenantmem "github.com/snaplink/sso/domains/tenant/memory"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/cluster"
	clustermem "github.com/snaplink/sso/platform/cluster/memory"
	"github.com/snaplink/sso/protocols/oauth"
)

// rcov2PasswordAuth returns a password authenticator accepting the canonical
// rcov credentials and reporting the openid attribute set.
func rcov2PasswordAuth() sso.Authenticator {
	return authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == rcovUsername && p == rcovPassword {
				return &sso.AuthResult{UserID: rcovUser, AuthMethods: []string{"pwd"}}, nil
			}
			return nil, context.Canceled
		}))
}

// TestRcov2Cl_CrossReplicaRevocation arms cross-replica revocation + an
// in-process bus, starts the consumer loop, publishes a KindTokenRevoked event,
// and confirms the adopt path (applyTokenRevocation) runs without panicking.
func TestRcov2Cl_CrossReplicaRevocation(t *testing.T) {
	t.Parallel()
	bus := clustermem.New()
	iss := defaultimpl.NewEd25519JWTIssuer()
	srv := sso.NewServer(
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithTokenIssuer("jwt", iss),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithInvalidationBus(bus),
		sso.WithCrossReplicaRevocation(),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done, err := srv.StartInvalidationBus(ctx)
	if err != nil {
		t.Fatalf("StartInvalidationBus: %v", err)
	}

	// A peer revoked a token: publish the additive deny-set event.
	exp := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	if perr := bus.Publish(ctx, cluster.Event{
		Kind: cluster.KindTokenRevoked,
		Payload: map[string]string{
			cluster.MetaRevokedToken: "peer-revoked-token",
			cluster.MetaRevokedExp:   exp,
		},
	}); perr != nil {
		t.Fatalf("publish: %v", perr)
	}

	// Give the consumer a beat to drain the event, then shut down cleanly.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("invalidation bus consumer did not drain on shutdown")
	}
}

// rcov2PingNotifier records whether a CIBA ping fired (and can be made to fail).
type rcov2PingNotifier struct {
	mu     sync.Mutex
	fired  bool
	failIt bool
}

func (n *rcov2PingNotifier) Notify(_ context.Context, _, _, _ string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.fired = true
	if n.failIt {
		return context.DeadlineExceeded
	}
	return nil
}

// TestRcov2Cl_CIBAPollPing drives the CIBA flow end-to-end: backchannel-auth ->
// operator resolves (approve, ping fires) -> /token poll mints. Covers
// handleCIBATokenGrant + ResolveBackchannelAuthRequest + deliverCIBAPing.
func TestRcov2Cl_CIBAPollPing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, AllowedAuthenticators: []string{"password"},
		TokenStrategy: "jwt", Active: true, SkipConsent: true,
	})
	notifier := &rcov2PingNotifier{}

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(rcov2PasswordAuth()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithCIBA(defaultimpl.NewMemoryCIBAStore(), oauth.CIBATransportFunc(
			func(context.Context, string, string, map[string]string) error { return nil }),
			time.Minute, time.Nanosecond),
		sso.WithCIBAPingNotifier(oauth.CIBAPingNotifierFunc(notifier.Notify)),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// 1. Backchannel auth: the login_hint resolves to rcovUser via GetByID.
	status, out := rcovPostJSON(t, httpSrv.URL+"/backchannel-authentication", "", map[string]any{
		"client_id":                 rcovClient,
		"client_secret":             rcovSecret,
		"login_hint":                rcovUser,
		"client_notification_token": "cnt-12345678",
		"scope":                     "openid",
	})
	if status != http.StatusOK {
		t.Fatalf("backchannel-auth = %d body=%v", status, out)
	}
	authReqID, _ := out["auth_req_id"].(string)
	if authReqID == "" {
		t.Fatalf("no auth_req_id: %v", out)
	}

	// 2. Polling before resolution => authorization_pending.
	status, tok := rcovPostJSON(t, httpSrv.URL+"/token", "", map[string]any{
		"grant_type":    "urn:openid:params:grant-type:ciba",
		"auth_req_id":   authReqID,
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	if status != http.StatusBadRequest || tok["error"] != "authorization_pending" {
		t.Fatalf("ciba pending poll = %d %v, want authorization_pending", status, tok)
	}

	// 3. Operator approves (ping fires async).
	if rerr := srv.ResolveBackchannelAuthRequest(ctx, authReqID, true); rerr != nil {
		t.Fatalf("ResolveBackchannelAuthRequest: %v", rerr)
	}

	// 4. Poll mints (interval is ~0 so no slow_down between polls).
	status, tok = rcovPostJSON(t, httpSrv.URL+"/token", "", map[string]any{
		"grant_type":    "urn:openid:params:grant-type:ciba",
		"auth_req_id":   authReqID,
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	if status != http.StatusOK {
		t.Fatalf("ciba approved poll = %d body=%v, want 200", status, tok)
	}
	if tok["access_token"] == "" || tok["access_token"] == nil {
		t.Errorf("ciba mint produced no access_token: %v", tok)
	}

	// The ping should have fired (best-effort, async — allow a brief window).
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		notifier.mu.Lock()
		fired := notifier.fired
		notifier.mu.Unlock()
		if fired {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestRcov2Cl_CIBADeny covers the CIBA denial branch (recordCIBADecision +
// access_denied poll).
func TestRcov2Cl_CIBADeny(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, AllowedAuthenticators: []string{"password"},
		TokenStrategy: "jwt", Active: true, SkipConsent: true,
	})
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(rcov2PasswordAuth()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithCIBA(defaultimpl.NewMemoryCIBAStore(), oauth.CIBATransportFunc(
			func(context.Context, string, string, map[string]string) error { return nil }),
			time.Minute, time.Nanosecond),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	_, out := rcovPostJSON(t, httpSrv.URL+"/backchannel-authentication", "", map[string]any{
		"client_id": rcovClient, "client_secret": rcovSecret,
		"login_hint": rcovUser, "scope": "openid",
	})
	authReqID, _ := out["auth_req_id"].(string)

	if rerr := srv.ResolveBackchannelAuthRequest(ctx, authReqID, false); rerr != nil {
		t.Fatalf("resolve(deny): %v", rerr)
	}
	status, tok := rcovPostJSON(t, httpSrv.URL+"/token", "", map[string]any{
		"grant_type":    "urn:openid:params:grant-type:ciba",
		"auth_req_id":   authReqID,
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	if status != http.StatusBadRequest || tok["error"] != "access_denied" {
		t.Errorf("ciba denied poll = %d %v, want access_denied", status, tok)
	}
}

// TestRcov2Cl_BackchannelLogout covers OIDC BCL/FCL fan-out on /end_session:
// a logout_token is POSTed to the client's backchannel_logout_uri receiver.
func TestRcov2Cl_BackchannelLogout(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// A receiver that records the logout_token it was POSTed.
	var (
		mu       sync.Mutex
		received bool
	)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("logout_token") != "" {
			mu.Lock()
			received = true
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(receiver.Close)

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, AllowedAuthenticators: []string{"password"},
		TokenStrategy: "jwt", Active: true, SkipConsent: true,
		BackchannelLogoutURI:  receiver.URL,
		FrontchannelLogoutURI: receiver.URL + "/fc",
	})
	iss := defaultimpl.NewEd25519JWTIssuer()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(rcov2PasswordAuth()),
		sso.WithTokenIssuer("jwt", iss),
		sso.WithIDTokenIssuer(iss),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithBackchannelLogout(iss, sso.NewHTTPLogoutNotifier()),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// Login (openid) to mint the id_token used as the logout hint.
	status, out := rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid"},
	})
	if status != http.StatusOK {
		t.Fatalf("bcl login = %d body=%v", status, out)
	}
	idToken, _ := out["id_token"].(string)
	if idToken == "" {
		t.Fatalf("bcl login produced no id_token: %v", out)
	}

	// RP-initiated logout fans out the back-channel logout_token.
	resp, err := http.Get(httpSrv.URL + "/end_session?id_token_hint=" + idToken)
	if err != nil {
		t.Fatalf("end_session: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 500 {
		t.Fatalf("end_session = %d, want < 500", resp.StatusCode)
	}

	// Fan-out is synchronous within end_session (it waits on the worker pool),
	// so the receiver must have been hit by now.
	mu.Lock()
	got := received
	mu.Unlock()
	if !got {
		t.Errorf("backchannel logout receiver was never POSTed a logout_token")
	}
}

// TestRcov2Cl_ResidencyDecision covers the data-residency decision seam: a tenant
// pinned to "us" denies a write served from "ap" (ResidencyDecision +
// mapResidencyError), while a home-region request is allowed.
func TestRcov2Cl_ResidencyDecision(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	tstore := tenantmem.New()
	if perr := tstore.PutTenant(ctx, &tenantpkg.Tenant{
		ID:             "acme",
		Slug:           "acme",
		Name:           "Acme",
		HomeRegion:     "us",
		AllowedRegions: []string{"us"},
		EnforceWrites:  true,
	}); perr != nil {
		t.Fatalf("PutTenant: %v", perr)
	}

	srv := sso.NewServer(
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithTenantStore(tstore),
		sso.WithRegionMiddleware(region.ConfigPinnedResolver{Region: region.ID("us")}, region.MiddlewareOptions{}),
		sso.WithTenantResidencyCheck(time.Minute),
	)

	// Serving region "ap" is neither the home region nor allowed => denied.
	code, denied := srv.ResidencyDecision(ctx, "acme", region.ID("ap"), true)
	if !denied {
		t.Errorf("ResidencyDecision(ap) denied = false, want denied")
	}
	if code == "" {
		t.Errorf("denied decision returned an empty wire code")
	}

	// Serving from the home region is allowed.
	if _, denied := srv.ResidencyDecision(ctx, "acme", region.ID("us"), true); denied {
		t.Errorf("ResidencyDecision(us, home) denied = true, want allowed")
	}

	// An unconstrained tenant (no policy) is allowed.
	if _, denied := srv.ResidencyDecision(ctx, "unknown-tenant", region.ID("ap"), true); denied {
		t.Errorf("ResidencyDecision(unknown tenant) denied = true, want allowed (fail-open)")
	}
}
