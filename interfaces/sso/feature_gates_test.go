package sso_test

// feature_gates_test.go exercises Direction 5 (protocol-level attack-surface
// reduction): a gate explicitly turned off hides its routes (router-native
// 404, not a 401/501 from a reachable-but-declining handler) and its
// discovery-doc fields, while the default (gate left unset) reproduces the
// server's pre-FeatureGates behavior exactly. Reuses the rcov* helpers from
// rootcov_flow_test.go / rootcov_admin_test.go (same package, same dir).

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/federation"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/caep"
	"github.com/yangwb1123/snaplink/shared/security"
)

// fgAdminEnv bundles an AdminMiddleware-fronted httptest server plus a bearer
// token authorized admin:* — the shape production wraps interfaces/sso.Server
// in (cmd/sso-server always layers AdminMiddleware over /api/v1/admin/*), so
// tests against it see the same 401 challenge a real deployment would.
type fgAdminEnv struct {
	url   string
	token string
}

// fgNewAdminServer builds a server with the given extra options (typically
// sso.WithFeatureGates) plus enough wiring to log in and mint an admin:*
// bearer, then fronts it with the real AdminMiddleware — mirroring
// rcovNewAdminServer but parameterized so each test can vary FeatureGates.
func fgNewAdminServer(t *testing.T, extra ...sso.Option) *fgAdminEnv {
	t.Helper()
	ctx := context.Background()

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, Name: "Feature-Gate Test Client",
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
		Active: true, SkipConsent: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == rcovUsername && p == rcovPassword {
				return &sso.AuthResult{UserID: rcovUser, AuthMethods: []string{"pwd"}}, nil
			}
			return nil, errors.New("bad credentials")
		},
	))

	prov := permissions.NewMemoryProvider()
	_ = prov.AddRole(ctx, "", permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, rcovUser, "", []string{"root"})
	_ = prov.AddRole(ctx, rcovClient, permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, rcovUser, rcovClient, []string{"root"})

	opts := append([]sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPermissionProvider(prov),
	}, extra...)
	srv := sso.NewServer(opts...)

	mw := sso.NewAdminMiddleware(srv, prov)
	httpSrv := httptest.NewServer(mw.HTTPMiddleware(srv.Handler()))
	t.Cleanup(httpSrv.Close)

	status, out := rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	if status != http.StatusOK {
		t.Fatalf("feature-gate admin login status=%d body=%v", status, out)
	}
	token, _ := out["access_token"].(string)
	if token == "" {
		t.Fatalf("no admin token: %v", out)
	}
	return &fgAdminEnv{url: httpSrv.URL, token: token}
}

// fgAdminEndpoints hits the runtime inventory as the authenticated admin and
// returns the decoded endpoint list.
func fgAdminEndpoints(t *testing.T, env *fgAdminEnv) []map[string]any {
	t.Helper()
	status, out := rcovDo(t, http.MethodGet, env.url+"/api/v1/admin/endpoints", env.token, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/v1/admin/endpoints status=%d body=%v", status, out)
	}
	raw, _ := out["endpoints"].([]any)
	list := make([]map[string]any, 0, len(raw))
	for _, e := range raw {
		if m, ok := e.(map[string]any); ok {
			list = append(list, m)
		}
	}
	return list
}

func fgInventoryHasPath(list []map[string]any, path string) bool {
	for _, e := range list {
		if e["path"] == path {
			return true
		}
	}
	return false
}

// TestFeatureGates_OIDCOff_HidesUserinfoAndEndSession proves the OIDC gate
// removes /userinfo + /end_session from the router (404, not a handler that
// exists but declines) and from both discovery and the endpoint inventory.
func TestFeatureGates_OIDCOff_HidesUserinfoAndEndSession(t *testing.T) {
	t.Parallel()
	env := fgNewAdminServer(t, sso.WithFeatureGates(sso.FeatureGates{OIDC: sso.Bool(false)}))

	if status, _ := rcovDo(t, http.MethodGet, env.url+"/userinfo", "", nil); status != http.StatusNotFound {
		t.Errorf("GET /userinfo with oidc off = %d, want 404", status)
	}
	if status, _ := rcovDo(t, http.MethodGet, env.url+"/end_session", "", nil); status != http.StatusNotFound {
		t.Errorf("GET /end_session with oidc off = %d, want 404", status)
	}

	var doc map[string]any
	resp := rcovGetJSON(t, env.url+"/.well-known/openid-configuration", &doc)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status=%d", resp.StatusCode)
	}
	if _, present := doc["userinfo_endpoint"]; present {
		t.Errorf("discovery advertises userinfo_endpoint with oidc gate off: %v", doc["userinfo_endpoint"])
	}
	if _, present := doc["end_session_endpoint"]; present {
		t.Errorf("discovery advertises end_session_endpoint with oidc gate off: %v", doc["end_session_endpoint"])
	}

	list := fgAdminEndpoints(t, env)
	if fgInventoryHasPath(list, sso.PathUserInfo) {
		t.Errorf("inventory lists %s with oidc gate off", sso.PathUserInfo)
	}
	if fgInventoryHasPath(list, sso.PathEndSession) {
		t.Errorf("inventory lists %s with oidc gate off", sso.PathEndSession)
	}
	// A core (ungated) route must still be present — the gate scopes only
	// the OIDC surface, not the whole inventory.
	if !fgInventoryHasPath(list, sso.PathHealth) {
		t.Errorf("inventory missing always-on %s", sso.PathHealth)
	}
}

// TestFeatureGates_CIBAOff_Hides404 proves the CIBA gate removes
// /backchannel-authentication entirely — before FeatureGates existed this
// route was mounted unconditionally and 501'd without a CIBA store; the gate
// is the first way to make it a router-native 404 instead.
func TestFeatureGates_CIBAOff_Hides404(t *testing.T) {
	t.Parallel()
	env := fgNewAdminServer(t, sso.WithFeatureGates(sso.FeatureGates{CIBA: sso.Bool(false)}))

	status, _ := rcovDo(t, http.MethodPost, env.url+"/backchannel-authentication", "", nil)
	if status != http.StatusNotFound {
		t.Errorf("POST /backchannel-authentication with ciba off = %d, want 404", status)
	}
	list := fgAdminEndpoints(t, env)
	if fgInventoryHasPath(list, sso.PathBackchannelAuth) {
		t.Errorf("inventory lists %s with ciba gate off", sso.PathBackchannelAuth)
	}
}

// TestFeatureGates_CAEPOff_Hides404 proves the CAEP gate removes
// POST /ssf/receive entirely, even with a receiver wired via
// WithCAEPReceiver — the gate suppresses reachability of an
// already-constructed receiver, it does not need the receiver absent.
func TestFeatureGates_CAEPOff_Hides404(t *testing.T) {
	t.Parallel()
	rcv, err := caep.NewReceiver(
		"https://rp.example.com",
		defaultimpl.NewMemoryJTIReplayStore(),
		fgNopRevoker{},
		defaultimpl.NewMemoryUserProvider(),
		[]caep.TrustedTransmitter{{
			Issuer: "https://transmitter.example.com",
			JWKS:   security.NewStaticJWKS(nil),
		}},
	)
	if err != nil {
		t.Fatalf("caep.NewReceiver: %v", err)
	}
	env := fgNewAdminServer(t,
		sso.WithCAEPReceiver(rcv),
		sso.WithFeatureGates(sso.FeatureGates{CAEP: sso.Bool(false)}),
	)

	status, _ := rcovDo(t, http.MethodPost, env.url+"/ssf/receive", "", nil)
	if status != http.StatusNotFound {
		t.Errorf("POST /ssf/receive with caep off = %d, want 404", status)
	}
	list := fgAdminEndpoints(t, env)
	if fgInventoryHasPath(list, sso.PathSSFReceive) {
		t.Errorf("inventory lists %s with caep gate off", sso.PathSSFReceive)
	}
}

// fgNopRevoker is a no-op caep.SubjectRevoker — the gate-off path never
// reaches the receiver's decision logic, so it is never invoked.
type fgNopRevoker struct{}

func (fgNopRevoker) RevokeAllForSubject(context.Context, string) (caep.RevocationResult, error) {
	return caep.RevocationResult{}, nil
}

// TestFeatureGates_FederationOff_Hides404 proves the Federation gate removes
// the RFC 9728 protected-resource metadata document (representative of the
// whole federation sub-feature group) even though WithProtectedResourceMetadata
// is wired.
func TestFeatureGates_FederationOff_Hides404(t *testing.T) {
	t.Parallel()
	env := fgNewAdminServer(t,
		sso.WithProtectedResourceMetadata(sso.ProtectedResourceMetadata{ResourceName: "Gate Test Resource"}),
		sso.WithFeatureGates(sso.FeatureGates{Federation: sso.Bool(false)}),
	)

	status, _ := rcovDo(t, http.MethodGet, env.url+"/.well-known/oauth-protected-resource", "", nil)
	if status != http.StatusNotFound {
		t.Errorf("GET /.well-known/oauth-protected-resource with federation off = %d, want 404", status)
	}
	list := fgAdminEndpoints(t, env)
	if fgInventoryHasPath(list, sso.PathProtectedResourceMetadata) {
		t.Errorf("inventory lists %s with federation gate off", sso.PathProtectedResourceMetadata)
	}
}

// TestFeatureGates_FederationResolveVisibleWhenAnchored proves the new
// federation resolve endpoint is mounted only when the federation entity is
// wired with configured trust anchors, and it disappears when the federation
// gate is switched off.
func TestFeatureGates_FederationResolveVisibleWhenAnchored(t *testing.T) {
	t.Parallel()
	env := fgNewAdminServer(t,
		sso.WithFederationEntity(&federation.Config{
			TrustAnchors: []federation.TrustAnchor{{EntityID: "https://ta.example.com", Keys: []sso.JWK{}}},
		}, defaultimpl.NewEd25519JWTIssuer()),
	)

	status, _ := rcovDo(t, http.MethodGet, env.url+"/.well-known/openid-federation-resolve", "", nil)
	if status != http.StatusBadRequest {
		t.Errorf("GET resolve without sub = %d, want 400", status)
	}
	list := fgAdminEndpoints(t, env)
	if !fgInventoryHasPath(list, sso.PathFederationResolve) {
		t.Errorf("inventory missing %s when trust anchors are configured", sso.PathFederationResolve)
	}

	envOff := fgNewAdminServer(t,
		sso.WithFederationEntity(&federation.Config{
			TrustAnchors: []federation.TrustAnchor{{EntityID: "https://ta.example.com", Keys: []sso.JWK{}}},
		}, defaultimpl.NewEd25519JWTIssuer()),
		sso.WithFeatureGates(sso.FeatureGates{Federation: sso.Bool(false)}),
	)
	if status, _ := rcovDo(t, http.MethodGet, envOff.url+"/.well-known/openid-federation-resolve", "", nil); status != http.StatusNotFound {
		t.Errorf("GET resolve with federation off = %d, want 404", status)
	}
	if fgInventoryHasPath(fgAdminEndpoints(t, envOff), sso.PathFederationResolve) {
		t.Errorf("inventory lists %s with federation gate off", sso.PathFederationResolve)
	}
}

// TestFeatureGates_FederationOff_HomeRealmAlsoHidden proves the same gate
// suppresses a DIFFERENT sub-feature in the same group (B2B home-realm
// discovery, gated only on WithConnectionStore) — the group-level gate
// covers every sub-block, not just the one the previous test exercised.
func TestFeatureGates_FederationOff_HomeRealmAlsoHidden(t *testing.T) {
	t.Parallel()
	env := fgNewAdminServer(t,
		sso.WithConnectionStore(connections.NewMemoryStore()),
		sso.WithFeatureGates(sso.FeatureGates{Federation: sso.Bool(false)}),
	)

	status, _ := rcovDo(t, http.MethodGet, env.url+sso.PathHomeRealm+"?login_hint=user@example.com", "", nil)
	if status != http.StatusNotFound {
		t.Errorf("GET %s with federation off = %d, want 404", sso.PathHomeRealm, status)
	}
}

// TestFeatureGates_SelfServiceOff_Hides404 proves the SelfService gate
// removes the always-mounted /me/permissions,/me/menus,/me/roles group
// (mountSelfServiceProfile registers these unconditionally of any backing
// store) entirely at the router level.
func TestFeatureGates_SelfServiceOff_Hides404(t *testing.T) {
	t.Parallel()
	env := fgNewAdminServer(t, sso.WithFeatureGates(sso.FeatureGates{SelfService: sso.Bool(false)}))

	for _, path := range []string{sso.PathMyPermissions, sso.PathMyMenus, sso.PathMyRoles} {
		if status, _ := rcovDo(t, http.MethodGet, env.url+path, "", nil); status != http.StatusNotFound {
			t.Errorf("GET %s with self_service off = %d, want 404", path, status)
		}
	}
	list := fgAdminEndpoints(t, env)
	if fgInventoryHasPath(list, sso.PathMyPermissions) {
		t.Errorf("inventory lists %s with self_service gate off", sso.PathMyPermissions)
	}
}

// TestFeatureGates_AdminAPIOff_HidesAdminSurface proves the AdminAPI gate
// removes the ENTIRE /api/v1/admin/* group at the router level — tested
// WITHOUT the AdminMiddleware wrapper (unlike the other tests here) so a
// 404 can only come from Mount() never registering the group, not from an
// auth challenge.
func TestFeatureGates_AdminAPIOff_HidesAdminSurface(t *testing.T) {
	t.Parallel()
	srvOff := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithFeatureGates(sso.FeatureGates{AdminAPI: sso.Bool(false)}),
	)
	httpOff := httptest.NewServer(srvOff.Handler())
	t.Cleanup(httpOff.Close)
	if status, _ := rcovDo(t, http.MethodGet, httpOff.URL+"/api/v1/admin/endpoints", "", nil); status != http.StatusNotFound {
		t.Errorf("GET /api/v1/admin/endpoints with admin_api off (no middleware) = %d, want 404", status)
	}

	// Contrast: the default (gate unset) reaches the handler at all —
	// proving the 404 above came from the gate, not from some unrelated
	// router quirk.
	srvOn := sso.NewServer(sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()))
	httpOn := httptest.NewServer(srvOn.Handler())
	t.Cleanup(httpOn.Close)
	if status, _ := rcovDo(t, http.MethodGet, httpOn.URL+"/api/v1/admin/endpoints", "", nil); status == http.StatusNotFound {
		t.Errorf("GET /api/v1/admin/endpoints with default gates = 404, want the route to exist")
	}
}

// TestFeatureGates_AdminEndpointsRequiresAdminAuth proves the new inventory
// endpoint inherits the same admin bearer challenge as every other
// /api/v1/admin/ route (it is registered inside the admin surface, not
// bolted on separately).
func TestFeatureGates_AdminEndpointsRequiresAdminAuth(t *testing.T) {
	t.Parallel()
	env := fgNewAdminServer(t)

	if status, _ := rcovDo(t, http.MethodGet, env.url+"/api/v1/admin/endpoints", "", nil); status != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/admin/endpoints without bearer = %d, want 401", status)
	}
	if status, _ := rcovDo(t, http.MethodGet, env.url+"/api/v1/admin/endpoints", "garbage", nil); status != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/admin/endpoints with garbage bearer = %d, want 401", status)
	}
	list := fgAdminEndpoints(t, env)
	if len(list) == 0 {
		t.Fatal("admin endpoints inventory is empty with a valid admin bearer")
	}
}

// TestFeatureGates_DefaultConfigUnchanged proves that leaving FeatureGates
// entirely unset (the state every pre-existing caller is in) reproduces
// exactly the pre-gate behavior for a representative endpoint per surface:
// /userinfo reachable (401, unauthenticated — NOT 404), CIBA's pre-existing
// 501-without-a-store behavior, and discovery still advertising the OIDC
// endpoints.
func TestFeatureGates_DefaultConfigUnchanged(t *testing.T) {
	t.Parallel()
	env := fgNewAdminServer(t) // no WithFeatureGates at all

	if status, _ := rcovDo(t, http.MethodGet, env.url+"/userinfo", "", nil); status != http.StatusUnauthorized {
		t.Errorf("GET /userinfo with default gates = %d, want 401 (route must exist)", status)
	}
	if status, _ := rcovDo(t, http.MethodPost, env.url+"/backchannel-authentication", "", nil); status != http.StatusNotImplemented {
		t.Errorf("POST /backchannel-authentication with default gates = %d, want 501 (pre-gate behavior: mounted, no CIBA store)", status)
	}

	var doc map[string]any
	resp := rcovGetJSON(t, env.url+"/.well-known/openid-configuration", &doc)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status=%d", resp.StatusCode)
	}
	if _, present := doc["userinfo_endpoint"]; !present {
		t.Error("discovery missing userinfo_endpoint with default gates")
	}
	if _, present := doc["end_session_endpoint"]; !present {
		t.Error("discovery missing end_session_endpoint with default gates")
	}

	list := fgAdminEndpoints(t, env)
	if !fgInventoryHasPath(list, sso.PathUserInfo) {
		t.Errorf("inventory missing %s with default gates", sso.PathUserInfo)
	}
	if !fgInventoryHasPath(list, sso.PathBackchannelAuth) {
		t.Errorf("inventory missing %s with default gates", sso.PathBackchannelAuth)
	}
}
