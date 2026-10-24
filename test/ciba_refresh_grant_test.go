package ssotest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

type cibaGrantHTTPCase struct {
	name               string
	grants             []string
	scope              string
	wantRefresh        bool
	noStore, failStore bool
}

func cibaGrantHTTPCases() []cibaGrantHTTPCase {
	return []cibaGrantHTTPCase{
		{name: "nil legacy no offline", scope: "openid api:read", wantRefresh: true},
		{name: "empty legacy no offline", grants: []string{}, scope: "openid", wantRefresh: true},
		{name: "explicit permits no offline", grants: []string{oauth.GrantCIBA, sso.GrantRefreshToken}, scope: "openid api:read", wantRefresh: true},
		{name: "explicit denial", grants: []string{oauth.GrantCIBA}, scope: "openid"},
		{name: "offline cannot override denial", grants: []string{oauth.GrantCIBA}, scope: "openid offline_access"},
		{name: "case alias", grants: []string{oauth.GrantCIBA, "REFRESH_TOKEN"}, scope: "openid"},
		{name: "authorized unwired no issuer fallback", grants: []string{oauth.GrantCIBA, sso.GrantRefreshToken}, scope: "openid", noStore: true},
		{name: "denied unwired no issuer fallback", grants: []string{oauth.GrantCIBA}, scope: "openid", noStore: true},
		{name: "omitted scope retains resource defaults", grants: []string{oauth.GrantCIBA, sso.GrantRefreshToken}, wantRefresh: true},
		{name: "non OIDC preserves existing CIBA policy", grants: []string{oauth.GrantCIBA, sso.GrantRefreshToken}, scope: "api:read", wantRefresh: true},
	}
}

type cibaGrantHTTPFixture struct {
	server   *sso.Server
	http     *httptest.Server
	requests oauth.CIBAStore
	refresh  oauth.RefreshTokenStore
	fault    *codeRefreshStore
	sink     *audit.MemorySink
	pushEP   *httptest.Server
	lastPush func(string) map[string]any
	notified chan string
}

func newCIBAGrantStores(t *testing.T, backend string) (oauth.CIBAStore, oauth.RefreshTokenStore) {
	t.Helper()
	if backend == "memory" {
		return defaultimpl.NewMemoryCIBAStore(), defaultimpl.NewMemoryRefreshTokenStore()
	}
	dsn := "file:" + filepath.Join(t.TempDir(), "owned-ciba.sqlite") + "?_journal=WAL"
	requests, err := sqlitestores.NewCIBAStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := requests.Close(); err != nil {
			t.Error(err)
		}
	})
	refresh, err := sqlitestores.NewRefreshTokenStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := refresh.Close(); err != nil {
			t.Error(err)
		}
	})
	return requests, refresh
}

func newCIBAGrantHTTP(t *testing.T, backend, mode string, tc cibaGrantHTTPCase) *cibaGrantHTTPFixture {
	t.Helper()
	requests, refresh := newCIBAGrantStores(t, backend)
	f := &cibaGrantHTTPFixture{requests: requests, refresh: refresh, sink: audit.NewMemorySink(100), notified: make(chan string, 1)}
	if tc.failStore {
		f.fault = &codeRefreshStore{MemoryRefreshTokenStore: defaultimpl.NewMemoryRefreshTokenStore(), fail: true}
		f.refresh = f.fault
	}
	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(t.Context(), &sso.User{ID: cibaUser}); err != nil {
		t.Fatal(err)
	}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: cibaClient, Secret: cibaSecret, Active: true, TokenStrategy: "jwt", GrantTypes: tc.grants,
		AllowedScopes: []string{"openid", "api:read", "offline_access"}, AllowedResources: []string{"https://s36.invalid/resource"}, RefreshTokenTTL: 17 * time.Minute})
	issuer := defaultimpl.NewEd25519JWTIssuer()
	transport := oauth.CIBATransportFunc(func(context.Context, string, string, map[string]string) error { return nil })
	opts := []sso.Option{sso.WithUserProvider(users), sso.WithClientStore(clients), sso.WithTokenIssuer("jwt", directOfflineIssuer{issuer}),
		sso.WithIDTokenIssuer(issuer), sso.WithAuditRecorder(audit.New(f.sink)), sso.WithCIBA(requests, transport, time.Minute, time.Millisecond)}
	if !tc.noStore {
		opts = append(opts, sso.WithRefreshTokenStore(f.refresh, time.Hour))
	}
	opts = append(opts, f.deliveryOptions(t, mode)...)
	f.server = sso.NewServer(opts...)
	f.http = httptest.NewServer(f.server.Handler())
	f.http.Client().Timeout = 3 * time.Second
	t.Cleanup(f.http.Close)
	return f
}

func (f *cibaGrantHTTPFixture) deliveryOptions(t *testing.T, mode string) []sso.Option {
	t.Helper()
	if mode == "ping" {
		return []sso.Option{sso.WithCIBAPingNotifier(oauth.CIBAPingNotifierFunc(func(_ context.Context, client, id, credential string) error {
			f.notified <- client + ":" + id + ":" + credential
			return nil
		}))}
	}
	if mode != "push" {
		return nil
	}
	endpoint, last := newCIBAPushEndpoint(t)
	endpoint.Client().Timeout = 3 * time.Second
	f.pushEP = endpoint
	f.lastPush = func(id string) map[string]any {
		delivery := waitForCIBAPushDelivery(t, last, id)
		if delivery.auth != "Bearer synthetic-s36-notification" {
			t.Fatal("registered notification credential changed")
		}
		return delivery.body
	}
	notifier := oauth.NewCIBAPushNotifier(func(context.Context, string) (string, error) { return endpoint.URL, nil }, oauth.WithCIBAPushHTTPClient(endpoint.Client()))
	return []sso.Option{sso.WithCIBAPushNotifier(notifier)}
}

func (f *cibaGrantHTTPFixture) post(t *testing.T, path string, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.http.Client().Post(f.http.URL+path, "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err = io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(raw) > 65536 {
		t.Fatal("bounded credential response read failed")
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Pragma") != "no-cache" {
		t.Fatal("credential cache headers changed")
	}
	return resp.StatusCode, out
}

func (f *cibaGrantHTTPFixture) poll(t *testing.T, id string) (int, map[string]any) {
	t.Helper()
	return f.post(t, "/token", map[string]any{"client_id": cibaClient, "client_secret": cibaSecret, "grant_type": oauth.GrantCIBA, "auth_req_id": id})
}

func (f *cibaGrantHTTPFixture) complete(t *testing.T, mode string, tc cibaGrantHTTPCase) (*oauth.CIBARequest, map[string]any) {
	t.Helper()
	request := map[string]any{"client_id": cibaClient, "client_secret": cibaSecret, "login_hint": cibaUser, "scope": tc.scope,
		"nonce": "rp-s36-nonce-not-a-family", "acr_values": "urn:s36:acr", "resource": []string{"https://s36.invalid/resource"}}
	if mode != "poll" {
		request["client_notification_token"] = "synthetic-s36-notification"
	}
	status, body := f.post(t, "/backchannel-authentication", request)
	id, _ := body["auth_req_id"].(string)
	if status != http.StatusOK || id == "" {
		t.Fatalf("backchannel request failed: status=%d", status)
	}
	r, err := f.requests.Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.server.ResolveBackchannelAuthRequest(t.Context(), id, true); err != nil {
		t.Fatal(err)
	}
	if mode == "push" {
		return r, f.lastPush(id)
	}
	if mode == "ping" {
		select {
		case got := <-f.notified:
			if got != cibaClient+":"+id+":synthetic-s36-notification" {
				t.Fatal("ping collection identity changed")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("bounded ping callback did not complete")
		}
	}
	status, response := f.poll(t, id)
	if status != http.StatusOK {
		t.Fatalf("approved poll failed: status=%d", status)
	}
	return r, response
}

func TestE2E_CIBARefreshGrant_StoresAndDelivery(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, mode := range []string{"poll", "ping", "push"} {
			for _, tc := range cibaGrantHTTPCases() {
				t.Run(backend+"/"+mode+"/"+tc.name, func(t *testing.T) {
					t.Parallel()
					f := newCIBAGrantHTTP(t, backend, mode, tc)
					r, response := f.complete(t, mode, tc)
					f.assertReply(t, tc, r, response)
					f.assertReplayAndRotation(t, tc, r, response)
				})
			}
		}
	}
}

func TestE2E_CIBARefreshGrant_MemoryStoreOutage(t *testing.T) {
	for _, mode := range []string{"poll", "ping", "push"} {
		for _, allow := range []bool{false, true} {
			grants := []string{oauth.GrantCIBA}
			if allow {
				grants = append(grants, sso.GrantRefreshToken)
			}
			name := "denied"
			if allow {
				name = "authorized"
			}
			t.Run(mode+"/"+name, func(t *testing.T) {
				t.Parallel()
				tc := cibaGrantHTTPCase{grants: grants, scope: "openid", failStore: true}
				f := newCIBAGrantHTTP(t, "memory", mode, tc)
				r, response := f.complete(t, mode, tc)
				f.assertReply(t, tc, r, response)
				f.assertReplayAndRotation(t, tc, r, response)
				want := int64(0)
				if allow {
					want = 1
				}
				if f.fault.writes.Load() != want {
					t.Fatal("unauthorized outage reached the store, or authorized failure bypassed managed issuance")
				}
			})
		}
	}
}

func (f *cibaGrantHTTPFixture) count(t *testing.T) int {
	t.Helper()
	count, err := f.refresh.(oauth.RefreshTokenSubjectCounter).CountForSubject(t.Context(), cibaUser, cibaClient)
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func (f *cibaGrantHTTPFixture) auditCount(t *testing.T) int {
	t.Helper()
	events, err := f.sink.Query(t.Context(), audit.Query{Type: audit.EventRefreshTokenIssued})
	if err != nil {
		t.Fatal(err)
	}
	return len(events)
}

func (f *cibaGrantHTTPFixture) assertReply(t *testing.T, tc cibaGrantHTTPCase, r *oauth.CIBARequest, response map[string]any) {
	t.Helper()
	refresh, present := response["refresh_token"]
	if present != tc.wantRefresh || (present && (refresh == "" || refresh == "synthetic-issuer-owned-refresh")) {
		t.Fatal("refresh presence changed or issuer refresh leaked")
	}
	want := 0
	if tc.wantRefresh {
		want = 1
	}
	if f.count(t) != want || f.auditCount(t) != want {
		t.Fatal("initial refresh persistence/audit side effects changed")
	}
	if tc.scope == "" && !reflect.DeepEqual(r.Scopes, []string{"api:read"}) {
		t.Fatal("resource defaults gained implicit protocol scopes")
	}
	claims := fcDecodeJWT(t, response["access_token"])
	_, idPresent := response["id_token"]
	if claims["sub"] != cibaUser || claims["client_id"] != cibaClient || claims["scope"] != strings.Join(r.Scopes, " ") || claims["acr"] != r.ACRValues || idPresent != slices.Contains(r.Scopes, "openid") {
		t.Fatal("independent access/ID or approved scope/client context changed")
	}
	if !tc.wantRefresh {
		return
	}
	stored, err := f.refresh.(oauth.RefreshTokenInspector).Inspect(t.Context(), refresh.(string))
	if err != nil || !reflect.DeepEqual(stored.Scopes, r.Scopes) || !reflect.DeepEqual(stored.Resources, r.Resources) || stored.ClientID != r.ClientID || stored.UserID != r.SubjectID || stored.FamilyID == "" || stored.FamilyID == r.Nonce || stored.Generation != 0 || stored.SID != "" || len(stored.AuthorizationDetails) != 0 || stored.Acr != r.ACRValues || stored.AuthTime.IsZero() {
		t.Fatal("initial managed refresh grant/authentication/family context changed")
	}
}

func (f *cibaGrantHTTPFixture) assertReplayAndRotation(t *testing.T, tc cibaGrantHTTPCase, r *oauth.CIBARequest, response map[string]any) {
	t.Helper()
	count, audits := f.count(t), f.auditCount(t)
	status, replay := f.poll(t, r.AuthReqID)
	if status != http.StatusBadRequest || replay["error"] != "expired_token" || replay["access_token"] != nil || replay["refresh_token"] != nil || f.count(t) != count || f.auditCount(t) != audits {
		t.Fatal("consumed CIBA request replay did not preserve the existing error and state")
	}
	if !tc.wantRefresh {
		return
	}
	rt := response["refresh_token"].(string)
	parent, err := f.refresh.(oauth.RefreshTokenInspector).Inspect(t.Context(), rt)
	if err != nil {
		t.Fatal(err)
	}
	status, rotated := f.post(t, "/token", map[string]any{"grant_type": sso.GrantRefreshToken, "refresh_token": rt, "client_id": cibaClient, "client_secret": cibaSecret})
	if status != http.StatusOK || rotated["refresh_token"] == nil || rotated["refresh_token"] == rt || f.count(t) != count || f.auditCount(t) != audits+1 {
		t.Fatal("existing-family rotation changed; no offline-scope requirement may be added here")
	}
	child, err := f.refresh.(oauth.RefreshTokenInspector).Inspect(t.Context(), rotated["refresh_token"].(string))
	if err != nil || child.FamilyID != parent.FamilyID || child.Generation != 1 || !child.AuthTime.Equal(parent.AuthTime) || child.Acr != parent.Acr || !reflect.DeepEqual(child.Scopes, parent.Scopes) || !reflect.DeepEqual(child.Resources, parent.Resources) {
		t.Fatal("refresh rotation lost original grant, family or authentication context")
	}
}
