package ssotest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

type deviceOfflineCase struct {
	name                            string
	scopes                          []string
	pollScope                       string
	wantRefresh                     bool
	noStore, failStore, denyOffline bool
	legacyGrants, denyRefreshGrant  bool
}

func deviceOfflineCases() []deviceOfflineCase {
	return []deviceOfflineCase{
		{name: "omitted scope defaults exclude offline"},
		{name: "empty scope", scopes: []string{}},
		{name: "resource only", scopes: []string{"api:read"}},
		{name: "openid only", scopes: []string{"openid"}},
		{name: "substring", scopes: []string{"offline_access:extra"}},
		{name: "case alias", scopes: []string{"OFFLINE_ACCESS"}},
		{name: "offline on poll cannot expand grant", scopes: []string{"openid"}, pollScope: "openid offline_access"},
		{name: "poll narrowing does not replace stored grant", scopes: []string{"openid", "offline_access"}, pollScope: "openid", wantRefresh: true},
		{name: "explicit offline", scopes: []string{"openid", "api:read", "offline_access"}, wantRefresh: true},
		{name: "non OIDC offline", scopes: []string{"offline_access"}, wantRefresh: true},
		{name: "legacy grants still require offline", scopes: []string{"api:read"}, legacyGrants: true},
		{name: "legacy grants with offline", scopes: []string{"offline_access"}, legacyGrants: true, wantRefresh: true},
		{name: "explicit refresh grant denied", scopes: []string{"openid", "offline_access"}, denyRefreshGrant: true},
		{name: "client denies offline", scopes: []string{"offline_access"}, denyOffline: true},
		{name: "authorized unwired never copies issuer refresh", scopes: []string{"openid", "offline_access"}, noStore: true},
		{name: "unauthorized unwired never copies issuer refresh", scopes: []string{"openid"}, noStore: true},
		{name: "authorized store failure no issuer fallback", scopes: []string{"openid", "offline_access"}, failStore: true},
	}
}

func newDeviceOfflineServer(t *testing.T, tc deviceOfflineCase) (*httptest.Server, *codeRefreshStore, *audit.MemorySink, oauth.DeviceCodeStore) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(t.Context(), &sso.User{ID: devUser}); err != nil {
		t.Fatal(err)
	}
	allowed := []string{"openid", "api:read", "offline_access:extra", "OFFLINE_ACCESS", "offline_access"}
	if tc.denyOffline {
		allowed = []string{"openid", "api:read"}
	}
	grants := []string{sso.GrantDeviceCode, sso.GrantRefreshToken}
	if tc.legacyGrants {
		grants = nil
	}
	if tc.denyRefreshGrant {
		grants = []string{sso.GrantDeviceCode}
	}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: devClient, Secret: devSecret, Active: true, TokenStrategy: "jwt",
		AllowedAuthenticators: []string{"password"}, AllowedScopes: allowed, GrantTypes: grants})
	password := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(func(context.Context, string, string) (*sso.AuthResult, error) {
		return &sso.AuthResult{UserID: devUser, Provider: "password"}, nil
	}))
	issuer := defaultimpl.NewEd25519JWTIssuer()
	store := &codeRefreshStore{MemoryRefreshTokenStore: defaultimpl.NewMemoryRefreshTokenStore(), fail: tc.failStore}
	devices, sink := defaultimpl.NewMemoryDeviceCodeStore(), audit.NewMemorySink(100)
	opts := []sso.Option{sso.WithUserProvider(users), sso.WithClientStore(clients), sso.WithAuthenticator(password),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()), sso.WithTokenIssuer("jwt", directOfflineIssuer{issuer}),
		sso.WithIDTokenIssuer(issuer), sso.WithDeviceCodeStore(devices, time.Minute, time.Millisecond, ""), sso.WithAuditRecorder(audit.New(sink))}
	if !tc.noStore {
		opts = append(opts, sso.WithRefreshTokenStore(store, time.Hour))
	}
	server := httptest.NewServer(sso.NewServer(opts...).Handler())
	t.Cleanup(server.Close)
	return server, store, sink, devices
}

func TestE2E_DeviceOfflineAccessBoundaries(t *testing.T) {
	for _, tc := range deviceOfflineCases() {
		t.Run(tc.name, func(t *testing.T) {
			server, store, sink, devices := newDeviceOfflineServer(t, tc)
			request := map[string]any{"client_id": devClient}
			if tc.scopes != nil {
				request["scope"] = strings.Join(tc.scopes, " ")
			}
			status, code, headers := fcPost(t, server.URL, "/device/code", request)
			if tc.denyOffline {
				if status != http.StatusBadRequest || code["error"] != "invalid_scope" || code["device_code"] != nil || store.writes.Load() != 0 {
					t.Fatal("client scope ceiling must reject before issuing device/refresh credentials")
				}
				assertDeviceOfflineAudits(t, sink, 0)
				return
			}
			if status != http.StatusOK || headers.Get("Cache-Control") != "no-store" || headers.Get("Pragma") != "no-cache" {
				t.Fatalf("device-code status/cache contract changed: %d", status)
			}
			dc, err := devices.GetByDeviceCode(t.Context(), code["device_code"].(string))
			if err != nil {
				t.Fatal(err)
			}
			if tc.scopes == nil || len(tc.scopes) == 0 {
				if !reflect.DeepEqual(dc.Scopes, []string{"api:read", "offline_access:extra", "OFFLINE_ACCESS"}) {
					t.Fatal("empty defaults changed order or gained protocol scope")
				}
			}
			bearer := userBearerToken(t, server)
			if verifyUserCode(t, server, bearer, dc.UserCode, true) != http.StatusOK {
				t.Fatal("authenticated approval failed")
			}
			poll := map[string]any{"grant_type": sso.GrantDeviceCode, "device_code": dc.DeviceCode, "client_id": devClient, "client_secret": devSecret, "scope": tc.pollScope}
			status, response, headers := fcPost(t, server.URL, "/token", poll)
			if status != http.StatusOK || headers.Get("Cache-Control") != "no-store" || headers.Get("Pragma") != "no-cache" {
				t.Fatalf("approved poll status/cache contract changed: %d", status)
			}
			assertDeviceOfflineReply(t, tc, dc, response, store)
			assertDeviceOfflineAudits(t, sink, int(store.writes.Load())-boolDeviceFailure(tc.failStore))
			assertDeviceOfflineReplayAndRotation(t, tc, server, poll, response, store)
		})
	}
}

func boolDeviceFailure(failed bool) int {
	if failed {
		return 1
	}
	return 0
}

func assertDeviceOfflineAudits(t *testing.T, sink *audit.MemorySink, want int) {
	t.Helper()
	events, err := sink.Query(t.Context(), audit.Query{Type: audit.EventRefreshTokenIssued})
	if err != nil || len(events) != want {
		t.Fatalf("refresh issuance audits=%d want=%d error=%v", len(events), want, err)
	}
}

func assertDeviceOfflineReply(t *testing.T, tc deviceOfflineCase, dc *oauth.DeviceCode, response map[string]any, store *codeRefreshStore) {
	t.Helper()
	wantWrites := int64(0)
	if tc.wantRefresh || tc.failStore {
		wantWrites = 1
	}
	if store.writes.Load() != wantWrites {
		t.Fatalf("managed refresh issue attempts=%d want=%d", store.writes.Load(), wantWrites)
	}
	refresh, present := response["refresh_token"]
	if present != tc.wantRefresh || (present && (refresh == "" || refresh == "synthetic-issuer-owned-refresh")) {
		t.Fatalf("refresh field presence=%v want=%v; issuer refresh must never leak", present, tc.wantRefresh)
	}
	if response["access_token"] == nil || response["scope"] != strings.Join(dc.Scopes, " ") {
		t.Fatal("access issuance or stored scope order changed")
	}
	_, idPresent := response["id_token"]
	if idPresent != slices.Contains(dc.Scopes, "openid") {
		t.Fatal("ID-token opt-in must be independent of offline access")
	}
	if tc.wantRefresh {
		stored, err := store.Inspect(t.Context(), refresh.(string))
		if err != nil || !reflect.DeepEqual(stored.Scopes, dc.Scopes) || stored.ClientID != devClient || stored.UserID != devUser || stored.FamilyID == "" || stored.Generation != 0 || stored.SID != "" || len(stored.AuthorizationDetails) != 0 {
			t.Fatal("managed initial refresh authorization or lineage changed")
		}
	}
}

func assertDeviceOfflineReplayAndRotation(t *testing.T, tc deviceOfflineCase, server *httptest.Server, poll, response map[string]any, store *codeRefreshStore) {
	t.Helper()
	writes := store.writes.Load()
	status, replay, _ := fcPost(t, server.URL, "/token", poll)
	if status != http.StatusBadRequest || replay["error"] != "invalid_grant" || store.writes.Load() != writes {
		t.Fatal("consumed device code replay must fail without new refresh issuance")
	}
	if !tc.wantRefresh {
		return
	}
	refresh := response["refresh_token"].(string)
	status, rotated := refreshExchange(t, server, refresh, "", devClient, devSecret)
	if status != http.StatusOK || rotated["refresh_token"] == nil || rotated["refresh_token"] == refresh || store.writes.Load() != writes+1 {
		t.Fatal("authorized existing-family refresh rotation changed")
	}
}
