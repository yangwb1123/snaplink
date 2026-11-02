package ssotest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

type admissionObservedStore struct {
	oauth.CIBAStore
	writes atomic.Int64
	lastID atomic.Value
}

func (s *admissionObservedStore) Issue(ctx context.Context, req *oauth.CIBARequest) (string, error) {
	s.writes.Add(1)
	id, err := s.CIBAStore.Issue(ctx, req)
	if err == nil {
		s.lastID.Store(id)
	}
	return id, err
}

type backchannelHTTPFixture struct {
	*cibaGrantHTTPFixture
	observed   *admissionObservedStore
	challenges atomic.Int64
}

func newBackchannelHTTP(t *testing.T, backend, mode string, grants []string) *backchannelHTTPFixture {
	t.Helper()
	requests, refresh := newCIBAGrantStores(t, backend)
	observed := &admissionObservedStore{CIBAStore: requests}
	f := &backchannelHTTPFixture{cibaGrantHTTPFixture: &cibaGrantHTTPFixture{requests: observed, refresh: refresh,
		sink: audit.NewMemorySink(100), notified: make(chan string, 1)}, observed: observed}
	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(t.Context(), &sso.User{ID: cibaUser}); err != nil {
		t.Fatal(err)
	}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: cibaClient, Secret: cibaSecret, Active: true, TokenStrategy: "jwt", GrantTypes: grants,
		AllowedScopes: []string{"openid", "api:read", "offline_access"}, AllowedResources: []string{"https://s36.invalid/resource"}, RefreshTokenTTL: 17 * time.Minute})
	issuer := defaultimpl.NewEd25519JWTIssuer()
	transport := oauth.CIBATransportFunc(func(context.Context, string, string, map[string]string) error { f.challenges.Add(1); return nil })
	opts := []sso.Option{sso.WithUserProvider(users), sso.WithClientStore(clients), sso.WithTokenIssuer("jwt", directOfflineIssuer{issuer}),
		sso.WithIDTokenIssuer(issuer), sso.WithAuditRecorder(audit.New(f.sink)), sso.WithCIBA(observed, transport, time.Minute, time.Millisecond),
		sso.WithRefreshTokenStore(refresh, time.Hour)}
	opts = append(opts, f.deliveryOptions(t, mode)...)
	f.server = sso.NewServer(opts...)
	f.http = httptest.NewServer(f.server.Handler())
	f.http.Client().Timeout = 3 * time.Second
	t.Cleanup(f.http.Close)
	return f
}

func (f *backchannelHTTPFixture) auditEvents(t *testing.T, kind audit.EventType) int {
	t.Helper()
	events, err := f.sink.Query(t.Context(), audit.Query{Type: kind})
	if err != nil {
		t.Fatal(err)
	}
	return len(events)
}

func (f *backchannelHTTPFixture) assertDenied(t *testing.T, status int, response map[string]any, wantStatus int, code string) {
	t.Helper()
	if status != wantStatus || response["error"] != code {
		t.Errorf("admission status/error=%d/%v, want %d/%s", status, response["error"], wantStatus, code)
	}
	for _, key := range []string{"auth_req_id", "access_token", "refresh_token", "id_token"} {
		if _, present := response[key]; present {
			t.Errorf("rejected admission returned %s", key)
		}
	}
	if f.observed.writes.Load() != 0 || f.observed.lastID.Load() != nil || f.challenges.Load() != 0 || f.count(t) != 0 || f.auditCount(t) != 0 || f.auditEvents(t, audit.EventCIBAAuthRequest) != 0 || f.auditEvents(t, audit.EventTokenIssued) != 0 {
		t.Error("rejected admission persisted/delivered a request, issued credentials or recorded success")
	}
}

func TestE2E_BackchannelGrantAdmission_StoresAndDelivery(t *testing.T) {
	cases := []struct {
		name, scope string
		grants      []string
		permitted   bool
		refresh     bool
	}{
		{name: "nil legacy", scope: "openid api:read", permitted: true, refresh: true},
		{name: "empty legacy", scope: "openid", grants: []string{}, permitted: true, refresh: true},
		{name: "explicit with refresh no offline", scope: "openid", grants: []string{oauth.GrantCIBA, sso.GrantRefreshToken}, permitted: true, refresh: true},
		{name: "explicit without refresh", scope: "openid", grants: []string{oauth.GrantCIBA}, permitted: true},
		{name: "refresh only", scope: "openid", grants: []string{sso.GrantRefreshToken}},
		{name: "case alias", scope: "openid", grants: []string{strings.ToUpper(oauth.GrantCIBA), sso.GrantRefreshToken}},
		{name: "offline cannot authorize", scope: "openid offline_access", grants: []string{sso.GrantRefreshToken}},
		{name: "omitted resource defaults", grants: []string{oauth.GrantCIBA, sso.GrantRefreshToken}, permitted: true, refresh: true},
	}
	for _, backend := range []string{"memory", "sqlite"} {
		for _, mode := range []string{"poll", "ping", "push"} {
			for _, tc := range cases {
				t.Run(backend+"/"+mode+"/"+tc.name, func(t *testing.T) {
					t.Parallel()
					f := newBackchannelHTTP(t, backend, mode, tc.grants)
					if !tc.permitted {
						body := map[string]any{"client_id": cibaClient, "client_secret": cibaSecret, "login_hint": cibaUser, "scope": tc.scope}
						if mode != "poll" {
							body["client_notification_token"] = "synthetic-s36-notification"
						}
						status, response := f.post(t, "/backchannel-authentication", body)
						f.assertDenied(t, status, response, http.StatusBadRequest, "unauthorized_client")
						return
					}
					grant := cibaGrantHTTPCase{scope: tc.scope, wantRefresh: tc.refresh}
					r, response := f.complete(t, mode, grant)
					f.assertReply(t, grant, r, response)
					f.assertReplayAndRotation(t, grant, r, response)
					if f.observed.writes.Load() != 1 || f.challenges.Load() != 1 || f.auditEvents(t, audit.EventCIBAAuthRequest) != 1 || !reflect.DeepEqual(r.Resources, []string{"https://s36.invalid/resource"}) {
						t.Fatal("authorized pending/challenge/audit or approved resource context changed")
					}
				})
			}
		}
	}
}

func TestE2E_BackchannelGrantAdmission_ErrorPrecedence(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, tc := range []struct {
			name, code string
			status     int
		}{
			{"bad secret", "invalid_client", 401},
			{"unknown client", "invalid_client", 401},
			{"inactive", "inactive_client", 403},
			{"bad resource", "invalid_target", 400},
		} {
			t.Run(backend+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				f := newBackchannelHTTP(t, backend, "poll", []string{sso.GrantRefreshToken})
				body := map[string]any{"client_id": cibaClient, "client_secret": cibaSecret, "login_hint": cibaUser, "scope": "openid"}
				switch tc.name {
				case "bad secret":
					body["client_secret"] = "wrong"
				case "unknown client":
					body["client_id"] = "unknown"
				case "inactive":
					client, err := f.server.ClientStoreAccessor().Get(t.Context(), cibaClient)
					if err != nil {
						t.Fatal(err)
					}
					client.Active = false
					if err := f.server.ClientStoreAccessor().Update(t.Context(), client); err != nil {
						t.Fatal(err)
					}
				case "bad resource":
					body["resource"] = []string{"https://other.invalid"}
				}
				status, response := f.post(t, "/backchannel-authentication", body)
				f.assertDenied(t, status, response, tc.status, tc.code)
			})
		}
	}
}
