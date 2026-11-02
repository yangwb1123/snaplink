package ssotest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

type authCodeGrantHTTPCase struct {
	name                            string
	grants, scopes                  []string
	requested                       string
	wantRefresh, noStore, failStore bool
	status                          int
}

func authCodeGrantHTTPCases() []authCodeGrantHTTPCase {
	allow := []string{sso.GrantAuthorizationCode, sso.GrantRefreshToken}
	offline := []string{"openid", "offline_access"}
	return []authCodeGrantHTTPCase{
		{name: "nil legacy", scopes: offline, wantRefresh: true},
		{name: "empty legacy", grants: []string{}, scopes: offline, wantRefresh: true},
		{name: "explicit permits", grants: allow, scopes: offline, wantRefresh: true},
		{name: "duplicate exact", grants: []string{sso.GrantAuthorizationCode, sso.GrantRefreshToken, sso.GrantRefreshToken}, scopes: offline, wantRefresh: true},
		{name: "code alone despite allowed offline and attributes", grants: []string{sso.GrantAuthorizationCode}, scopes: offline},
		{name: "case alias", grants: []string{sso.GrantAuthorizationCode, "REFRESH_TOKEN"}, scopes: offline},
		{name: "prefix alias", grants: []string{sso.GrantAuthorizationCode, "xrefresh_token"}, scopes: offline},
		{name: "suffix alias", grants: []string{sso.GrantAuthorizationCode, "refresh_token:extra"}, scopes: offline},
		{name: "whitespace alias", grants: []string{sso.GrantAuthorizationCode, "refresh_token "}, scopes: offline},
		{name: "unsplit entry", grants: []string{sso.GrantAuthorizationCode, "authorization_code refresh_token"}, scopes: offline},
		{name: "empty entry", grants: []string{sso.GrantAuthorizationCode, ""}, scopes: offline},
		{name: "grant list alone no offline", grants: allow, scopes: []string{"openid", "profile"}},
		{name: "narrow away offline", grants: allow, scopes: offline, requested: "openid"},
		{name: "scope cannot expand", grants: allow, scopes: []string{"openid"}, requested: "openid offline_access", status: 400},
		{name: "allowed unwired no issuer fallback", grants: allow, scopes: offline, noStore: true},
		{name: "denied unwired no issuer fallback", grants: []string{sso.GrantAuthorizationCode}, scopes: offline, noStore: true},
		{name: "authorized outage", grants: allow, scopes: offline, failStore: true},
		{name: "denied outage unreachable", grants: []string{sso.GrantAuthorizationCode}, scopes: offline, failStore: true},
	}
}

// The fault is an explicit issue seam; persistence counts come from the real
// underlying memory/SQLite store, not this wrapper's counter.
type authCodeGrantHTTPRefresh struct {
	oauth.RefreshTokenStore
	oauth.RefreshTokenFamilyTracker
	calls atomic.Int64
	fail  bool
}

func (s *authCodeGrantHTTPRefresh) Issue(ctx context.Context, token string, info *oauth.RefreshToken) error {
	s.calls.Add(1)
	if s.fail {
		return errors.New("synthetic authcode issue outage")
	}
	return s.RefreshTokenStore.Issue(ctx, token, info)
}

type authCodeGrantHTTPFixture struct {
	http    *httptest.Server
	codes   oauth.AuthCodeStore
	refresh oauth.RefreshTokenStore
	issue   *authCodeGrantHTTPRefresh
	sink    *audit.MemorySink
	issuer  *defaultimpl.Ed25519JWTIssuer
	code    *oauth.AuthCode
}

func newAuthCodeGrantHTTPStores(t *testing.T, backend string) (oauth.AuthCodeStore, oauth.RefreshTokenStore) {
	t.Helper()
	if backend == "memory" {
		return defaultimpl.NewMemoryAuthCodeStore(), defaultimpl.NewMemoryRefreshTokenStore()
	}
	dsn := "file:" + filepath.Join(t.TempDir(), "owned-authcode.sqlite") + "?_journal=WAL"
	codes, err := sqlitestores.NewAuthCodeStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := codes.Close(); err != nil {
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
	return codes, refresh
}

func newAuthCodeGrantHTTP(t *testing.T, backend string, tc authCodeGrantHTTPCase) *authCodeGrantHTTPFixture {
	t.Helper()
	codes, refresh := newAuthCodeGrantHTTPStores(t, backend)
	f := &authCodeGrantHTTPFixture{codes: codes, refresh: refresh, sink: audit.NewMemorySink(100), issuer: defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(fcIssuer))}
	f.issue = &authCodeGrantHTTPRefresh{RefreshTokenStore: refresh, RefreshTokenFamilyTracker: refresh.(oauth.RefreshTokenFamilyTracker), fail: tc.failStore}
	f.code = &oauth.AuthCode{UserID: fcUserID, ClientID: fcClientID, Provider: "password", Scopes: tc.scopes, RedirectURI: fcRedirect, CodeChallenge: fcChallenge(), CodeChallengeMethod: "S256", ExpiresAt: time.Now().Add(time.Minute), AuthTime: time.Unix(1700000000, 0), AuthMethods: []string{"pwd", "mfa"}, ACR: "urn:s42:acr", Nonce: "s42-rp-nonce", Attributes: map[string]string{"locale": "en-US"}, Resources: []string{"https://s42.invalid/api"}, AuthorizationDetails: []byte(`[{"type":"unit","id":"a"}]`)}
	if err := codes.Issue(t.Context(), "synthetic-s42-code", f.code); err != nil {
		t.Fatal(err)
	}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: fcClientID, Active: true, TokenStrategy: "jwt", TokenEndpointAuthMethod: "none", RequirePKCE: true, GrantTypes: tc.grants, AllowedScopes: []string{"openid", "profile", "offline_access"}, AllowedResources: f.code.Resources, RedirectURIs: []string{fcRedirect}, RefreshTokenTTL: 17 * time.Minute, Attributes: map[string]string{"grant_types": sso.GrantRefreshToken}})
	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(t.Context(), &sso.User{ID: fcUserID}); err != nil {
		t.Fatal(err)
	}
	opts := []sso.Option{sso.WithIssuer(fcIssuer), sso.WithUserProvider(users), sso.WithClientStore(clients), sso.WithTokenIssuer("jwt", directOfflineIssuer{f.issuer}), sso.WithIDTokenIssuer(f.issuer), sso.WithAuthCodeStore(codes, time.Minute), sso.WithAuditRecorder(audit.New(f.sink))}
	if !tc.noStore {
		opts = append(opts, sso.WithRefreshTokenStore(f.issue, time.Hour))
	}
	f.http = httptest.NewServer(sso.NewServer(opts...).Handler())
	f.http.Client().Timeout = 3 * time.Second
	t.Cleanup(f.http.Close)
	return f
}

func (f *authCodeGrantHTTPFixture) post(t *testing.T, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil || len(raw) > 16384 {
		t.Fatal("bounded request serialization failed")
	}
	resp, err := f.http.Client().Post(f.http.URL+"/token", "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err = io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(raw) > 65536 {
		t.Fatal("bounded response read failed")
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

func (f *authCodeGrantHTTPFixture) exchange(t *testing.T, scope string) (int, map[string]any) {
	t.Helper()
	return f.post(t, map[string]any{"grant_type": sso.GrantAuthorizationCode, "client_id": fcClientID, "code": "synthetic-s42-code", "redirect_uri": fcRedirect, "code_verifier": fcVerifier, "scope": scope})
}

func (f *authCodeGrantHTTPFixture) count(t *testing.T) int {
	t.Helper()
	n, err := f.refresh.(oauth.RefreshTokenSubjectCounter).CountForSubject(t.Context(), fcUserID, fcClientID)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *authCodeGrantHTTPFixture) auditCount(t *testing.T) int {
	t.Helper()
	events, err := f.sink.Query(t.Context(), audit.Query{Type: audit.EventRefreshTokenIssued})
	if err != nil {
		t.Fatal(err)
	}
	return len(events)
}

func TestE2E_AuthCodeRefreshGrant_RealStores(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, tc := range authCodeGrantHTTPCases() {
			t.Run(backend+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				f := newAuthCodeGrantHTTP(t, backend, tc)
				status, reply := f.exchange(t, tc.requested)
				want := http.StatusOK
				if tc.status != 0 {
					want = tc.status
				}
				if status != want {
					t.Fatalf("code exchange status=%d want=%d", status, want)
				}
				f.assertReply(t, tc, reply)
				count, events, calls := f.count(t), f.auditCount(t), f.issue.calls.Load()
				status, replay := f.exchange(t, tc.requested)
				if status != 400 || replay["error"] != "invalid_grant" || f.count(t) != count || f.auditCount(t) != events || f.issue.calls.Load() != calls {
					t.Fatal("consumed code replay changed error or storage/events")
				}
				if tc.wantRefresh {
					f.assertRotation(t, reply["refresh_token"].(string))
				}
			})
		}
	}
}

func (f *authCodeGrantHTTPFixture) assertReply(t *testing.T, tc authCodeGrantHTTPCase, reply map[string]any) {
	t.Helper()
	wantRows, wantCalls := 0, int64(0)
	if tc.wantRefresh {
		wantRows = 1
	}
	if tc.wantRefresh || tc.failStore && slices.Contains(tc.grants, sso.GrantRefreshToken) {
		wantCalls = 1
	}
	_, present := reply["refresh_token"]
	if present != tc.wantRefresh || f.count(t) != wantRows || f.auditCount(t) != wantRows || f.issue.calls.Load() != wantCalls {
		t.Fatal("initial refresh key, real persistence, issue calls or audit count mismatch")
	}
	if tc.status == 400 {
		if reply["error"] != "invalid_scope" || reply["access_token"] != nil {
			t.Fatal("scope expansion error changed")
		}
		return
	}
	if _, err := f.issuer.Validate(t.Context(), reply["access_token"].(string)); err != nil {
		t.Fatal("access signature validation failed")
	}
	effective := tc.scopes
	if tc.requested != "" {
		effective = strings.Fields(tc.requested)
	}
	claims := fcDecodeJWT(t, reply["access_token"])
	if claims["sub"] != fcUserID || claims["client_id"] != fcClientID || claims["scope"] != strings.Join(effective, " ") || claims["auth_time"] != float64(1700000000) || claims["acr"] != f.code.ACR || claims["sid"] != nil {
		t.Fatal("independent access/authentication/sessionless claims changed")
	}
	if _, present := reply["id_token"]; present != slices.Contains(effective, "openid") {
		t.Fatal("independent ID token presence changed")
	}
	if tc.wantRefresh {
		f.assertStored(t, reply["refresh_token"], effective)
	}
}

func (f *authCodeGrantHTTPFixture) assertStored(t *testing.T, raw any, effective []string) {
	t.Helper()
	token, ok := raw.(string)
	if !ok || token == "" || token == "synthetic-issuer-owned-refresh" {
		t.Fatal("managed refresh absent or issuer fallback leaked")
	}
	stored, err := f.refresh.(oauth.RefreshTokenInspector).Inspect(t.Context(), token)
	if err != nil || !reflect.DeepEqual(stored.Scopes, effective) || !reflect.DeepEqual(stored.Resources, f.code.Resources) || !reflect.DeepEqual(stored.Attributes, f.code.Attributes) || string(stored.AuthorizationDetails) != string(f.code.AuthorizationDetails) || !reflect.DeepEqual(stored.Amr, f.code.AuthMethods) || stored.Acr != f.code.ACR || !stored.AuthTime.Equal(f.code.AuthTime) || stored.SID != "" || stored.UserID != fcUserID || stored.ClientID != fcClientID || stored.Provider != "password" || stored.FamilyID == "" || stored.Generation != 0 || stored.ExpiresAt.Sub(stored.IssuedAt) != 17*time.Minute {
		t.Fatal("stored approved code, subject, context, TTL or initial family changed")
	}
}

func (f *authCodeGrantHTTPFixture) assertRotation(t *testing.T, parentToken string) {
	t.Helper()
	parent, err := f.refresh.(oauth.RefreshTokenInspector).Inspect(t.Context(), parentToken)
	if err != nil {
		t.Fatal(err)
	}
	status, reply := f.post(t, map[string]any{"grant_type": sso.GrantRefreshToken, "refresh_token": parentToken, "client_id": fcClientID})
	childToken, ok := reply["refresh_token"].(string)
	if status != 200 || !ok || childToken == "" || childToken == parentToken || f.count(t) != 1 || f.auditCount(t) != 2 {
		t.Fatal("authorized existing-family rotation changed")
	}
	child, err := f.refresh.(oauth.RefreshTokenInspector).Inspect(t.Context(), childToken)
	if err != nil || child.FamilyID != parent.FamilyID || child.Generation != 1 || !child.AuthTime.Equal(parent.AuthTime) || child.Acr != parent.Acr || !reflect.DeepEqual(child.Amr, parent.Amr) || !reflect.DeepEqual(child.Scopes, parent.Scopes) || !reflect.DeepEqual(child.Resources, parent.Resources) || !child.FamilyCreatedAt.Equal(parent.FamilyCreatedAt) {
		t.Fatal("rotation lost original family/grant/authentication age")
	}
	status, replay := f.post(t, map[string]any{"grant_type": sso.GrantRefreshToken, "refresh_token": parentToken, "client_id": fcClientID})
	if status != 400 || replay["error"] != "invalid_grant" || f.count(t) != 0 {
		t.Fatal("refresh reuse did not invalidate the family")
	}
}
