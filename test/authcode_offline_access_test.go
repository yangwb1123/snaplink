package ssotest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

type codeRefreshStore struct {
	*defaultimpl.MemoryRefreshTokenStore
	writes atomic.Int64
	fail   bool
}

func (s *codeRefreshStore) Issue(ctx context.Context, token string, info *oauth.RefreshToken) error {
	s.writes.Add(1)
	if s.fail {
		return errors.New("synthetic refresh-store outage")
	}
	return s.MemoryRefreshTokenStore.Issue(ctx, token, info)
}

type codeRefreshCase struct {
	name       string
	bound      []string
	requested  string
	want       bool
	status     int
	noStore    bool
	storeError bool
}

func newCodeRefreshServer(t *testing.T, tc codeRefreshCase) (*httptest.Server, *codeRefreshStore) {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: fcClientID, Active: true, TokenStrategy: "jwt", TokenEndpointAuthMethod: "none", RequirePKCE: true,
		AllowedScopes: []string{"openid", "profile", "offline_access"}, RedirectURIs: []string{fcRedirect}})
	codes := defaultimpl.NewMemoryAuthCodeStore()
	if err := codes.Issue(t.Context(), "synthetic-s25-code", &oauth.AuthCode{UserID: fcUserID, ClientID: fcClientID, Provider: "password", Scopes: tc.bound,
		RedirectURI: fcRedirect, CodeChallenge: fcChallenge(), CodeChallengeMethod: "S256", ExpiresAt: time.Now().Add(time.Minute),
		AuthTime: time.Unix(1700000000, 0), AuthMethods: []string{"pwd"}, ACR: "urn:test:pwd", SID: "synthetic-session", Resources: []string{"synthetic-api"}}); err != nil {
		t.Fatal(err)
	}
	store := &codeRefreshStore{MemoryRefreshTokenStore: defaultimpl.NewMemoryRefreshTokenStore(), fail: tc.storeError}
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(fcIssuer))
	opts := []sso.Option{sso.WithIssuer(fcIssuer), sso.WithClientStore(clients), sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer), sso.WithAuthCodeStore(codes, time.Minute)}
	if !tc.noStore {
		opts = append(opts, sso.WithRefreshTokenStore(store, time.Hour))
	}
	httpServer := httptest.NewServer(sso.NewServer(opts...).Handler())
	t.Cleanup(httpServer.Close)
	return httpServer, store
}

func codeRefreshExchange(t *testing.T, server *httptest.Server, requested string) (int, map[string]any) {
	t.Helper()
	status, reply, headers := fcPost(t, server.URL, "/token", map[string]any{"grant_type": "authorization_code", "client_id": fcClientID,
		"code": "synthetic-s25-code", "redirect_uri": fcRedirect, "code_verifier": fcVerifier, "scope": requested})
	if headers.Get("Cache-Control") != "no-store" || headers.Get("Pragma") != "no-cache" {
		t.Fatal("code exchange lost credential cache protection")
	}
	return status, reply
}

func TestE2E_AuthCodeOfflineAccessBoundaries(t *testing.T) {
	cases := []codeRefreshCase{
		{name: "no offline despite allowed client", bound: []string{"openid", "profile"}, status: 200},
		{name: "empty bound grant", status: 200},
		{name: "substring is not permission", bound: []string{"openid", "offline_access:read"}, status: 200},
		{name: "case is not permission", bound: []string{"openid", "OFFLINE_ACCESS"}, status: 200},
		{name: "explicit offline", bound: []string{"openid", "offline_access"}, want: true, status: 200},
		{name: "non OIDC offline", bound: []string{"offline_access"}, want: true, status: 200},
		{name: "narrow away offline", bound: []string{"openid", "profile", "offline_access"}, requested: "openid profile", status: 200},
		{name: "cannot expand grant", bound: []string{"openid"}, requested: "openid offline_access", status: 400},
		{name: "store unwired", bound: []string{"openid", "offline_access"}, noStore: true, status: 200},
		{name: "permitted store failure", bound: []string{"openid", "offline_access"}, storeError: true, status: 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, store := newCodeRefreshServer(t, tc)
			status, reply := codeRefreshExchange(t, server, tc.requested)
			if status != tc.status {
				t.Fatalf("code exchange status=%d want=%d", status, tc.status)
			}
			assertCodeRefreshReply(t, tc, reply, store)
			status, replay := codeRefreshExchange(t, server, tc.requested)
			if status != http.StatusBadRequest || replay["error"] != "invalid_grant" {
				t.Fatal("authorization code was not single-use")
			}
		})
	}
}

func assertCodeRefreshReply(t *testing.T, tc codeRefreshCase, reply map[string]any, store *codeRefreshStore) {
	t.Helper()
	if tc.status == http.StatusBadRequest {
		if reply["error"] != "invalid_scope" || store.writes.Load() != 0 {
			t.Fatal("scope expansion changed its error or wrote a refresh")
		}
		return
	}
	refresh, hasRefresh := reply["refresh_token"].(string)
	if hasRefresh != tc.want || (tc.want && refresh == "") {
		t.Fatalf("refresh returned=%t want=%t", hasRefresh, tc.want)
	}
	wantWrites := int64(0)
	if tc.want || tc.storeError {
		wantWrites = 1
	}
	if store.writes.Load() != wantWrites {
		t.Fatalf("refresh writes=%d want=%d", store.writes.Load(), wantWrites)
	}
	if reply["access_token"] == nil {
		t.Fatal("optional refresh policy removed access token")
	}
	claims := fcDecodeJWT(t, reply["access_token"])
	if claims["sid"] != "synthetic-session" || claims["auth_time"] != float64(1700000000) || claims["acr"] != "urn:test:pwd" {
		t.Fatal("code exchange changed authentication context")
	}
	if slices.Contains(tc.bound, core.ScopeOpenID) && reply["id_token"] == nil {
		t.Fatal("optional refresh policy removed ID token")
	}
	if tc.want {
		stored, err := store.Inspect(t.Context(), refresh)
		if err != nil || stored.SID != "synthetic-session" || !slices.Contains(stored.Scopes, core.ScopeOfflineAccess) || stored.FamilyID == "" {
			t.Fatal("refresh lost authorization/session/family binding")
		}
	}
}
