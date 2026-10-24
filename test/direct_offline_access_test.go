package ssotest

import (
	"context"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/conditionalaccess"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
)

type directOfflineIssuer struct{ *defaultimpl.Ed25519JWTIssuer }

func (i directOfflineIssuer) Issue(ctx context.Context, subject *core.Subject, scopes []string) (*core.Token, error) {
	token, err := i.Ed25519JWTIssuer.Issue(ctx, subject, scopes)
	if token != nil {
		token.RefreshToken = "synthetic-issuer-owned-refresh"
	}
	return token, err
}

type directOfflineCase struct {
	name                    string
	scopes                  []string
	wantRefresh             bool
	noStore, failStore      bool
	issuerRefresh, restrict bool
	denyOffline             bool
	status                  int
}

func newDirectOfflineServer(t *testing.T, tc directOfflineCase) (*httptest.Server, *codeRefreshStore, *audit.MemorySink) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(t.Context(), &sso.User{ID: fcUserID}); err != nil {
		t.Fatal(err)
	}
	clients := defaultimpl.NewMemoryClientStore()
	allowed := []string{"openid", "profile", "offline_access", "offline_access:read", "OFFLINE_ACCESS"}
	if tc.denyOffline {
		allowed = []string{"openid", "profile"}
	}
	clients.AddSeed(&sso.Client{ID: fcClientID, Active: true, TokenStrategy: "jwt", AllowedScopes: allowed})
	password := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(func(context.Context, string, string) (*sso.AuthResult, error) {
		return &sso.AuthResult{UserID: fcUserID, AuthMethods: []string{"pwd"}, AchievedACR: "urn:test:pwd"}, nil
	}))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(fcIssuer))
	var accessIssuer core.TokenIssuer = issuer
	if tc.issuerRefresh {
		accessIssuer = directOfflineIssuer{issuer}
	}
	store := &codeRefreshStore{MemoryRefreshTokenStore: defaultimpl.NewMemoryRefreshTokenStore(), fail: tc.failStore}
	sink := audit.NewMemorySink(50)
	opts := []sso.Option{sso.WithIssuer(fcIssuer), sso.WithUserProvider(users), sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients), sso.WithAuthenticator(password), sso.WithTokenIssuer("jwt", accessIssuer), sso.WithIDTokenIssuer(issuer), sso.WithAuditRecorder(audit.New(sink))}
	if !tc.noStore {
		opts = append(opts, sso.WithRefreshTokenStore(store, time.Hour))
	}
	if tc.restrict {
		policy := conditionalaccess.NewMemoryStore()
		if err := policy.Put(t.Context(), conditionalaccess.Policy{Name: "direct-offline", Enabled: true, Actions: conditionalaccess.Actions{RestrictScopes: []string{"openid", "profile"}}}); err != nil {
			t.Fatal(err)
		}
		opts = append(opts, sso.WithConditionalAccess(policy, conditionalaccess.Config{Enforce: true}))
	}
	server := httptest.NewServer(sso.NewServer(opts...).Handler())
	t.Cleanup(server.Close)
	return server, store, sink
}

func TestE2E_DirectOfflineAccessBoundaries(t *testing.T) {
	cases := []directOfflineCase{
		{name: "no offline", scopes: []string{"openid", "profile"}, status: 200},
		{name: "omitted scope", status: 200},
		{name: "empty scope", scopes: []string{}, status: 200},
		{name: "substring", scopes: []string{"openid", "offline_access:read"}, status: 200},
		{name: "case alias", scopes: []string{"openid", "OFFLINE_ACCESS"}, status: 200},
		{name: "explicit offline", scopes: []string{"openid", "offline_access"}, wantRefresh: true, status: 200},
		{name: "non OIDC offline", scopes: []string{"offline_access"}, wantRefresh: true, status: 200},
		{name: "policy removes offline", scopes: []string{"openid", "profile", "offline_access"}, restrict: true, status: 200},
		{name: "client denies offline", scopes: []string{"openid", "offline_access"}, denyOffline: true, status: 400},
		{name: "issuer no offline managed", scopes: []string{"openid"}, issuerRefresh: true, status: 200},
		{name: "issuer no offline unwired", scopes: []string{"openid"}, issuerRefresh: true, noStore: true, status: 200},
		{name: "issuer explicit offline unwired", scopes: []string{"openid", "offline_access"}, issuerRefresh: true, noStore: true, wantRefresh: true, status: 200},
		{name: "managed overrides issuer", scopes: []string{"openid", "offline_access"}, issuerRefresh: true, wantRefresh: true, status: 200},
		{name: "authorized store failure", scopes: []string{"openid", "offline_access"}, failStore: true, status: 200},
		{name: "failure cannot fall back to issuer", scopes: []string{"openid", "offline_access"}, failStore: true, issuerRefresh: true, status: 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, store, sink := newDirectOfflineServer(t, tc)
			body := map[string]any{"provider": "password", "client_id": fcClientID, "credential": map[string]string{"username": "synthetic-user", "password": "synthetic-password"}, "nonce": "synthetic-nonce"}
			if tc.scopes != nil {
				body["scope"] = tc.scopes
			}
			status, response, headers := fcPost(t, server.URL, "/auth/login", body)
			if status != tc.status || headers.Get("Cache-Control") != "no-store" || headers.Get("Pragma") != "no-cache" {
				t.Fatalf("direct status/cache mismatch: status=%d want=%d", status, tc.status)
			}
			assertDirectOfflineReply(t, tc, response, store)
			wantEvents := 0
			if tc.wantRefresh && !tc.noStore {
				wantEvents = 1
			}
			events, err := sink.Query(t.Context(), audit.Query{Type: audit.EventRefreshTokenIssued})
			if err != nil || len(events) != wantEvents {
				t.Fatalf("refresh issuance audits=%d want=%d error=%v", len(events), wantEvents, err)
			}
		})
	}
}

func assertDirectOfflineReply(t *testing.T, tc directOfflineCase, response map[string]any, store *codeRefreshStore) {
	t.Helper()
	wantWrites := int64(0)
	if (tc.wantRefresh || tc.failStore) && !tc.noStore {
		wantWrites = 1
	}
	if store.writes.Load() != wantWrites {
		t.Fatalf("managed refresh writes=%d want=%d", store.writes.Load(), wantWrites)
	}
	if tc.status == 400 {
		if response["error"] != "invalid_scope" || response["access_token"] != nil {
			t.Fatal("client ceiling rejection changed")
		}
		return
	}
	_, present := response["refresh_token"]
	refresh, _ := response["refresh_token"].(string)
	if present != tc.wantRefresh || (tc.wantRefresh && refresh == "") {
		t.Fatalf("refresh field present=%t want=%t", present, tc.wantRefresh)
	}
	sid, _ := response["session_id"].(string)
	if sid == "" || response["access_token"] == nil || fcDecodeJWT(t, response["access_token"])["sid"] != sid {
		t.Fatal("direct access/session issuance changed")
	}
	if slices.Contains(tc.scopes, "openid") && (response["id_token"] == nil || fcDecodeJWT(t, response["id_token"])["sid"] != sid) {
		t.Fatal("direct ID-token opt-in or SID changed")
	}
	if tc.wantRefresh && !tc.noStore {
		stored, err := store.Inspect(t.Context(), refresh)
		if err != nil || stored.SID != sid || !slices.Contains(stored.Scopes, "offline_access") || stored.FamilyID == "" || refresh == "synthetic-issuer-owned-refresh" {
			t.Fatal("managed refresh authorization/ownership/session changed")
		}
	}
}
