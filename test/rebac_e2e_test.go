package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/lifecycle/rebac"
	"github.com/snaplink/sso/shared/core"
)

func TestReBACE2E(t *testing.T) {
	ctx := context.Background()

	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()

	_ = users.CreateOrUpdate(ctx, &core.User{ID: "admin", Email: "admin@test.com"})
	_ = users.CreateOrUpdate(ctx, &core.User{ID: "alice", Email: "alice@test.com"})

	clients.AddSeed(&core.Client{
		ID: "rbac-admin", Secret: "secret", Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})

	issuer := defaultimpl.NewEd25519JWTIssuer()
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*core.AuthResult, error) {
			return &core.AuthResult{UserID: "admin", Provider: "password"}, nil
		},
	))

	store := rebac.NewMemoryStore()

	srv := sso.NewServer(
		sso.WithIssuer("https://sso.test"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithSessionManager(sessions),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRebacStore(store),
		sso.WithRebacEngine(rebac.NewEngine(store)),
	)

	hsrv := httptest.NewServer(srv.Handler())
	defer hsrv.Close()

	// Admin login
	loginBody, _ := json.Marshal(map[string]any{
		"provider": "password", "client_id": "rbac-admin",
		"credential": map[string]string{"username": "admin", "password": "x"},
	})
	loginResp, err := http.Post(hsrv.URL+"/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer loginResp.Body.Close()

	var loginResult map[string]any
	json.NewDecoder(loginResp.Body).Decode(&loginResult)
	if loginResp.StatusCode != 200 {
		t.Fatalf("admin login failed: %v", loginResult["error"])
	}
	adminToken := loginResult["access_token"].(string)

	// Helper to create a tuple via admin API
	createTuple := func(object, relation, subject string) {
		body, _ := json.Marshal(rebac.Tuple{
			Object: object, Relation: relation, Subject: subject,
		})
		req, _ := http.NewRequest("POST", hsrv.URL+"/authz/tuples", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("create tuple %s %s %s: %v", object, relation, subject, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 && resp.StatusCode != 201 {
			t.Fatalf("create tuple %s %s %s: status=%d", object, relation, subject, resp.StatusCode)
		}
	}

	// Helper to check access — uses GET with query params
	checkAccess := func(object, relation, subject string) (bool, error) {
		url := fmt.Sprintf("%s/authz/check?object=%s&relation=%s&subject=%s",
			hsrv.URL, object, relation, subject)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false, fmt.Errorf("check request: %w", err)
		}
		defer resp.Body.Close()
		var result map[string]any
		json.NewDecoder(resp.Body).Decode(&result)
		allowed, _ := result["allowed"].(bool)
		return allowed, nil
	}

	// --- Create tuples ---
	createTuple("doc:doc-1", "viewer", "user:alice")
	createTuple("doc:doc-1", "editor", "user:admin")
	createTuple("folder:folder-a", "parent", "doc:doc-1")

	// --- Check access ---
	cases := []struct {
		object, relation, subject string
		want                      bool
	}{
		{"doc:doc-1", "viewer", "user:alice", true},
		{"doc:doc-1", "editor", "user:alice", false},
		{"doc:doc-1", "editor", "user:admin", true},
		{"doc:doc-2", "viewer", "user:alice", false},
	}
	for _, tc := range cases {
		got, err := checkAccess(tc.object, tc.relation, tc.subject)
		if err != nil {
			t.Fatalf("check(%s,%s,%s): %v", tc.object, tc.relation, tc.subject, err)
		}
		if got != tc.want {
			t.Errorf("check(%s,%s,%s): expected %v, got %v", tc.object, tc.relation, tc.subject, tc.want, got)
		}
	}

	// --- List tuples ---
	listResp := getReq(t, hsrv.URL+"/authz/tuples", adminToken)
	var listResult map[string]any
	json.NewDecoder(listResp.Body).Decode(&listResult)
	listResp.Body.Close()
	if listResult["tuples"] == nil {
		t.Fatal("expected tuples in list response")
	}
	listed := listResult["tuples"].([]any)
	if len(listed) < 3 {
		t.Errorf("expected at least 3 tuples, got %d", len(listed))
	}

	// --- Delete tuple ---
	delBody, _ := json.Marshal(rebac.Tuple{
		Object: "doc:doc-1", Relation: "viewer", Subject: "user:alice",
	})
	delReq, _ := http.NewRequest("DELETE", hsrv.URL+"/authz/tuples", bytes.NewReader(delBody))
	delReq.Header.Set("Authorization", "Bearer "+adminToken)
	delReq.Header.Set("Content-Type", "application/json")
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("delete tuple: %v", err)
	}
	delResp.Body.Close()

	// Verify deletion
	got, err := checkAccess("doc:doc-1", "viewer", "user:alice")
	if err != nil {
		t.Fatalf("check after delete: %v", err)
	}
	if got {
		t.Error("expected viewer=false after tuple deletion")
	}

	t.Log("ReBAC E2E test passed")
}

func getReq(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}
