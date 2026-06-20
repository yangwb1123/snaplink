package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// captureInviteSender records the last invitation token so the test can redeem it.
type captureInviteSender struct {
	mu                  sync.Mutex
	email, tenant, role string
	token               string
}

func (c *captureInviteSender) SendInvitation(_ context.Context, email, tenantID, role, token string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.email, c.tenant, c.role, c.token = email, tenantID, role, token
	return nil
}

func TestInvitation_SendAcceptFlow(t *testing.T) {
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: "u-alice"})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "inv-app", Secret: "s", Active: true,
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: "u-alice"}, nil
		},
	))
	members := defaultimpl.NewMemoryTenantUserStore()
	invites := defaultimpl.NewMemoryInvitationStore()
	sender := &captureInviteSender{}
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Hour))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithTenantUserStore(members),
		sso.WithInvitationStore(invites),
		sso.WithInvitationSender(sender),
	)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	// Admin sends an invite.
	code := putOrPostJSON(t, hs, http.MethodPost, "/api/v1/admin/tenants/acme/invitations", map[string]any{"email": "alice@acme.com", "role": "admin"})
	if code != http.StatusAccepted {
		t.Fatalf("send invite status=%d, want 202", code)
	}
	if sender.token == "" || sender.tenant != "acme" || sender.role != "admin" {
		t.Fatalf("sender did not capture invite: %+v", sender)
	}

	// Admin list shows the pending invite WITHOUT the token.
	lc, lbody := doReq(t, hs, http.MethodGet, "/api/v1/admin/tenants/acme/invitations", "")
	if lc != http.StatusOK {
		t.Fatalf("list invitations status=%d", lc)
	}
	raw, _ := json.Marshal(lbody)
	if bytes.Contains(raw, []byte(sender.token)) {
		t.Error("invitation list leaked the token value")
	}

	// Alice logs in and accepts the invite → joins acme as admin.
	tok := inviteLogin(t, hs)
	ac, abody := postBearerJSON(t, hs, "/me/invitations/accept", tok, map[string]any{"token": sender.token})
	if ac != http.StatusOK {
		t.Fatalf("accept status=%d body=%v", ac, abody)
	}
	if abody["tenant_id"] != "acme" || abody["role"] != "admin" {
		t.Errorf("accept response = %v", abody)
	}
	if m, err := members.Get(ctx, "acme", "u-alice"); err != nil || m.Role != sso.TenantRoleAdmin {
		t.Errorf("membership not granted: %+v, %v", m, err)
	}

	// Replaying the consumed token → invitation_invalid.
	rc, rbody := postBearerJSON(t, hs, "/me/invitations/accept", tok, map[string]any{"token": sender.token})
	if rc != http.StatusBadRequest || rbody["error"] != "invitation_invalid" {
		t.Errorf("replay status=%d body=%v, want 400 invitation_invalid", rc, rbody)
	}
}

func TestInvitation_SendRequiresSender(t *testing.T) {
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithTenantUserStore(defaultimpl.NewMemoryTenantUserStore()),
		sso.WithInvitationStore(defaultimpl.NewMemoryInvitationStore()),
		// no sender
	)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	code := putOrPostJSON(t, hs, http.MethodPost, "/api/v1/admin/tenants/acme/invitations", map[string]any{"email": "x@y.com"})
	if code != http.StatusNotImplemented {
		t.Errorf("send without sender status=%d, want 501", code)
	}
}

func putOrPostJSON(t *testing.T, srv *httptest.Server, method, path string, body any) int {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func postBearerJSON(t *testing.T, srv *httptest.Server, path, bearer string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

func inviteLogin(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider": "password", "client_id": "inv-app",
		"credential": map[string]string{"username": "alice", "password": "x"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	tok, _ := out["access_token"].(string)
	if tok == "" {
		t.Fatalf("no token: %s", raw)
	}
	return tok
}
