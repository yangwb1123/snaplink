package sso_test

// sse_admin_stream_test.go drives GET /api/v1/admin/events/stream through a
// REAL AdminMiddleware + audit.Recorder, mirroring TestRcovMisc_AuditAPI's
// server-building shape (rootcov_misc_test.go), so the wiring proven here
// (admin:read gate, the audit-pipeline tap installed by WithSSEBroker, the
// actual text/event-stream framing) matches what a production build sees.

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/sse"
)

// TestSSEOptInWiring proves WithSSEBroker is opt-in and byte-identical when
// absent (same proof shape as TestCAEPOptInWiring for the sibling tap).
func TestSSEOptInWiring(t *testing.T) {
	t.Parallel()

	primary := audit.NewMemorySink(8)
	recBaseline := audit.New(primary)
	sBaseline := sso.NewServer(sso.WithAuditRecorder(recBaseline))
	if sBaseline.SSEBroker() != nil {
		t.Fatal("baseline server reports a broker without the option")
	}
	if _, isMulti := sBaseline.AuditorSinkForTest().(*audit.MultiSink); isMulti {
		t.Fatal("baseline audit sink was wrapped without WithSSEBroker — not byte-identical")
	}

	broker := sse.NewBroker(sse.Options{})
	primary2 := audit.NewMemorySink(8)
	recWired := audit.New(primary2)
	sWired := sso.NewServer(
		sso.WithAuditRecorder(recWired),
		sso.WithSSEBroker(broker),
	)
	if sWired.SSEBroker() != broker {
		t.Fatal("SSEBroker() did not return the wired broker")
	}
	if _, isMulti := sWired.AuditorSinkForTest().(*audit.MultiSink); !isMulti {
		t.Fatal("audit sink was NOT tapped after WithSSEBroker")
	}
}

// TestSSEEventsStreamEndToEnd proves the full path: admin bearer auth gates
// the route, a live connection gets text/event-stream framing, and a login
// recorded AFTER the client connects arrives on the wire as an `event:
// login` frame.
func TestSSEEventsStreamEndToEnd(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: rcovUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Secret: rcovSecret, AllowedAuthenticators: []string{"password"},
		TokenStrategy: "jwt", Active: true, SkipConsent: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == rcovUsername && p == rcovPassword {
				return &sso.AuthResult{UserID: rcovUser}, nil
			}
			return nil, errors.New("bad")
		}))

	prov := permissions.NewMemoryProvider()
	_ = prov.AddRole(ctx, "", permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, rcovUser, "", []string{"root"})
	_ = prov.AddRole(ctx, rcovClient, permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = prov.AssignRoles(ctx, rcovUser, rcovClient, []string{"root"})

	broker := sse.NewBroker(sse.Options{})
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuditRecorder(audit.New(audit.NewMemorySink(50))),
		sso.WithSSEBroker(broker),
		sso.WithSSEHeartbeat(time.Hour), // long enough that no heartbeat noise hits the assertions below
		sso.WithPermissionProvider(prov),
	)
	mw := sso.NewAdminMiddleware(srv, prov)
	httpSrv := httptest.NewServer(mw.HTTPMiddleware(srv.Handler()))
	t.Cleanup(httpSrv.Close)
	t.Cleanup(broker.Close)

	streamURL := httpSrv.URL + "/api/v1/admin/events/stream"

	// Unauthenticated stream request: the admin middleware rejects it before
	// the handler ever subscribes — a plain 401, no open connection to drain.
	status, _ := rcovDo(t, http.MethodGet, streamURL, "", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("unauth stream = %d, want 401", status)
	}

	// Login to obtain an admin bearer token. This login's own audit event
	// fires BEFORE the stream connects, so it must NOT surface below (no
	// Last-Event-ID => no replay; see platform/sse for replay coverage).
	status, out := rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	if status != http.StatusOK {
		t.Fatalf("admin login = %d body=%v", status, out)
	}
	token, _ := out["access_token"].(string)
	if token == "" {
		t.Fatalf("no admin token: %v", out)
	}

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, streamURL, nil)
	if err != nil {
		t.Fatalf("new stream request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stream connect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	// By the time Do() returns, HandleStream has already Subscribed and
	// flushed headers (Subscribe -> writeStreamHeaders -> flush all happen
	// before the handler blocks on the live loop) — so this second login,
	// issued only now, is guaranteed to be observed live rather than raced
	// against subscription setup.
	status, out = rcovPostJSON(t, httpSrv.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	if status != http.StatusOK {
		t.Fatalf("trigger login = %d body=%v", status, out)
	}

	reader := bufio.NewReader(resp.Body)
	found := false
	for {
		line, rerr := reader.ReadString('\n')
		if strings.Contains(line, "event: login") {
			found = true
			break
		}
		if rerr != nil {
			break
		}
	}
	if !found {
		t.Fatal("did not observe an `event: login` frame on the stream after the trigger login")
	}
}
