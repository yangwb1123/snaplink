package sso_test

// anomaly_tenant_test.go pins improvement-1's dispatch contract: login
// events delivered to the anomaly runner carry the resolved client's
// tenant, and a tenant-less client yields an empty tenant (legacy mode).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/anomaly"
	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// anomalyTenantSink captures the LoginEvent behind every delivered signal.
type anomalyTenantSink struct {
	mu     sync.Mutex
	events []*anomaly.LoginEvent
}

func (s *anomalyTenantSink) Record(_ context.Context, event *anomaly.LoginEvent, _ anomaly.Signal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (s *anomalyTenantSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// alwaysDetector yields one signal per event so the sink observes every
// dispatched event (a zero-detector runner would never call the sink).
type alwaysDetector struct{}

func (alwaysDetector) Name() string { return "always" }
func (alwaysDetector) Inspect(_ context.Context, e *anomaly.LoginEvent) ([]anomaly.Signal, error) {
	return []anomaly.Signal{{Type: "test", Severity: anomaly.SeverityInfo, SubjectID: e.SubjectID}}, nil
}

// TestAnomalyDispatch_CarriesResolvedClientTenant drives real /auth/login
// requests against a server with a tenant-scoped client and a tenant-less
// client, asserting the events the runner receives carry the client's
// tenant on both the failure and success paths.
func TestAnomalyDispatch_CarriesResolvedClientTenant(t *testing.T) {
	t.Parallel()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "alice"})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "t1-client", Secret: "s1", TenantID: "t1",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt", Active: true,
	})
	clients.AddSeed(&sso.Client{
		ID: "no-tenant-client", Secret: "s2",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(
		authenticators.PasswordVerifierFunc(func(_ context.Context, user, pass string) (*sso.AuthResult, error) {
			if user == "alice" && pass == "wonderland" {
				return &sso.AuthResult{UserID: "alice", Provider: "password"}, nil
			}
			return nil, errors.New("bad credentials")
		}),
	)
	sink := &anomalyTenantSink{}
	runner := anomaly.NewRunner([]anomaly.Detector{alwaysDetector{}}, sink)
	runner.Start()
	defer func() { _ = runner.Close(context.Background()) }()

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAnomalyRunner(runner),
	)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	login := func(clientID, password string) int {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"provider":   "password",
			"client_id":  clientID,
			"credential": map[string]string{"username": "alice", "password": password},
		})
		resp, err := http.Post(ts.URL+"/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	// Failure path: tenant-scoped client → event carries t1.
	if status := login("t1-client", "wrong"); status != http.StatusUnauthorized {
		t.Fatalf("bad-credential login = %d, want 401", status)
	}
	waitForAnomalyEvent(t, sink, 1)
	if got := sink.events[0].TenantID; got != "t1" {
		t.Errorf("failure event tenant = %q, want t1", got)
	}

	// Failure path: tenant-less client → empty tenant (legacy mode).
	if status := login("no-tenant-client", "wrong"); status != http.StatusUnauthorized {
		t.Fatalf("bad-credential login = %d, want 401", status)
	}
	waitForAnomalyEvent(t, sink, 2)
	if got := sink.events[1].TenantID; got != "" {
		t.Errorf("tenant-less failure event tenant = %q, want empty", got)
	}

	// Success path: tenant-scoped client → event carries t1.
	if status := login("t1-client", "wonderland"); status != http.StatusOK {
		t.Fatalf("good login = %d, want 200", status)
	}
	waitForAnomalyEvent(t, sink, 3)
	if got := sink.events[2].TenantID; got != "t1" {
		t.Errorf("success event tenant = %q, want t1", got)
	}
}

func waitForAnomalyEvent(t *testing.T, sink *anomalyTenantSink, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sink.count() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("runner delivered %d events, want %d", sink.count(), want)
}
