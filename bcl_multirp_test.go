package sso_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/security"
)

const (
	multiUser   = "u-multi"
	multiCliA   = "multi-client-a"
	multiCliB   = "multi-client-b"
	multiCliC   = "multi-client-c"
	multiSecret = "secret"
	multiPasswd = "pw"
	multiBCAURI = "https://app-a.example/bc-logout"
	multiBCBURI = "https://app-b.example/bc-logout"
)

// newMultiRPHarness wires three clients with distinct BC URIs and an
// in-memory security.SubjectClientIndex so the fan-out path can be observed.
// Client C deliberately has NO BackchannelLogoutURI to verify the
// fan-out skips clients that don't speak BCL.
func newMultiRPHarness(t *testing.T) (*httptest.Server, *captureNotifier, security.SubjectClientIndex) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: multiUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: multiCliA, Secret: multiSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		BackchannelLogoutURI:  multiBCAURI,
	})
	clients.AddSeed(&sso.Client{
		ID: multiCliB, Secret: multiSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		BackchannelLogoutURI:  multiBCBURI,
	})
	clients.AddSeed(&sso.Client{
		ID: multiCliC, Secret: multiSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		// No BackchannelLogoutURI — should be skipped during fan-out.
	})

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != multiPasswd {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: multiUser}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer()
	notifier := &captureNotifier{}
	idx := defaultimpl.NewMemorySubjectClientIndex()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithBackchannelLogout(issuer, notifier),
		sso.WithSubjectClientIndex(idx),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, notifier, idx
}

// loginAsMultiRP drives /auth/login against a specific client and returns
// the access_token from the response.
func loginAsMultiRP(t *testing.T, srv *httptest.Server, clientID string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  clientID,
		"credential": map[string]string{"username": multiUser, "password": multiPasswd},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login %s: %v", clientID, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login %s status=%d body=%s", clientID, resp.StatusCode, rb)
	}
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	tok, _ := out["access_token"].(string)
	if tok == "" {
		t.Fatalf("login %s returned no access_token: %s", clientID, rb)
	}
	return tok
}

func TestBCLFanOut_NotifiesEveryRPWithLogoutURI(t *testing.T) {
	srv, notifier, _ := newMultiRPHarness(t)

	// User signs into all three clients in turn. After each
	// login, the security.SubjectClientIndex records (multiUser, clientID).
	tokA := loginAsMultiRP(t, srv, multiCliA)
	_ = loginAsMultiRP(t, srv, multiCliB)
	_ = loginAsMultiRP(t, srv, multiCliC)

	// POST /logout with the client-A bearer. Multi-RP fan-out
	// MUST notify both A AND B (each declares a BC URI). C is
	// in the index but has no BC URI → must be skipped without
	// erroring.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/logout", bytes.NewReader([]byte("{}")))
	req.Header.Set("Authorization", "Bearer "+tokA)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout status=%d", resp.StatusCode)
	}

	calls := notifier.snapshot()
	if len(calls) != 2 {
		t.Fatalf("expected 2 BCL notifications (A + B); got %d: %+v", len(calls), calls)
	}
	gotURIs := []string{calls[0].URI, calls[1].URI}
	sort.Strings(gotURIs)
	wantURIs := []string{multiBCAURI, multiBCBURI}
	sort.Strings(wantURIs)
	if gotURIs[0] != wantURIs[0] || gotURIs[1] != wantURIs[1] {
		t.Errorf("URIs = %v want %v", gotURIs, wantURIs)
	}
}

func TestBCLFanOut_FallsBackToSingleRPWithoutIndex(t *testing.T) {
	// Identical wiring but NO security.SubjectClientIndex — confirms the
	// fan-out helper degrades to the single-RP behavior when the
	// index isn't wired (zero behavior change for legacy ops).
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: multiUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: multiCliA, Secret: multiSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		BackchannelLogoutURI:  multiBCAURI,
	})
	clients.AddSeed(&sso.Client{
		ID: multiCliB, Secret: multiSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		BackchannelLogoutURI:  multiBCBURI,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != multiPasswd {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: multiUser}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer()
	notifier := &captureNotifier{}
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithBackchannelLogout(issuer, notifier),
		// NO security.SubjectClientIndex wired.
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	tokA := loginAsMultiRP(t, httpSrv, multiCliA)
	_ = loginAsMultiRP(t, httpSrv, multiCliB)

	req, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/logout", bytes.NewReader([]byte("{}")))
	req.Header.Set("Authorization", "Bearer "+tokA)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	calls := notifier.snapshot()
	if len(calls) != 1 {
		t.Fatalf("expected 1 BCL notification (single-RP fallback); got %d: %+v", len(calls), calls)
	}
	if calls[0].URI != multiBCAURI {
		t.Errorf("URI=%q want %q (origin client only)", calls[0].URI, multiBCAURI)
	}
}

func TestSubjectClientIndex_RecordListForget(t *testing.T) {
	idx := defaultimpl.NewMemorySubjectClientIndex()
	ctx := context.Background()

	if err := idx.RecordAccess(ctx, "sub-x", "client-a"); err != nil {
		t.Fatalf("record a: %v", err)
	}
	if err := idx.RecordAccess(ctx, "sub-x", "client-b"); err != nil {
		t.Fatalf("record b: %v", err)
	}
	// Re-record is a no-op (set semantics).
	_ = idx.RecordAccess(ctx, "sub-x", "client-a")

	clients, err := idx.ListClients(ctx, "sub-x")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(clients) != 2 {
		t.Fatalf("expected 2 clients, got %d: %v", len(clients), clients)
	}

	if err := idx.Forget(ctx, "sub-x", "client-a"); err != nil {
		t.Fatalf("forget: %v", err)
	}
	clients, _ = idx.ListClients(ctx, "sub-x")
	if len(clients) != 1 || clients[0] != "client-b" {
		t.Errorf("post-forget list = %v, want [client-b]", clients)
	}

	// Forget on an unknown pair is a nil-op.
	if err := idx.Forget(ctx, "sub-x", "client-unknown"); err != nil {
		t.Errorf("forget on unknown pair returned %v", err)
	}
	// Empty subject / clientID short-circuit.
	if err := idx.RecordAccess(ctx, "", "client-a"); err != nil {
		t.Errorf("empty subject record: %v", err)
	}
	if c, _ := idx.ListClients(ctx, "unknown-sub"); c != nil {
		t.Errorf("unknown sub list = %v, want nil", c)
	}
}
