package sso_test

// RiskScorer SPI integration — verifies the hook in handleLogin
// respects scorer decisions (Allow / Deny / RequireMFA-treated-as-Allow)
// AND that scorer errors fail OPEN (login proceeds, log the error).
//
// Reuses the e2e_test.go buildE2E pattern of a real httptest server with
// memory backends + a password verifier, then layers a controllable
// stub scorer on top via sso.WithRiskScorer.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/permissions"
)

// stubScorer is a controllable RiskScorer for tests. Decision and
// returnErr are pulled atomically so tests can flip behavior mid-run
// without locks; calls is the recording counter.
type stubScorer struct {
	decision  atomic.Value // sso.Decision
	returnErr atomic.Value // error
	calls     atomic.Int32
}

func newStubScorer(d sso.Decision) *stubScorer {
	s := &stubScorer{}
	s.decision.Store(d)
	return s
}

func (s *stubScorer) Score(_ context.Context, _ *sso.RiskRequest) (*sso.RiskAssessment, error) {
	s.calls.Add(1)
	if e, ok := s.returnErr.Load().(error); ok && e != nil {
		return nil, e
	}
	d, _ := s.decision.Load().(sso.Decision)
	return &sso.RiskAssessment{Decision: d}, nil
}

// buildRiskHarness is a focused mirror of e2e_test.go's buildE2E
// — minimal server, one user, one client, no gRPC backend. Optionally
// wires a RiskScorer when scorer != nil.
func buildRiskHarness(t *testing.T, scorer sso.RiskScorer) (*httptest.Server, *audit.MemorySink) {
	t.Helper()

	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("risk-test"))
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "alice"})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    "risk-app",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
		Active:                true,
	})

	pwAuth := authenticators.NewPasswordAuthenticator(
		authenticators.PasswordVerifierFunc(func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == "alice" && p == "s3cret" {
				return &sso.AuthResult{UserID: "alice"}, nil
			}
			return nil, errors.New("bad creds")
		}),
	)

	prov := permissions.NewMemoryProvider()
	sink := audit.NewMemorySink(50)
	recorder := audit.New(sink)

	opts := []sso.Option{
		sso.WithIssuer("risk-test"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(sessions),
		sso.WithAuthenticator(pwAuth),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPermissionProvider(prov),
		sso.WithAuditRecorder(recorder),
	}
	if scorer != nil {
		opts = append(opts, sso.WithRiskScorer(scorer))
	}

	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, sink
}

func loginRisk(t *testing.T, srv *httptest.Server) *http.Response {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  "risk-app",
		"credential": map[string]string{"username": "alice", "password": "s3cret"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /auth/login: %v", err)
	}
	return resp
}

func TestRiskScorer_NoScorer_ZeroOverhead(t *testing.T) {
	// Server constructed without WithRiskScorer — login succeeds via
	// the normal path (sanity that the nil-check in handleLogin
	// doesn't break the happy path).
	srv, _ := buildRiskHarness(t, nil)
	resp := loginRisk(t, srv)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("login = %d body=%s", resp.StatusCode, raw)
	}
}

func TestRiskScorer_Allow_LoginProceeds(t *testing.T) {
	stub := newStubScorer(sso.DecisionAllow)
	srv, _ := buildRiskHarness(t, stub)
	resp := loginRisk(t, srv)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Allow path returned %d, want 200", resp.StatusCode)
	}
	if stub.calls.Load() != 1 {
		t.Errorf("scorer calls = %d, want 1", stub.calls.Load())
	}
}

func TestRiskScorer_Deny_Returns403_AndEmitsFailureEvent(t *testing.T) {
	stub := newStubScorer(sso.DecisionDeny)
	srv, sink := buildRiskHarness(t, stub)
	resp := loginRisk(t, srv)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("Deny path returned %d, want 403 body=%s", resp.StatusCode, raw)
	}

	// Body carries the stable error code so SPAs can branch on it.
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "risk_denied" {
		t.Errorf("error code = %q, want risk_denied", body["error"])
	}

	// Audit event recorded with reason=risk_denied; outcome=failure.
	events, _ := sink.Query(context.Background(), audit.Query{
		Type:    audit.EventLoginFailure,
		Outcome: audit.OutcomeFailure,
	})
	if len(events) == 0 {
		t.Fatal("expected login_failure event in audit sink, got none")
	}
	found := false
	for _, e := range events {
		if e.Reason == "risk_denied" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no event with reason=risk_denied: %+v", events)
	}
}

func TestRiskScorer_ScorerError_FailsOpen(t *testing.T) {
	// Contract: a scorer that errors must NOT block login.
	stub := newStubScorer(sso.DecisionDeny) // would deny if it ran clean
	stub.returnErr.Store(errors.New("scorer offline"))
	srv, _ := buildRiskHarness(t, stub)

	resp := loginRisk(t, srv)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("scorer-error path returned %d, want 200 (fail-open contract) body=%s", resp.StatusCode, raw)
	}
}

func TestRiskScorer_RequireMFA_TreatedAsAllow_v1(t *testing.T) {
	// Forward-compat: RequireMFA is documented in risk.go as
	// reserved-for-future. Today the server treats it as Allow so a
	// scorer can emit it without breaking flows before MFA
	// orchestration lands.
	stub := newStubScorer(sso.DecisionRequireMFA)
	srv, _ := buildRiskHarness(t, stub)

	resp := loginRisk(t, srv)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("RequireMFA returned %d, want 200 (treated as Allow in v1)", resp.StatusCode)
	}
}

// Compile-time guard: stubScorer satisfies sso.RiskScorer.
var _ sso.RiskScorer = (*stubScorer)(nil)

// Used to keep `time` import for the (possible) future direct timestamp assertion.
var _ = time.Now
