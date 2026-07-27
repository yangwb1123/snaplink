package agentidentity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// stubTokenIssuer is a minimal, real (not expectation-based) core.TokenIssuer
// used only because this package's production code (interfaces/sso's
// WithAgentDelegationGrant) imports this package, and every real SDK
// issuer (infrastructure/defaultimpl) imports interfaces/sso in turn —
// using one here would be an import cycle, not a layering choice. It does
// genuine, deterministic work (mints a distinct token per Issue call,
// round-trips through Validate) rather than programmed expectations, so
// TestHandleGrant_Success can assert on the ACTUAL claims a mint produced.
type stubTokenIssuer struct {
	mu     sync.Mutex
	tokens map[string]*core.TokenClaims
	next   int
}

func newStubTokenIssuer() *stubTokenIssuer {
	return &stubTokenIssuer{tokens: make(map[string]*core.TokenClaims)}
}

func (s *stubTokenIssuer) Issue(_ context.Context, subject *core.Subject, scopes []string) (*core.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	tok := fmt.Sprintf("stub-token-%d", s.next)
	s.tokens[tok] = &core.TokenClaims{
		Subject:  subject.ID,
		ClientID: subject.ClientID,
		Scopes:   append([]string(nil), scopes...),
		Actor:    subject.Actor,
	}
	return &core.Token{
		AccessToken: tok,
		TokenType:   core.TokenTypeNameBearer,
		ExpiresIn:   3600,
		Scope:       strings.Join(scopes, " "),
		CreatedAt:   time.Now(),
	}, nil
}

func (s *stubTokenIssuer) Validate(_ context.Context, token string) (*core.TokenClaims, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	claims, ok := s.tokens[token]
	if !ok {
		return nil, errors.New("stub: unknown token")
	}
	return claims, nil
}

func (s *stubTokenIssuer) Revoke(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
	return nil
}

var _ core.TokenIssuer = (*stubTokenIssuer)(nil)

// testDeps is a real, deterministic Deps implementation for tests — not a
// mock-framework expectation double: every method does the SAME real work
// production wiring does (a real audit.Recorder + MemorySink records real
// events; stubTokenIssuer above genuinely mints + validates), just
// assembled directly instead of through interfaces/sso's WithAgentDelegationGrant.
type testDeps struct {
	agents      AgentProvider
	sessions    AgentSessionStore
	humanScopes func(ctx context.Context, sub string) ([]string, error)
	issuer      core.TokenIssuer
	auditor     *audit.Recorder
}

func (d *testDeps) Agents() AgentProvider       { return d.agents }
func (d *testDeps) Sessions() AgentSessionStore { return d.sessions }

func (d *testDeps) HumanScopes(ctx context.Context, sub string) ([]string, error) {
	return d.humanScopes(ctx, sub)
}

func (d *testDeps) IssuerForClient(c *core.Client) (string, core.TokenIssuer, error) {
	return "jwt", d.issuer, nil
}

func (d *testDeps) DPoPTokenTypeOr(defaultType, _ string) string { return defaultType }

func (d *testDeps) RecordTokenIssued(_ core.HandlerContext, _, _, _ string) {}

func (d *testDeps) Auditor() *audit.Recorder { return d.auditor }

func (d *testDeps) SrvLogger() spi.Logger { return spi.NopLogger{} }

var _ Deps = (*testDeps)(nil)

// grantHarness bundles a fresh, real-implementation Deps + the sink to
// inspect audited events.
type grantHarness struct {
	deps  *testDeps
	sink  *audit.MemorySink
	agent *Agent
	sess  *AgentSession
}

func newGrantHarness(t *testing.T) *grantHarness {
	t.Helper()
	agents := NewMemoryAgentProvider()
	sessions := NewMemoryAgentSessionStore()
	sink := audit.NewMemorySink(16)
	rec := audit.New(sink)

	agent := &Agent{ID: "agent-1", DisplayName: "Support Bot", AllowedScopes: []string{"tickets:read", "tickets:write"}}
	if err := agents.Register(context.Background(), agent); err != nil {
		t.Fatalf("Register agent: %v", err)
	}
	sess := &AgentSession{
		ID:            "sess-1",
		HumanSubject:  "alice",
		AgentID:       "agent-1",
		GrantedScopes: []string{"tickets:read", "tickets:write"},
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	if err := sessions.Create(context.Background(), sess); err != nil {
		t.Fatalf("Create session: %v", err)
	}

	return &grantHarness{
		deps: &testDeps{
			agents:   agents,
			sessions: sessions,
			humanScopes: func(context.Context, string) ([]string, error) {
				return []string{"tickets:read", "tickets:write", "profile:read"}, nil
			},
			issuer:  newStubTokenIssuer(),
			auditor: rec,
		},
		sink:  sink,
		agent: agent,
		sess:  sess,
	}
}

func doGrant(h *grantHarness, req Request) (int, map[string]any) {
	httpReq := httptest.NewRequest(http.MethodPost, "http://sso.example.com/token", nil)
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httpReq)
	client := &core.Client{ID: "agent-app"}

	HandleGrant(h.deps, ctx, client, req, "", "")

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func TestHandleGrant_MissingSessionID(t *testing.T) {
	t.Parallel()
	h := newGrantHarness(t)
	code, body := doGrant(h, Request{})
	if code != http.StatusBadRequest || body["error"] != core.ErrInvalidRequest {
		t.Fatalf("got (%d, %v), want (400, invalid_request)", code, body)
	}
}

func TestHandleGrant_UnknownSession(t *testing.T) {
	t.Parallel()
	h := newGrantHarness(t)
	code, body := doGrant(h, Request{AgentSessionID: "does-not-exist"})
	if code != http.StatusBadRequest || body["error"] != core.ErrInvalidGrant {
		t.Fatalf("got (%d, %v), want (400, invalid_grant)", code, body)
	}
}

func TestHandleGrant_RevokedSession(t *testing.T) {
	t.Parallel()
	h := newGrantHarness(t)
	if err := h.deps.sessions.Revoke(context.Background(), h.sess.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	code, body := doGrant(h, Request{AgentSessionID: h.sess.ID})
	if code != http.StatusBadRequest || body["error"] != core.ErrInvalidGrant {
		t.Fatalf("got (%d, %v), want (400, invalid_grant) for a revoked session", code, body)
	}
}

func TestHandleGrant_ExpiredSession(t *testing.T) {
	t.Parallel()
	h := newGrantHarness(t)
	expired := &AgentSession{
		ID: "sess-expired", HumanSubject: "alice", AgentID: "agent-1",
		GrantedScopes: []string{"tickets:read"}, ExpiresAt: time.Now().Add(-time.Minute),
	}
	if err := h.deps.sessions.Create(context.Background(), expired); err != nil {
		t.Fatalf("Create: %v", err)
	}
	code, body := doGrant(h, Request{AgentSessionID: "sess-expired"})
	if code != http.StatusBadRequest || body["error"] != core.ErrInvalidGrant {
		t.Fatalf("got (%d, %v), want (400, invalid_grant) for an expired session", code, body)
	}
}

func TestHandleGrant_UnknownAgent(t *testing.T) {
	t.Parallel()
	h := newGrantHarness(t)
	orphan := &AgentSession{
		ID: "sess-orphan", HumanSubject: "alice", AgentID: "no-such-agent",
		GrantedScopes: []string{"tickets:read"}, ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := h.deps.sessions.Create(context.Background(), orphan); err != nil {
		t.Fatalf("Create: %v", err)
	}
	code, body := doGrant(h, Request{AgentSessionID: "sess-orphan"})
	if code != http.StatusBadRequest || body["error"] != core.ErrInvalidGrant {
		t.Fatalf("got (%d, %v), want (400, invalid_grant) for an unknown agent", code, body)
	}
}

func TestHandleGrant_HumanEntitlementResolutionErrorDenies(t *testing.T) {
	t.Parallel()
	h := newGrantHarness(t)
	h.deps.humanScopes = func(context.Context, string) ([]string, error) {
		return nil, errors.New("entitlement store unavailable")
	}
	code, body := doGrant(h, Request{AgentSessionID: h.sess.ID})
	if code != http.StatusBadRequest || body["error"] != core.ErrInvalidGrant {
		t.Fatalf("got (%d, %v), want (400, invalid_grant) fail-closed on entitlement error", code, body)
	}
}

func TestHandleGrant_NeverWidensPastShrunkHumanEntitlement(t *testing.T) {
	t.Parallel()
	h := newGrantHarness(t)
	// The human's live entitlement has shrunk to NOTHING the session/agent
	// allow — e.g. a role change since the session was created.
	h.deps.humanScopes = func(context.Context, string) ([]string, error) {
		return []string{"profile:read"}, nil
	}
	code, body := doGrant(h, Request{AgentSessionID: h.sess.ID})
	if code != http.StatusBadRequest || body["error"] != core.ErrInvalidScope {
		t.Fatalf("got (%d, %v), want (400, invalid_scope) when the live intersection is empty", code, body)
	}
}

func TestHandleGrant_RequestedScopeOutsideIntersectionRejected(t *testing.T) {
	t.Parallel()
	h := newGrantHarness(t)
	code, body := doGrant(h, Request{AgentSessionID: h.sess.ID, Scope: "tickets:read admin:everything"})
	if code != http.StatusBadRequest || body["error"] != core.ErrInvalidScope {
		t.Fatalf("got (%d, %v), want (400, invalid_scope) for an over-reaching scope request", code, body)
	}
}

func TestHandleGrant_Success(t *testing.T) {
	t.Parallel()
	h := newGrantHarness(t)
	code, body := doGrant(h, Request{AgentSessionID: h.sess.ID})
	if code != http.StatusOK {
		t.Fatalf("got %d, body %v, want 200", code, body)
	}
	if body[core.KeyAccessToken] == "" || body[core.KeyAccessToken] == nil {
		t.Fatalf("missing access_token in response: %v", body)
	}
	if body[core.KeyScope] != "tickets:read tickets:write" {
		t.Fatalf("scope = %v, want the full granted intersection", body[core.KeyScope])
	}

	// Validate the minted token carries sub=agent + act=human.
	claims, err := h.deps.issuer.Validate(context.Background(), body[core.KeyAccessToken].(string))
	if err != nil {
		t.Fatalf("Validate minted token: %v", err)
	}
	if claims.Subject != "agent-1" {
		t.Fatalf("sub = %q, want the agent's identity", claims.Subject)
	}
	if claims.Actor == nil || claims.Actor.Subject != "alice" {
		t.Fatalf("act claim = %+v, want {sub: alice}", claims.Actor)
	}

	// Mint must be audited (SetMeta, never a raw map literal — verified by
	// the event actually carrying the expected metadata).
	events, err := h.sink.Query(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d audited events, want 1", len(events))
	}
	evt := events[0]
	if evt.Type != audit.EventAgentDelegationTokenIssued {
		t.Fatalf("event type = %v, want EventAgentDelegationTokenIssued", evt.Type)
	}
	if evt.Metadata[core.KeyOriginalSubject] != "alice" {
		t.Fatalf("event meta[original_subject] = %v, want alice", evt.Metadata[core.KeyOriginalSubject])
	}
	if evt.Metadata[MetaAgentSessionID] != "sess-1" {
		t.Fatalf("event meta[agent_session_id] = %v, want sess-1", evt.Metadata[MetaAgentSessionID])
	}
}

func TestHandleGrant_RequestedScopeNarrowsWithinIntersection(t *testing.T) {
	t.Parallel()
	h := newGrantHarness(t)
	code, body := doGrant(h, Request{AgentSessionID: h.sess.ID, Scope: "tickets:read"})
	if code != http.StatusOK {
		t.Fatalf("got %d, body %v, want 200", code, body)
	}
	if body[core.KeyScope] != "tickets:read" {
		t.Fatalf("scope = %v, want the caller-narrowed subset", body[core.KeyScope])
	}
}
