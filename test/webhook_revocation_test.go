package ssotest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/lifecycle/webhook"
)

// This suite is the FULL-SERVER proof that RFC 7009 /token/revoke now closes
// the AS-to-RS active-revocation-push gap via the ALREADY-BUILT, generic
// platform/lifecycle/webhook.Engine (admin CRUD, retry, dead-letter — see
// that package's doc.go) rather than a new parallel mechanism: before
// audit.RecordTokenRevoked existed (see interfaces/sso.Server.
// notifyTokenRevoked), EventTokenRevoked was a declared, CEF/OCSF-mapped
// audit event type that NOTHING ever recorded on a successful revoke, so an
// operator-registered webhook subscription for it could never fire. Mirrors
// test/caep_integration_test.go's shape (that suite is CAEP's full-server
// audit-pipeline-wiring proof; this is the generic-webhook-engine sibling).

const (
	webhookRevokeClientID     = "webhook-revoke-client"
	webhookRevokeClientSecret = "webhook-revoke-secret"
)

// webhookRevokeReceiver records every event body an httptest webhook
// receiver was POSTed.
type webhookRevokeReceiver struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *webhookRevokeReceiver) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		var e audit.Event
		_ = json.NewDecoder(req.Body).Decode(&e)
		r.mu.Lock()
		r.events = append(r.events, e)
		r.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}
}

func (r *webhookRevokeReceiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

func (r *webhookRevokeReceiver) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.events...)
}

// webhookWaitFor polls cond until true or a 3s deadline, failing on timeout —
// delivery runs in a background goroutine (Engine.Record never blocks the
// caller), so tests observe its effect asynchronously.
func webhookWaitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

// newWebhookRevokeServer wires a real *sso.Server with a seeded client, a
// real Ed25519 issuer, a real audit Recorder, and eng as the webhook egress
// engine — returning the server, the issuer (to mint tokens), and an
// httptest wrapper to drive real HTTP requests against it.
func newWebhookRevokeServer(t *testing.T, eng *webhook.Engine, sink *audit.MemorySink) (*httptest.Server, *defaultimpl.Ed25519JWTIssuer) {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: webhookRevokeClientID, Secret: webhookRevokeClientSecret,
		Active: true, TokenStrategy: "jwt",
	})
	jwtIssuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Hour))
	rec := audit.New(sink)

	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", jwtIssuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
		sso.WithAuditRecorder(rec),
		sso.WithWebhookEngine(eng),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, jwtIssuer
}

// postRevokeWebhook drives a real RFC 7009 /token/revoke request and returns
// the full response (status + body) so callers can assert wire-shape
// invariants. Named distinctly from handle_introspect_test.go's postRevoke
// (same package, different signature) to avoid a redeclaration.
func postRevokeWebhook(t *testing.T, baseURL, token string) (int, string) {
	t.Helper()
	form := "token=" + token + "&client_id=" + webhookRevokeClientID + "&client_secret=" + webhookRevokeClientSecret
	resp, err := http.Post(baseURL+"/token/revoke", "application/x-www-form-urlencoded", strings.NewReader(form))
	if err != nil {
		t.Fatalf("post /token/revoke: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(body)
}

// TestWebhookEngine_TokenRevoke_DeliversTokenRevokedEvent proves the actual
// gap closure: a real /token/revoke, authenticated with real client
// credentials against a real token, causes the operator-registered webhook
// subscription for audit.EventTokenRevoked to receive EXACTLY ONE delivery
// carrying the client + subject that were revoked.
func TestWebhookEngine_TokenRevoke_DeliversTokenRevokedEvent(t *testing.T) {
	t.Parallel()
	recv := &webhookRevokeReceiver{}
	recvSrv := httptest.NewTLSServer(recv.handler())
	defer recvSrv.Close()

	subs := webhook.NewMemorySubscriptionStore()
	ctx := context.Background()
	if _, err := subs.Create(ctx, webhook.EventSubscription{
		URL: recvSrv.URL, EventTypes: []audit.EventType{audit.EventTokenRevoked}, Secret: "s3cr3t",
	}); err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	eng := webhook.NewEngine(subs, webhook.NewMemoryDeadLetterStore(0), webhook.WithHTTPClient(recvSrv.Client()))
	defer func() { _ = eng.Close(context.Background()) }()

	sink := audit.NewMemorySink(64)
	httpSrv, jwtIssuer := newWebhookRevokeServer(t, eng, sink)

	tok, err := jwtIssuer.Issue(ctx, &sso.Subject{ID: "user-revoked-1", ClientID: webhookRevokeClientID}, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	status, body := postRevokeWebhook(t, httpSrv.URL, tok.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if strings.TrimSpace(body) != "{}" {
		t.Errorf("body = %q, want RFC 7009's empty JSON object", body)
	}

	webhookWaitFor(t, func() bool { return recv.count() == 1 }, "webhook receives the token_revoked delivery")
	got := recv.snapshot()[0]
	if got.Type != audit.EventTokenRevoked {
		t.Errorf("Type = %q, want %q", got.Type, audit.EventTokenRevoked)
	}
	if got.ClientID != webhookRevokeClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, webhookRevokeClientID)
	}
	if got.ActorID != "user-revoked-1" {
		t.Errorf("ActorID = %q, want %q", got.ActorID, "user-revoked-1")
	}
	if got := recv.count(); got != 1 {
		t.Fatalf("want exactly 1 delivery, got %d", got)
	}
}

// TestWebhookEngine_TokenRevoke_UnknownTokenDeliversNothing proves the
// oracle-safety guardrail extends to the new emission: RFC 7009 §2.2
// requires an unknown/already-revoked token to look IDENTICAL to a
// successful revoke on the wire (200, empty body) — but it must NOT fire a
// token_revoked webhook, since nothing was actually revoked.
func TestWebhookEngine_TokenRevoke_UnknownTokenDeliversNothing(t *testing.T) {
	t.Parallel()
	recv := &webhookRevokeReceiver{}
	recvSrv := httptest.NewTLSServer(recv.handler())
	defer recvSrv.Close()

	subs := webhook.NewMemorySubscriptionStore()
	ctx := context.Background()
	if _, err := subs.Create(ctx, webhook.EventSubscription{
		URL: recvSrv.URL, EventTypes: []audit.EventType{audit.EventTokenRevoked}, Secret: "s3cr3t",
	}); err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	eng := webhook.NewEngine(subs, webhook.NewMemoryDeadLetterStore(0), webhook.WithHTTPClient(recvSrv.Client()))
	defer func() { _ = eng.Close(context.Background()) }()

	sink := audit.NewMemorySink(64)
	httpSrv, _ := newWebhookRevokeServer(t, eng, sink)

	status, body := postRevokeWebhook(t, httpSrv.URL, "not-a-real-token")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (RFC 7009 §2.2: unknown token must not be distinguishable)", status)
	}
	if strings.TrimSpace(body) != "{}" {
		t.Errorf("body = %q, want the SAME empty JSON object a successful revoke returns", body)
	}
	// Give any (incorrectly-spawned) delivery a moment to land before
	// asserting silence.
	time.Sleep(50 * time.Millisecond)
	if got := recv.count(); got != 0 {
		t.Errorf("unknown token must never trigger a token_revoked webhook, got %d deliveries", got)
	}
}

// TestWebhookEngine_TokenRevoke_FailOpen_HungSubscriber proves the fail-open
// contract this task's background section requires: a webhook subscriber
// that never responds must NEVER slow down or block the /token/revoke
// response. Engine.Record only ever spawns a goroutine and returns
// immediately (see engine.go), so the revoke response must land in well
// under the receiver's (infinite) response time.
func TestWebhookEngine_TokenRevoke_FailOpen_HungSubscriber(t *testing.T) {
	t.Parallel()
	block := make(chan struct{})
	recvSrv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-block // deliberately never responds within the test's lifetime
	}))

	subs := webhook.NewMemorySubscriptionStore()
	ctx := context.Background()
	if _, err := subs.Create(ctx, webhook.EventSubscription{
		URL: recvSrv.URL, EventTypes: []audit.EventType{audit.EventTokenRevoked}, Secret: "s3cr3t",
	}); err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	eng := webhook.NewEngine(subs, webhook.NewMemoryDeadLetterStore(0), webhook.WithHTTPClient(recvSrv.Client()))
	t.Cleanup(func() {
		// eng.Close cancels its delivery context, aborting the in-flight POST
		// client-side immediately (proven by
		// TestEngine_Close_AbortsInFlightDeliveryPromptly in the webhook
		// package) — it does NOT depend on the server ever responding.
		_ = eng.Close(context.Background())
		close(block)
		recvSrv.Close()
	})

	sink := audit.NewMemorySink(64)
	httpSrv, jwtIssuer := newWebhookRevokeServer(t, eng, sink)

	tok, err := jwtIssuer.Issue(ctx, &sso.Subject{ID: "user-fail-open", ClientID: webhookRevokeClientID}, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	start := time.Now()
	status, _ := postRevokeWebhook(t, httpSrv.URL, tok.AccessToken)
	elapsed := time.Since(start)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 even though the webhook subscriber is hung", status)
	}
	if elapsed > time.Second {
		t.Fatalf("/token/revoke took %s — a hung webhook subscriber must never block the revoke response (fail-open)", elapsed)
	}
}
