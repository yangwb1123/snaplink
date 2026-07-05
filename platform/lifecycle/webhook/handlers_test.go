package webhook_test

// HTTP-handler tests for the webhook admin subscription/dead-letter
// endpoints. External package (webhook_test) mirrors platform/netpolicy's
// handlers_test.go pattern: a small testDeps satisfies webhook.HandlerDeps
// backed entirely by a real Engine over the real Memory* stores + a real
// audit.Recorder over a MemorySink — no mocks.
//
// Param-bearing routes (:id on Delete/Replay) are driven through a real
// core.StdRouter so the param is extracted exactly as in production; the
// param-free routes use core.NewContext directly.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/lifecycle/webhook"
	"github.com/snaplink/sso/shared/core"
)

type testDeps struct {
	eng *webhook.Engine
	rec *audit.Recorder
}

func (d *testDeps) WebhookEngine() *webhook.Engine { return d.eng }
func (d *testDeps) Auditor() *audit.Recorder       { return d.rec }

var _ webhook.HandlerDeps = (*testDeps)(nil)

// nilEngineDeps exercises the not-configured guards.
type nilEngineDeps struct{}

func (nilEngineDeps) WebhookEngine() *webhook.Engine { return nil }
func (nilEngineDeps) Auditor() *audit.Recorder       { return nil }

func newTestDeps() (*testDeps, *audit.MemorySink) {
	sink := audit.NewMemorySink(64)
	eng := webhook.NewEngine(webhook.NewMemorySubscriptionStore(), webhook.NewMemoryDeadLetterStore(0))
	return &testDeps{eng: eng, rec: audit.New(sink)}, sink
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return m
}

// router builds a StdRouter wiring the param-bearing handlers against d so
// we get production param extraction for :id.
func router(d webhook.HandlerDeps) *core.StdRouter {
	r := core.NewStdRouter()
	r.DELETE("/subscriptions/:id", func(ctx core.HandlerContext) { webhook.HandleDeleteSubscription(d, ctx) })
	r.POST("/deadletters/:id/replay", func(ctx core.HandlerContext) { webhook.HandleReplayDeadLetter(d, ctx) })
	return r
}

func TestHandleListSubscriptions_EmptyAndPopulated(t *testing.T) {
	t.Parallel()
	d, _ := newTestDeps()

	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/subscriptions", nil))
	webhook.HandleListSubscriptions(d, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleListSubscriptions empty code=%d", rec.Code)
	}

	if _, err := d.eng.Subscriptions().Create(context.Background(), webhook.EventSubscription{
		URL: "https://example.com/hook", EventTypes: []audit.EventType{audit.EventLogin}, Secret: "s3cr3t",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rec = httptest.NewRecorder()
	ctx = core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/subscriptions", nil))
	webhook.HandleListSubscriptions(d, ctx)
	body := decode(t, rec)
	subs, ok := body[core.KeyWebhookSubscriptions].([]any)
	if !ok || len(subs) != 1 {
		t.Fatalf("HandleListSubscriptions body = %v", body)
	}
	view, ok := subs[0].(map[string]any)
	if !ok {
		t.Fatalf("subscription view = %v", subs[0])
	}
	if _, leaked := view["Secret"]; leaked {
		t.Fatal("subscription view MUST NOT expose the raw secret")
	}
	if hasSecret, _ := view["has_secret"].(bool); !hasSecret {
		t.Errorf("expected has_secret=true, got %v", view["has_secret"])
	}
}

func TestHandleListSubscriptions_NilEngine(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/subscriptions", nil))
	webhook.HandleListSubscriptions(nilEngineDeps{}, ctx)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("nil-engine code=%d, want 500", rec.Code)
	}
	if decode(t, rec)[core.KeyError] != core.ErrWebhookNotConfigured {
		t.Fatalf("nil-engine wrong error: %v", rec.Body.String())
	}
}

func TestHandleCreateSubscription_ValidAudits(t *testing.T) {
	t.Parallel()
	d, sink := newTestDeps()

	body, _ := json.Marshal(map[string]any{
		"url":         "https://example.com/hook",
		"event_types": []string{string(audit.EventLogin)},
		"secret":      "s3cr3t",
	})
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodPost, "/subscriptions", bytes.NewReader(body)))
	webhook.HandleCreateSubscription(d, ctx)
	if rec.Code != http.StatusCreated {
		t.Fatalf("HandleCreateSubscription code=%d body=%s", rec.Code, rec.Body.String())
	}
	resp := decode(t, rec)
	view, ok := resp[core.KeyWebhookSubscription].(map[string]any)
	if !ok || view["id"] == "" {
		t.Fatalf("HandleCreateSubscription body = %v", resp)
	}
	if sink.Len() != 1 {
		t.Fatalf("audit events = %d, want 1", sink.Len())
	}
}

func TestHandleCreateSubscription_InvalidRejected(t *testing.T) {
	t.Parallel()
	d, _ := newTestDeps()
	// Missing secret.
	body, _ := json.Marshal(map[string]any{
		"url":         "https://example.com/hook",
		"event_types": []string{string(audit.EventLogin)},
	})
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodPost, "/subscriptions", bytes.NewReader(body)))
	webhook.HandleCreateSubscription(d, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("HandleCreateSubscription invalid code=%d, want 400", rec.Code)
	}
	if decode(t, rec)[core.KeyError] != core.ErrInvalidRequest {
		t.Fatalf("HandleCreateSubscription invalid wrong error: %v", rec.Body.String())
	}
}

func TestHandleCreateSubscription_BadJSON(t *testing.T) {
	t.Parallel()
	d, _ := newTestDeps()
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodPost, "/subscriptions", bytes.NewReader([]byte("{not json"))))
	webhook.HandleCreateSubscription(d, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("HandleCreateSubscription bad JSON code=%d, want 400", rec.Code)
	}
}

func TestHandleDeleteSubscription(t *testing.T) {
	t.Parallel()
	d, _ := newTestDeps()
	created, err := d.eng.Subscriptions().Create(context.Background(), webhook.EventSubscription{
		URL: "https://example.com/hook", EventTypes: []audit.EventType{audit.EventLogin}, Secret: "s3cr3t",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := httptest.NewRecorder()
	router(d).ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/subscriptions/"+created.ID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleDeleteSubscription code=%d", rec.Code)
	}
	if _, err := d.eng.Subscriptions().Get(context.Background(), created.ID); err == nil {
		t.Fatal("subscription should have been deleted")
	}
}

func TestHandleDeleteSubscription_EmptyID(t *testing.T) {
	t.Parallel()
	d, _ := newTestDeps()
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodDelete, "/subscriptions/", nil))
	webhook.HandleDeleteSubscription(d, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("HandleDeleteSubscription empty id code=%d, want 400", rec.Code)
	}
}

func TestHandleListDeadLetters_FilterBySubscription(t *testing.T) {
	t.Parallel()
	d, _ := newTestDeps()
	ctx := context.Background()
	if _, err := d.eng.DeadLetters().Add(ctx, webhook.DeadLetterEntry{SubscriptionID: "sub-a"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := d.eng.DeadLetters().Add(ctx, webhook.DeadLetterEntry{SubscriptionID: "sub-b"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := httptest.NewRecorder()
	hctx := core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/deadletters?subscription_id=sub-a", nil))
	webhook.HandleListDeadLetters(d, hctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleListDeadLetters code=%d", rec.Code)
	}
	body := decode(t, rec)
	entries, ok := body[core.KeyWebhookDeadLetters].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("HandleListDeadLetters body = %v", body)
	}
}

func TestHandleReplayDeadLetter_UnknownID(t *testing.T) {
	t.Parallel()
	d, _ := newTestDeps()
	rec := httptest.NewRecorder()
	router(d).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/deadletters/nope/replay", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("HandleReplayDeadLetter unknown id code=%d, want 404", rec.Code)
	}
	if decode(t, rec)[core.KeyError] != core.ErrWebhookDeadLetterNotFound {
		t.Fatalf("HandleReplayDeadLetter wrong error: %v", rec.Body.String())
	}
}
