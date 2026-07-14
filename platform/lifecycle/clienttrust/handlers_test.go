package clienttrust_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/platform/lifecycle/clienttrust"
	"github.com/snaplink/sso/shared/core"
)

type testHandlerDeps struct{ store core.ClientStore }

func (d testHandlerDeps) ClientStore() core.ClientStore { return d.store }

var _ clienttrust.HandlerDeps = testHandlerDeps{}

func newRouter(d clienttrust.HandlerDeps) *core.StdRouter {
	r := core.NewStdRouter()
	r.GET("/clients/:id/trust-score", func(ctx core.HandlerContext) {
		clienttrust.HandleGetClientTrustScore(d, ctx)
	})
	return r
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return m
}

func TestHandleGetClientTrustScore_NeverScoredReturnsColdStart(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	if err := store.Add(context.Background(), &core.Client{ID: "c1", Active: true}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	router := newRouter(testHandlerDeps{store: store})

	req := httptest.NewRequest(http.MethodGet, "/clients/c1/trust-score", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["scored"] != false {
		t.Errorf("scored = %v, want false", body["scored"])
	}
	if body["cold_start_default"] != true {
		t.Errorf("cold_start_default = %v, want true", body["cold_start_default"])
	}
	if got, want := body["trust_score"].(float64), clienttrust.ColdStartScore; got != want {
		t.Errorf("trust_score = %v, want %v", got, want)
	}
}

func TestHandleGetClientTrustScore_ScoredClient(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	now := time.Now()
	client := &core.Client{ID: "c2", Active: true}
	if err := store.Add(context.Background(), client); err != nil {
		t.Fatalf("Add: %v", err)
	}
	client.ClientTrustScore = 0.42
	client.ClientTrustSetAt = now
	if err := store.Update(context.Background(), client); err != nil {
		t.Fatalf("Update: %v", err)
	}
	router := newRouter(testHandlerDeps{store: store})

	req := httptest.NewRequest(http.MethodGet, "/clients/c2/trust-score", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["scored"] != true {
		t.Errorf("scored = %v, want true", body["scored"])
	}
	if got := body["trust_score"].(float64); got != 0.42 {
		t.Errorf("trust_score = %v, want 0.42", got)
	}
	if body["trust_set_at"] == nil || body["trust_set_at"] == "" {
		t.Error("trust_set_at must be populated for a scored client")
	}
}

func TestHandleGetClientTrustScore_UnknownClientIs404(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	router := newRouter(testHandlerDeps{store: store})

	req := httptest.NewRequest(http.MethodGet, "/clients/ghost/trust-score", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}
