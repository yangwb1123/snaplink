package sso_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/netpolicy/memory"
)

// netHarness wires a Server with the netpolicy API enabled, a memory store,
// and an optional classifier. Returns the *httptest.Server URL prefix for
// the API endpoints.
type netHarness struct {
	srv        *httptest.Server
	store      netpolicy.Store
	classifier *netpolicy.Classifier
	sink       *audit.MemorySink
}

func newNetHarness(t *testing.T, withClassifier bool) *netHarness {
	t.Helper()
	store := memory.New()
	t.Cleanup(func() { store.Close() })

	var classifier *netpolicy.Classifier
	if withClassifier {
		classifier = netpolicy.NewClassifier()
		_ = classifier.Reload(context.Background(), store)
	}

	sink := audit.NewMemorySink(20)
	recorder := audit.New(sink)

	srv := sso.NewServer(
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithAuditRecorder(recorder),
		sso.WithNetworkPolicy(store, classifier),
		sso.WithNetworkPolicyAPI(),
	)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return &netHarness{srv: ts, store: store, classifier: classifier, sink: sink}
}

func (h *netHarness) do(t *testing.T, method, path, body string) (*http.Response, []byte) {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	var req *http.Request
	var err error
	if rdr != nil {
		req, err = http.NewRequest(method, h.srv.URL+path, rdr)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequest(method, h.srv.URL+path, nil)
	}
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return resp, buf[:n]
}

func TestNetPolicyHTTP_ApplyListGet(t *testing.T) {
	h := newNetHarness(t, false)
	body := `{"name":"intranet","cidrs":["10.0.0.0/8"],"priority":100,"advertised_jwks_url":"http://x/jwks"}`
	resp, _ := h.do(t, "POST", "/api/v1/netpolicy/policies", body)
	if resp.StatusCode != 200 {
		t.Fatalf("Apply status = %d", resp.StatusCode)
	}

	resp, payload := h.do(t, "GET", "/api/v1/netpolicy/policies", "")
	if resp.StatusCode != 200 {
		t.Fatalf("List status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(payload), "intranet") {
		t.Errorf("List missing 'intranet': %s", payload)
	}

	resp, payload = h.do(t, "GET", "/api/v1/netpolicy/policies/intranet", "")
	if resp.StatusCode != 200 {
		t.Fatalf("Get status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(payload), `"advertised_jwks_url":"http://x/jwks"`) {
		t.Errorf("Get payload missing advertised URL: %s", payload)
	}
}

func TestNetPolicyHTTP_GetUnknown(t *testing.T) {
	h := newNetHarness(t, false)
	resp, _ := h.do(t, "GET", "/api/v1/netpolicy/policies/ghost", "")
	if resp.StatusCode != 404 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestNetPolicyHTTP_ApplyMissingName(t *testing.T) {
	h := newNetHarness(t, false)
	resp, _ := h.do(t, "POST", "/api/v1/netpolicy/policies", `{}`)
	if resp.StatusCode != 400 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestNetPolicyHTTP_Delete(t *testing.T) {
	h := newNetHarness(t, false)
	h.do(t, "POST", "/api/v1/netpolicy/policies", `{"name":"x"}`)
	resp, _ := h.do(t, "DELETE", "/api/v1/netpolicy/policies/x", "")
	if resp.StatusCode != 200 {
		t.Fatalf("Delete status = %d", resp.StatusCode)
	}
	resp, _ = h.do(t, "GET", "/api/v1/netpolicy/policies/x", "")
	if resp.StatusCode != 404 {
		t.Fatalf("after delete Get status = %d", resp.StatusCode)
	}
}

func TestNetPolicyHTTP_MutationsAudited(t *testing.T) {
	h := newNetHarness(t, false)
	h.do(t, "POST", "/api/v1/netpolicy/policies", `{"name":"x"}`)
	h.do(t, "DELETE", "/api/v1/netpolicy/policies/x", "")
	if got := h.sink.Len(); got != 2 {
		t.Fatalf("expected 2 audit events, got %d", got)
	}
}

func TestNetPolicyHTTP_ClassifyWithClassifier(t *testing.T) {
	h := newNetHarness(t, true)
	// Seed a policy and reload classifier.
	_, _ = h.store.Apply(context.Background(), &netpolicy.Policy{
		Name: "intranet", CIDRs: []string{"10.0.0.0/8"},
	})
	_ = h.classifier.Reload(context.Background(), h.store)

	resp, payload := h.do(t, "GET", "/api/v1/netpolicy/classify?remote_addr=10.1.2.3", "")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("unmarshal: %v\nbody=%s", err, payload)
	}
	if got["class"] != "intranet" {
		t.Fatalf("class = %v, want intranet", got["class"])
	}
}

func TestNetPolicyHTTP_ClassifyWithoutClassifier_501(t *testing.T) {
	h := newNetHarness(t, false)
	resp, _ := h.do(t, "GET", "/api/v1/netpolicy/classify?remote_addr=1.2.3.4", "")
	if resp.StatusCode != 501 {
		t.Fatalf("status = %d, want 501", resp.StatusCode)
	}
}

func TestNetPolicyHTTP_ResolveMeUsesRequestHost(t *testing.T) {
	h := newNetHarness(t, true)
	_, _ = h.store.Apply(context.Background(), &netpolicy.Policy{
		Name: "public", Hostnames: []string{"sso.example.com"},
	})
	_ = h.classifier.Reload(context.Background(), h.store)

	req, _ := http.NewRequest("GET", h.srv.URL+"/api/v1/netpolicy/resolve-me", nil)
	req.Host = "sso.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got["class"] != "public" {
		t.Fatalf("class = %v", got["class"])
	}
}

func TestServer_ClassifyRequestHelper(t *testing.T) {
	store := memory.New()
	defer store.Close()
	_, _ = store.Apply(context.Background(), &netpolicy.Policy{
		Name: "intranet", CIDRs: []string{"10.0.0.0/8"},
	})
	classifier := netpolicy.NewClassifier()
	_ = classifier.Reload(context.Background(), store)

	srv := sso.NewServer(
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithNetworkPolicy(store, classifier),
	)

	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.5.5.5:1234"
	p := srv.ClassifyRequest(r)
	if p == nil || p.Name != "intranet" {
		t.Fatalf("ClassifyRequest = %+v", p)
	}
}

func TestServer_ClassifyRequestReturnsNilWithoutClassifier(t *testing.T) {
	srv := sso.NewServer(sso.WithRouter(sso.NewStdRouter()))
	r, _ := http.NewRequest("GET", "/", nil)
	if got := srv.ClassifyRequest(r); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}
