package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/snaplink/sso/interfaces/sso"
)

func okNext() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func gateConfig() *Config {
	return &Config{ResourceURI: "https://mcp/", RequiredScope: "mcp:read", Issuer: "https://sso"}
}

func TestRSGate_AllowsValidToken(t *testing.T) {
	iss := edIssuer()
	gate := newRSGate(jwksAuthClient(t, iss), gateConfig(), okNext())
	tok, _ := iss.Issue(context.Background(), &sso.Subject{ID: "agent-1", Resources: []string{"https://mcp/"}}, []string{"mcp:read"})

	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	w := httptest.NewRecorder()
	gate.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("valid token: code = %d, want 200", w.Code)
	}
}

func TestRSGate_RejectsMissingWrongAudWrongScope(t *testing.T) {
	iss := edIssuer()
	cfg := gateConfig()
	gate := newRSGate(jwksAuthClient(t, iss), cfg, okNext())

	// missing token
	w := httptest.NewRecorder()
	gate.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Header().Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("missing: code=%d hdr=%q", w.Code, w.Header().Get("WWW-Authenticate"))
	}

	// wrong aud
	bad, _ := iss.Issue(context.Background(), &sso.Subject{ID: "a", Resources: []string{"https://other/"}}, []string{"mcp:read"})
	w = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+bad.AccessToken)
	gate.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong aud: code=%d, want 401", w.Code)
	}

	// insufficient scope
	noscope, _ := iss.Issue(context.Background(), &sso.Subject{ID: "a", Resources: []string{"https://mcp/"}}, []string{"other"})
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+noscope.AccessToken)
	gate.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no scope: code=%d, want 401", w.Code)
	}
}

func TestPRMHandler(t *testing.T) {
	w := httptest.NewRecorder()
	prmHandler(gateConfig())(w, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil))
	body := w.Body.String()
	if !strings.Contains(body, `"https://sso"`) || !strings.Contains(body, `"https://mcp/"`) {
		t.Fatalf("PRM body missing fields: %s", body)
	}
}

func TestLivez(t *testing.T) {
	w := httptest.NewRecorder()
	livezHandler()(w, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "alive") {
		t.Fatalf("livez: code=%d body=%s", w.Code, w.Body.String())
	}
}

// TestBuildHTTPHandler_Wiring proves the production handler mounts an OPEN
// /livez and a GATED /mcp (401 without a token). conn is nil here because
// /readyz is not exercised.
func TestBuildHTTPHandler_Wiring(t *testing.T) {
	cfg := gateConfig()
	cfg.JWKSURL = "https://sso/jwks"
	sc := &snaplinkClient{auth: jwksAuthClient(t, edIssuer()), authz: bufconnAuthz(t)}
	srv := newMCPServer(&toolDeps{intro: sc.auth, authz: sc.authz})
	h := buildHTTPHandler(srv, sc, cfg)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, pathLivez, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("livez wiring: code=%d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, pathMCP, nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("/mcp must require auth: code=%d", w.Code)
	}
}

// TestEndToEnd_MCPTransport proves the Streamable HTTP transport + tool dispatch
// work end to end with a real MCP client. The gate is covered separately in
// Task 4, so this mounts the raw streamable handler (no gate) to keep the
// transport smoke independent of client-side header injection.
func TestEndToEnd_MCPTransport(t *testing.T) {
	srv := newMCPServer(&toolDeps{authz: bufconnAuthz(t)}) // intro unused by check_permission
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: ts.URL}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer session.Close()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "check_permission",
		Arguments: map[string]any{"subject_id": "user-alice", "client_id": "web-app", "permission": "user:read"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res.Content)
	}
}
