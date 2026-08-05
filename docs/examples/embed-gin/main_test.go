package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestSmoke_AuthorizationCodeAndEmbedderRoute exercises the example's own
// newApp() wiring: embedder route, full authorization-code flow, the SDK
// normalized panic 500 (gin.New() has no Recovery), and the unmatched-surface
// byte contract.
func TestSmoke_AuthorizationCodeAndEmbedderRoute(t *testing.T) {
	gin.SetMode(gin.TestMode) // silence debug route prints; main keeps default mode
	handler := newApp()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Embedder route coexists on the same engine.
	resp, err := http.Get(ts.URL + "/hello")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "hello from the embedder" {
		t.Fatalf("/hello = %d %q", resp.StatusCode, body)
	}

	// Full authorization-code flow.
	loginBody, _ := json.Marshal(map[string]any{
		"provider":      "password",
		"client_id":     clientID,
		"credential":    map[string]string{"username": "alice", "password": "wonderland"},
		"response_type": "code",
		"redirect_uri":  redirectURI,
		"state":         "xyz",
	})
	resp, err = http.Post(ts.URL+"/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login = %d %s", resp.StatusCode, raw)
	}
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	code, _ := out["code"].(string)
	if code == "" {
		t.Fatalf("no code: %s", raw)
	}

	exchange := "grant_type=authorization_code&code=" + code + "&client_id=" + clientID +
		"&client_secret=" + clientSecret + "&redirect_uri=" + redirectURI
	resp, err = http.Post(ts.URL+"/token", "application/x-www-form-urlencoded", bytes.NewBufferString(exchange))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	out = map[string]any{}
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusOK || out["access_token"] == "" {
		t.Fatalf("exchange = %d %s", resp.StatusCode, raw)
	}

	// Panic route: with gin.New() there is no framework Recovery, so the
	// SDK's outermost recovery writes the normalized JSON 500.
	resp, err = http.Get(ts.URL + "/boom")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("/boom = %d %s, want SDK JSON 500", resp.StatusCode, raw)
	}
	if string(raw) != `{"error":"internal_error"}` {
		t.Errorf("/boom body = %s, want SDK normalized JSON", raw)
	}

	// Unmatched surface: byte-identical to http.NotFound.
	ref := httptest.NewRecorder()
	http.NotFound(ref, httptest.NewRequest(http.MethodGet, "/nope", nil))
	resp, err = http.Get(ts.URL + "/nope")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != ref.Code || !bytes.Equal(raw, ref.Body.Bytes()) {
		t.Errorf("unknown path = %d %q, want http.NotFound bytes %q", resp.StatusCode, raw, ref.Body.Bytes())
	}
}
