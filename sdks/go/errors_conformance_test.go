package snaplink

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The error taxonomy is a cross-language contract, not a per-language detail:
// a caller branches on the code, so the five hosted-login SDKs must classify
// the same response identically. The cases come from the shared fixture rather
// than from a local list, which is what makes drift detectable.

type errorCase struct {
	Code   string `json:"code"`
	Status int    `json:"status"`
	Class  string `json:"class"`
}

type errorFixture struct {
	Cases []errorCase `json:"cases"`
	Shape struct {
		Fallback struct {
			Code string `json:"code"`
		} `json:"fallback"`
	} `json:"shape"`
}

func loadErrorFixture(t *testing.T) errorFixture {
	t.Helper()
	path := filepath.Join("..", "..", "ops", "build", "sdk-conformance", "errors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read the shared error fixture: %v", err)
	}
	var fixture errorFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("the shared error fixture is invalid: %v", err)
	}
	if len(fixture.Cases) == 0 || fixture.Shape.Fallback.Code == "" {
		t.Fatal("the shared error fixture must carry cases and a fallback code")
	}
	return fixture
}

// serveFailure answers every request with the given status and body.
func serveFailure(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

func tokenExchangeError(t *testing.T, client *Client) *Error {
	t.Helper()
	_, err := client.Refresh(context.Background())
	var sdkErr *Error
	if !asError(err, &sdkErr) {
		t.Fatalf("expected a *Error, got %v", err)
	}
	return sdkErr
}

func TestEveryFixtureErrorCodeSurvivesVerbatim(t *testing.T) {
	fixture := loadErrorFixture(t)
	for _, testCase := range fixture.Cases {
		if testCase.Status == 0 {
			// A locally originated case (license verification) is never a wire
			// response, so there is nothing for a transport to classify.
			continue
		}
		body, err := json.Marshal(map[string]string{
			"error":             testCase.Code,
			"error_description": "reworded by any implementation",
		})
		if err != nil {
			t.Fatal(err)
		}
		server := serveFailure(t, testCase.Status, string(body))
		client := NewClient(nil, server.Client())
		client.tokens = &TokenResponse{AccessToken: "access-1", RefreshToken: "refresh-1", TokenType: "Bearer"}
		client.baseURL = server.URL

		got := tokenExchangeError(t, client)

		if got.Code != testCase.Code {
			t.Fatalf("case %s was classified as %q", testCase.Code, got.Code)
		}
		if got.Status != testCase.Status {
			t.Fatalf("case %s reported status %d, want %d", testCase.Code, got.Status, testCase.Status)
		}
	}
}

func TestAResponseWithoutACodeIsNeverInventedIntoAServerCode(t *testing.T) {
	fixture := loadErrorFixture(t)
	for _, body := range []string{`{}`, `{"error_description":"no code here"}`, `not json at all`, ``} {
		server := serveFailure(t, http.StatusInternalServerError, body)
		client := NewClient(nil, server.Client())
		client.tokens = &TokenResponse{AccessToken: "access-1", RefreshToken: "refresh-1", TokenType: "Bearer"}
		client.baseURL = server.URL

		got := tokenExchangeError(t, client)

		if got.Code != fixture.Shape.Fallback.Code {
			t.Fatalf("body %q was classified as %q, want the SDK fallback", body, got.Code)
		}
		if got.Code == "invalid_grant" {
			t.Fatal("an unreadable response must never look like a terminal grant failure")
		}
		if got.Status != http.StatusInternalServerError {
			t.Fatalf("the response status must be preserved: %d", got.Status)
		}
	}
}

func TestALocallyOriginatedErrorKeepsTheZeroStatus(t *testing.T) {
	fixture := loadErrorFixture(t)
	err := &Error{Status: 0, Code: "invalid_request", Description: "client_id is required"}
	if err.Status == 0 && err.Code == fixture.Shape.Fallback.Code {
		t.Fatal("a pre-flight validation failure is not an unclassified response")
	}
	if err.Code == "" {
		t.Fatal("a local failure must still carry a non-empty code")
	}
}
