package snaplink

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// The session lifecycle is the explicit half of the SDK: refresh, logout, and
// the predicates. Automatic renewal is deliberately absent, because it makes
// "which request fired, and when" unobservable.

type sessionServer struct {
	*httptest.Server
	tokenCalls  []url.Values
	logoutCalls []string
	tokens      TokenResponse
	logoutCode  int
}

func newSessionServer(t *testing.T) *sessionServer {
	t.Helper()
	fixture := &sessionServer{tokens: TokenResponse{
		AccessToken:  "access-2",
		RefreshToken: "refresh-2",
		ExpiresIn:    900,
		TokenType:    "Bearer",
	}}
	fixture.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			fixture.tokenCalls = append(fixture.tokenCalls, form)
			if form.Get("grant_type") == "refresh_token" && form.Get("refresh_token") == "" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "invalid_grant", "error_description": "unknown refresh token",
				})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(fixture.tokens)
		case "/logout":
			fixture.logoutCalls = append(fixture.logoutCalls, r.Header.Get("Authorization"))
			if fixture.logoutCode != 0 {
				w.WriteHeader(fixture.logoutCode)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fixture.Close)
	return fixture
}

// loggedIn drives a real login so the client holds tokens the refresh grant can
// rotate.
func loggedIn(t *testing.T, server *sessionServer) *Client {
	t.Helper()
	client := NewClient(nil, server.Client())
	client.tokens = &TokenResponse{
		AccessToken: "access-1", RefreshToken: "refresh-1", ExpiresIn: 900, TokenType: "Bearer",
	}
	client.baseURL = server.URL
	client.clientID = "spa-client"
	return client
}

func TestIsLoggedInAndCanRefreshReflectHeldState(t *testing.T) {
	client := NewClient(nil, nil)
	if client.IsLoggedIn() {
		t.Fatal("a fresh client is not logged in")
	}
	if client.CanRefresh() {
		t.Fatal("a fresh client cannot refresh")
	}
	server := newSessionServer(t)
	session := loggedIn(t, server)
	if !session.IsLoggedIn() || !session.CanRefresh() {
		t.Fatal("a logged-in client reports both")
	}
}

func TestRefreshRenewsTheAccessTokenAndRotatesTheRefreshToken(t *testing.T) {
	server := newSessionServer(t)
	client := loggedIn(t, server)

	tokens, err := client.Refresh(context.Background())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if tokens.AccessToken != "access-2" {
		t.Fatalf("access token %q", tokens.AccessToken)
	}
	if client.AccessToken() != "access-2" {
		t.Fatal("the client must adopt the new access token")
	}
	if len(server.tokenCalls) != 1 {
		t.Fatalf("expected one token call, got %d", len(server.tokenCalls))
	}
	form := server.tokenCalls[0]
	if form.Get("grant_type") != "refresh_token" {
		t.Fatalf("grant_type %q", form.Get("grant_type"))
	}
	if form.Get("refresh_token") != "refresh-1" {
		t.Fatalf("refresh_token %q", form.Get("refresh_token"))
	}
	if form.Get("client_id") != "spa-client" {
		t.Fatalf("client_id %q", form.Get("client_id"))
	}
	if form.Has("code_verifier") {
		t.Fatal("a refresh must never carry a code verifier")
	}
}

func TestRefreshKeepsThePreviousRefreshTokenWhenTheServerDoesNotRotate(t *testing.T) {
	server := newSessionServer(t)
	server.tokens.RefreshToken = ""
	client := loggedIn(t, server)

	tokens, err := client.Refresh(context.Background())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if tokens.RefreshToken != "refresh-1" {
		t.Fatalf("a non-rotating response must not lose the ability to refresh: %q", tokens.RefreshToken)
	}
	if !client.CanRefresh() {
		t.Fatal("the client must still be able to refresh")
	}
}

func TestRefreshWithoutARefreshTokenIsTerminalNotARetry(t *testing.T) {
	server := newSessionServer(t)
	client := loggedIn(t, server)
	client.tokens.RefreshToken = ""

	_, err := client.Refresh(context.Background())
	if err == nil {
		t.Fatal("expected a login_required error")
	}
	var sdkErr *Error
	if !asError(err, &sdkErr) || sdkErr.Code != "login_required" {
		t.Fatalf("expected login_required, got %v", err)
	}
	if len(server.tokenCalls) != 0 {
		t.Fatal("no request may be made without a refresh token")
	}
}

func TestRefreshSurfacesAnInvalidGrant(t *testing.T) {
	server := newSessionServer(t)
	client := loggedIn(t, server)
	client.tokens.RefreshToken = "" // force the server-side invalid_grant branch

	_, err := client.Refresh(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestLogoutRevokesServerSideThenClearsLocalState(t *testing.T) {
	server := newSessionServer(t)
	client := loggedIn(t, server)

	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if len(server.logoutCalls) != 1 {
		t.Fatalf("expected one logout call, got %d", len(server.logoutCalls))
	}
	if server.logoutCalls[0] != "Bearer access-1" {
		t.Fatalf("authorization %q", server.logoutCalls[0])
	}
	if client.AccessToken() != "" || client.IsLoggedIn() {
		t.Fatal("local state must be cleared")
	}
}

func TestLogoutClearsLocalStateEvenWhenTheServerCallFails(t *testing.T) {
	server := newSessionServer(t)
	server.logoutCode = http.StatusInternalServerError
	client := loggedIn(t, server)

	if err := client.Logout(context.Background()); err == nil {
		t.Fatal("the server error must be reported")
	}
	if client.IsLoggedIn() {
		t.Fatal("a caller asking to log out must end up logged out locally regardless")
	}
}

func TestLogoutWithoutASessionIsANoOp(t *testing.T) {
	server := newSessionServer(t)
	client := NewClient(nil, server.Client())
	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("logout without a session must be a no-op: %v", err)
	}
	if len(server.logoutCalls) != 0 {
		t.Fatal("no request may be made without a session")
	}
}

func TestClearIsLocalOnlyAndDistinctFromLogout(t *testing.T) {
	server := newSessionServer(t)
	client := loggedIn(t, server)

	client.Clear()
	if client.IsLoggedIn() {
		t.Fatal("clear must drop local state")
	}
	if len(server.logoutCalls) != 0 {
		t.Fatal("clear must not contact the server; that is what logout is for")
	}
}

func TestExpiresAtIsZeroWithoutAnAccessToken(t *testing.T) {
	client := NewClient(nil, nil)
	if client.ExpiresAt() != 0 {
		t.Fatalf("ExpiresAt %v", client.ExpiresAt())
	}
	client.tokens = &TokenResponse{AccessToken: "a", ExpiresIn: 900}
	if client.ExpiresAt().Seconds() != 900 {
		t.Fatalf("ExpiresAt %v", client.ExpiresAt())
	}
}

func asError(err error, target **Error) bool {
	value, ok := err.(*Error)
	if ok {
		*target = value
	}
	return ok
}
