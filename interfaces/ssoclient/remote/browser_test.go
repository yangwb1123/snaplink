package remote_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/remote"
)

func TestBrowserFlowRoundTrip(t *testing.T) {
	var exchange url.Values
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		exchange = r.Form
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access"})
	}))
	defer tokenServer.Close()
	tokens := remote.NewTokenClient(tokenServer.URL,
		remote.WithAuthorizationEndpoint("https://sso.example/auth/login"),
		remote.WithClientID("app"), remote.WithRedirectURI("https://app.example/callback"))
	flow, err := remote.NewBrowserFlow(tokens,
		remote.WithBrowserScopes("openid", "profile"),
		remote.WithBrowserCookie("app_state", "/oauth"))
	if err != nil {
		t.Fatal(err)
	}

	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodGet, "https://app.example/oauth/login", nil)
	if err := flow.Begin(loginRec, loginReq); err != nil {
		t.Fatal(err)
	}
	location, _ := url.Parse(loginRec.Header().Get("Location"))
	state := location.Query().Get("state")
	cookies := loginRec.Result().Cookies()
	if loginRec.Code != http.StatusFound || state == "" || len(cookies) != 1 {
		t.Fatalf("login status=%d location=%q cookies=%d", loginRec.Code, location, len(cookies))
	}
	if !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].Path != "/oauth" {
		t.Fatalf("state cookie = %#v", cookies[0])
	}

	callbackReq := httptest.NewRequest(http.MethodGet,
		"https://app.example/callback?code=code-1&state="+url.QueryEscape(state), nil)
	callbackReq.AddCookie(cookies[0])
	callbackRec := httptest.NewRecorder()
	token, err := flow.Callback(callbackRec, callbackReq)
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "access" || exchange.Get("code_verifier") == "" {
		t.Fatalf("token=%#v exchange=%#v", token, exchange)
	}
	if callbackRec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("callback response must be non-cacheable")
	}
}

func TestBrowserFlowRejectsMissingCookieAndReplay(t *testing.T) {
	tokens := remote.NewTokenClient("https://sso.example/token",
		remote.WithAuthorizationEndpoint("https://sso.example/auth/login"),
		remote.WithClientID("app"), remote.WithRedirectURI("https://app.example/callback"))
	flow, err := remote.NewBrowserFlow(tokens)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://app.example/callback?code=x&state=observed", nil)
	if _, err := flow.Callback(rec, req); !errors.Is(err, ssoclient.ErrInvalidAuthorizationFlow) {
		t.Fatalf("error = %v", err)
	}
}

func TestBrowserFlowMapsProviderRejection(t *testing.T) {
	tokens := remote.NewTokenClient("https://sso.example/token",
		remote.WithAuthorizationEndpoint("https://sso.example/auth/login"),
		remote.WithClientID("app"), remote.WithRedirectURI("https://app.example/callback"))
	flow, err := remote.NewBrowserFlow(tokens)
	if err != nil {
		t.Fatal(err)
	}
	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodGet, "https://app.example/login", nil)
	if err := flow.Begin(loginRec, loginReq); err != nil {
		t.Fatal(err)
	}
	location, _ := url.Parse(loginRec.Header().Get("Location"))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"https://app.example/callback?error=access_denied&state="+url.QueryEscape(location.Query().Get("state")), nil)
	req.AddCookie(loginRec.Result().Cookies()[0])
	if _, err := flow.Callback(rec, req); !errors.Is(err, ssoclient.ErrAuthorizationRejected) {
		t.Fatalf("error = %v", err)
	}
}
