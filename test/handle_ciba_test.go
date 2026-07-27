package ssotest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

const (
	cibaUser   = "u-ciba"
	cibaClient = "ciba-client"
	cibaSecret = "ciba-secret"
)

// newCIBAServer wires a full *sso.Server with CIBA enabled, returning
// the HTTP test server + the store (so the test can drive the
// out-of-band confirm via store.SetStatus, standing in for the device
// callback) + a pointer to the last delivered auth_req_id.
func newCIBAServer(t *testing.T, interval time.Duration) (*httptest.Server, oauth.CIBAStore, *string) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: cibaUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: cibaClient, Secret: cibaSecret,
		TokenStrategy: "jwt", Active: true,
	})
	store := defaultimpl.NewMemoryCIBAStore()
	var delivered string
	transport := oauth.CIBATransportFunc(func(_ context.Context, authReqID, _ string, _ map[string]string) error {
		delivered = authReqID
		return nil
	})
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithCIBA(store, transport, 2*time.Minute, interval),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, store, &delivered
}

func cibaBackchannelAuth(t *testing.T, srv *httptest.Server, form url.Values) (int, map[string]any) {
	t.Helper()
	form.Set("client_id", cibaClient)
	form.Set("client_secret", cibaSecret)
	resp, err := http.Post(srv.URL+"/backchannel-authentication",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST /backchannel-authentication: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func cibaTokenPoll(t *testing.T, srv *httptest.Server, authReqID string) (int, map[string]any) {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", oauth.GrantCIBA)
	form.Set("auth_req_id", authReqID)
	form.Set("client_id", cibaClient)
	form.Set("client_secret", cibaSecret)
	resp, err := http.Post(srv.URL+"/token",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func TestCIBA_PollFlow_HappyPath(t *testing.T) {
	srv, store, delivered := newCIBAServer(t, time.Millisecond)
	form := url.Values{}
	form.Set("login_hint", cibaUser)
	form.Set("scope", "openid profile")
	form.Set("binding_message", "approve 4242")
	status, body := cibaBackchannelAuth(t, srv, form)
	if status != http.StatusOK {
		t.Fatalf("backchannel auth status = %d body=%v", status, body)
	}
	authReqID, _ := body["auth_req_id"].(string)
	if authReqID == "" {
		t.Fatalf("no auth_req_id: %v", body)
	}
	if *delivered != authReqID {
		t.Fatalf("transport delivered %q want %q", *delivered, authReqID)
	}

	// poll before approval → authorization_pending
	st, out := cibaTokenPoll(t, srv, authReqID)
	if st != http.StatusBadRequest || out["error"] != "authorization_pending" {
		t.Fatalf("pending poll = %d %v", st, out)
	}

	// out-of-band confirm (device callback stand-in)
	if err := store.SetStatus(context.Background(), authReqID, oauth.CIBAApproved); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	// Wait out the (tiny) poll interval so the approved poll isn't
	// rejected as slow_down.
	time.Sleep(5 * time.Millisecond)
	st, out = cibaTokenPoll(t, srv, authReqID)
	if st != http.StatusOK {
		t.Fatalf("approved poll = %d %v", st, out)
	}
	if _, ok := out["access_token"]; !ok {
		t.Fatalf("no access_token: %v", out)
	}

	// single-use: a replay after success → expired_token
	st, out = cibaTokenPoll(t, srv, authReqID)
	if st != http.StatusBadRequest || out["error"] != "expired_token" {
		t.Fatalf("replay = %d %v", st, out)
	}
}

func TestCIBA_Denied(t *testing.T) {
	srv, store, _ := newCIBAServer(t, 0)
	form := url.Values{}
	form.Set("login_hint", cibaUser)
	_, body := cibaBackchannelAuth(t, srv, form)
	authReqID, _ := body["auth_req_id"].(string)
	_ = store.SetStatus(context.Background(), authReqID, oauth.CIBADenied)
	st, out := cibaTokenPoll(t, srv, authReqID)
	if st != http.StatusBadRequest || out["error"] != "access_denied" {
		t.Fatalf("denied poll = %d %v", st, out)
	}
}

func TestCIBA_UnknownHintCollapses(t *testing.T) {
	srv, _, _ := newCIBAServer(t, 0)
	// missing hint
	st, out := cibaBackchannelAuth(t, srv, url.Values{})
	if st != http.StatusBadRequest || out["error"] != "unknown_user_id" {
		t.Fatalf("missing hint = %d %v", st, out)
	}
	// unresolvable hint collapses to the same error (anti-enumeration)
	form := url.Values{}
	form.Set("login_hint", "ghost-user")
	st, out = cibaBackchannelAuth(t, srv, form)
	if st != http.StatusBadRequest || out["error"] != "unknown_user_id" {
		t.Fatalf("unknown hint = %d %v", st, out)
	}
}

func TestCIBA_UnknownAuthReqIDCollapses(t *testing.T) {
	srv, _, _ := newCIBAServer(t, 0)
	st, out := cibaTokenPoll(t, srv, "ciba_does-not-exist")
	if st != http.StatusBadRequest || out["error"] != "expired_token" {
		t.Fatalf("unknown auth_req_id = %d %v", st, out)
	}
}

func TestCIBA_SlowDown(t *testing.T) {
	srv, _, _ := newCIBAServer(t, 10*time.Second)
	form := url.Values{}
	form.Set("login_hint", cibaUser)
	_, body := cibaBackchannelAuth(t, srv, form)
	authReqID, _ := body["auth_req_id"].(string)
	// Leave the request pending so polls don't consume it. First poll
	// records LastPoll and returns authorization_pending; an immediate
	// second poll (within the 10s interval) returns slow_down.
	if st, out := cibaTokenPoll(t, srv, authReqID); st != http.StatusBadRequest || out["error"] != "authorization_pending" {
		t.Fatalf("first poll = %d %v", st, out)
	}
	st, out := cibaTokenPoll(t, srv, authReqID)
	if st != http.StatusBadRequest || out["error"] != "slow_down" {
		t.Fatalf("slow_down poll = %d %v", st, out)
	}
}

func TestCIBA_DiscoveryAdvertised(t *testing.T) {
	srv, _, _ := newCIBAServer(t, 0)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if _, ok := doc["backchannel_authentication_endpoint"]; !ok {
		t.Fatalf("missing backchannel_authentication_endpoint: %v", doc)
	}
	modes, _ := doc["backchannel_token_delivery_modes_supported"].([]any)
	if len(modes) != 1 || modes[0] != "poll" {
		t.Fatalf("delivery modes = %v", doc["backchannel_token_delivery_modes_supported"])
	}
	grants, _ := doc["grant_types_supported"].([]any)
	found := false
	for _, g := range grants {
		if g == oauth.GrantCIBA {
			found = true
		}
	}
	if !found {
		t.Fatalf("ciba grant not in grant_types_supported: %v", grants)
	}
}
