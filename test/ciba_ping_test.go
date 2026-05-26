package ssotest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/oauth"
)

// newCIBAPingServer wires a CIBA server with a ping notifier, returning
// the *sso.Server (to drive ResolveBackchannelAuthRequest, standing in
// for the operator's device callback), an HTTP test server, and the
// record of every (auth_req_id, notification_token) the notifier saw.
func newCIBAPingServer(t *testing.T, notifyErr error) (*sso.Server, *httptest.Server, *[][2]string, *sync.Mutex) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: cibaUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: cibaClient, Secret: cibaSecret,
		TokenStrategy: "jwt", Active: true,
	})
	store := defaultimpl.NewMemoryCIBAStore()
	transport := oauth.CIBATransportFunc(func(context.Context, string, string, map[string]string) error {
		return nil
	})

	var mu sync.Mutex
	var pings [][2]string
	notifier := oauth.CIBAPingNotifierFunc(func(_ context.Context, clientID, authReqID, token string) error {
		mu.Lock()
		pings = append(pings, [2]string{authReqID, token})
		mu.Unlock()
		return notifyErr
	})

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithCIBA(store, transport, 2*time.Minute, 0),
		sso.WithCIBAPingNotifier(notifier),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return srv, httpSrv, &pings, &mu
}

// pingRequestAuthReqID drives /backchannel-authentication with the given
// client_notification_token and returns the minted auth_req_id.
func pingRequestAuthReqID(t *testing.T, httpSrv *httptest.Server, notifToken string) string {
	t.Helper()
	form := url.Values{}
	form.Set("client_id", cibaClient)
	form.Set("client_secret", cibaSecret)
	form.Set("login_hint", cibaUser)
	if notifToken != "" {
		form.Set("client_notification_token", notifToken)
	}
	resp, err := http.PostForm(httpSrv.URL+"/backchannel-authentication", form)
	if err != nil {
		t.Fatalf("POST /backchannel-authentication: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	id, _ := out["auth_req_id"].(string)
	if id == "" {
		t.Fatalf("no auth_req_id minted: status=%d body=%s", resp.StatusCode, raw)
	}
	return id
}

func TestCIBAPing_FiresOnResolve(t *testing.T) {
	srv, httpSrv, pings, mu := newCIBAPingServer(t, nil)
	id := pingRequestAuthReqID(t, httpSrv, "notif-tok-123")

	if err := srv.ResolveBackchannelAuthRequest(context.Background(), id, true); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// The notifier fires asynchronously; poll briefly for it.
	deadline := time.Now().Add(time.Second)
	for {
		mu.Lock()
		n := len(*pings)
		mu.Unlock()
		if n == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*pings) != 1 {
		t.Fatalf("pings = %d, want 1", len(*pings))
	}
	if (*pings)[0][0] != id || (*pings)[0][1] != "notif-tok-123" {
		t.Errorf("ping = %v, want [%s notif-tok-123]", (*pings)[0], id)
	}
}

func TestCIBAPing_PollModeDoesNotPing(t *testing.T) {
	srv, httpSrv, pings, mu := newCIBAPingServer(t, nil)
	// No client_notification_token => poll mode => no ping even though a
	// notifier is wired.
	id := pingRequestAuthReqID(t, httpSrv, "")

	if err := srv.ResolveBackchannelAuthRequest(context.Background(), id, true); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(*pings) != 0 {
		t.Errorf("poll-mode request pinged: %v", *pings)
	}
}

func TestCIBAPing_ResolveUnknownReturnsError(t *testing.T) {
	srv, _, _, _ := newCIBAPingServer(t, nil)
	err := srv.ResolveBackchannelAuthRequest(context.Background(), "no-such-id", true)
	if !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Errorf("err = %v, want ErrCIBARequestNotFound", err)
	}
}

func TestCIBAPing_NotEnabledWithoutStore(t *testing.T) {
	srv := sso.NewServer(
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
	)
	if err := srv.ResolveBackchannelAuthRequest(context.Background(), "x", true); !errors.Is(err, sso.ErrCIBANotEnabled) {
		t.Errorf("err = %v, want ErrCIBANotEnabled", err)
	}
}

func TestCIBAPing_DiscoveryAdvertisesPing(t *testing.T) {
	_, httpSrv, _, _ := newCIBAPingServer(t, nil)
	resp, err := http.Get(httpSrv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	modes, _ := doc["backchannel_token_delivery_modes_supported"].([]any)
	if len(modes) != 2 || modes[0] != "poll" || modes[1] != "ping" {
		t.Fatalf("delivery modes = %v, want [poll ping]", doc["backchannel_token_delivery_modes_supported"])
	}
}
