package ssotest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/protocols/oauth"
)

// newCIBAPushServer wires a full *sso.Server with CIBA + push delivery
// (CIBA Core §10.3) enabled: pushEndpoint is cibaClient's registered
// backchannel_token_delivery_uri (a REAL httptest.Server the test
// controls), reached via pushClient so the endpoint's self-signed TLS
// cert is trusted (push delivery is https-only by contract). Returns the
// *sso.Server (to drive ResolveBackchannelAuthRequest, standing in for the
// operator's device-confirmation callback) and its HTTP test server (for
// the actual /backchannel-authentication + /token requests).
func newCIBAPushServer(t *testing.T, pushClient *http.Client, pushEndpoint string) (*sso.Server, *httptest.Server) {
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
	resolver := func(_ context.Context, clientID string) (string, error) {
		if clientID == cibaClient {
			return pushEndpoint, nil
		}
		return "", nil // any other client: no registered push endpoint
	}
	notifier := oauth.NewCIBAPushNotifier(resolver, oauth.WithCIBAPushHTTPClient(pushClient))

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithCIBA(store, transport, 2*time.Minute, time.Millisecond),
		sso.WithCIBAPushNotifier(notifier),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return srv, httpSrv
}

// cibaPushDelivery captures one push delivery the test's endpoint observed.
type cibaPushDelivery struct {
	auth string
	body map[string]any
}

// newCIBAPushEndpoint starts a REAL httptest.TLS server standing in for
// the client's backchannel_token_delivery_uri, recording every delivery it
// receives.
func newCIBAPushEndpoint(t *testing.T) (*httptest.Server, *atomic.Value) {
	t.Helper()
	var last atomic.Value
	last.Store(cibaPushDelivery{})
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		last.Store(cibaPushDelivery{auth: r.Header.Get("Authorization"), body: body})
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	return ts, &last
}

// waitForCIBAPushDelivery polls last (populated by newCIBAPushEndpoint's
// handler) until a delivery with the expected auth_req_id lands or the
// deadline elapses — push fires from a detached goroutine
// (dispatchCIBANotification -> deliverCIBAPush), so it is not synchronous
// with ResolveBackchannelAuthRequest returning.
func waitForCIBAPushDelivery(t *testing.T, last *atomic.Value, authReqID string) cibaPushDelivery {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		d := last.Load().(cibaPushDelivery)
		if d.body != nil && d.body["auth_req_id"] == authReqID {
			return d
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for a push delivery of auth_req_id=%s; last observed=%+v", authReqID, d)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestCIBAPush_DeliversTokenPayloadToRegisteredEndpoint proves the full
// CIBA Core §10.3 push flow end to end against REAL HTTP servers (no
// mocks): a client registers a client_notification_token, the operator's
// device-confirmation callback resolves the request via
// ResolveBackchannelAuthRequest, and the server autonomously mints the
// token set and POSTs it — authenticated with the notification token as a
// bearer credential — to the client's registered endpoint, WITHOUT the
// client ever polling /token.
func TestCIBAPush_DeliversTokenPayloadToRegisteredEndpoint(t *testing.T) {
	pushEP, last := newCIBAPushEndpoint(t)
	srv, httpSrv := newCIBAPushServer(t, pushEP.Client(), pushEP.URL)

	form := url.Values{}
	form.Set("login_hint", cibaUser)
	form.Set("scope", "openid profile")
	form.Set("client_notification_token", "notif-tok-push")
	status, body := cibaBackchannelAuth(t, httpSrv, form)
	if status != http.StatusOK {
		t.Fatalf("backchannel auth status = %d body=%v", status, body)
	}
	authReqID, _ := body["auth_req_id"].(string)
	if authReqID == "" {
		t.Fatalf("no auth_req_id minted: %v", body)
	}

	// Out-of-band confirm (device-callback stand-in) — this is what fires
	// push, NOT a /token poll (a push-registered client never polls).
	if err := srv.ResolveBackchannelAuthRequest(context.Background(), authReqID, true); err != nil {
		t.Fatalf("ResolveBackchannelAuthRequest: %v", err)
	}

	delivery := waitForCIBAPushDelivery(t, last, authReqID)
	if delivery.auth != "Bearer notif-tok-push" {
		t.Errorf("push Authorization = %q, want %q", delivery.auth, "Bearer notif-tok-push")
	}
	accessToken, _ := delivery.body["access_token"].(string)
	if accessToken == "" {
		t.Errorf("pushed payload missing access_token: %+v", delivery.body)
	}
	if tt, _ := delivery.body["token_type"].(string); tt != "Bearer" {
		t.Errorf("pushed token_type = %v, want Bearer", delivery.body["token_type"])
	}
	// No OIDC id_token issuer is wired in this harness (mirrors
	// TestCIBA_PollFlow_HappyPath, handle_ciba_test.go, which likewise only
	// asserts access_token) — id_token issuance into the push payload is
	// exercised at the unit level by
	// TestMintCIBATokensForPush_EmitsIDTokenForOpenIDScope
	// (internal/handler/tokengrant/token_ciba_test.go).

	// The push path claims the request via the SAME single-use
	// ConsumeIfApproved the poll path uses, so a subsequent poll must see
	// it as already consumed (expired_token) — exactly one token set was
	// ever minted for this approval.
	st, out := cibaTokenPoll(t, httpSrv, authReqID)
	if st != http.StatusBadRequest || out["error"] != "expired_token" {
		t.Fatalf("poll after push = %d %v, want 400 expired_token", st, out)
	}
}

// TestCIBAPush_NoNotificationTokenFallsBackToPoll proves a request WITHOUT
// a client_notification_token never triggers push (even though a
// CIBAPushNotifier is wired) and the client's ordinary poll still mints
// tokens normally — push is additive, not a behavior change for poll-only
// clients.
func TestCIBAPush_NoNotificationTokenFallsBackToPoll(t *testing.T) {
	pushEP, last := newCIBAPushEndpoint(t)
	srv, httpSrv := newCIBAPushServer(t, pushEP.Client(), pushEP.URL)

	form := url.Values{}
	form.Set("login_hint", cibaUser)
	// No client_notification_token: poll-only request.
	status, body := cibaBackchannelAuth(t, httpSrv, form)
	if status != http.StatusOK {
		t.Fatalf("backchannel auth status = %d body=%v", status, body)
	}
	authReqID, _ := body["auth_req_id"].(string)

	if err := srv.ResolveBackchannelAuthRequest(context.Background(), authReqID, true); err != nil {
		t.Fatalf("ResolveBackchannelAuthRequest: %v", err)
	}
	// Give any (incorrectly) fired push goroutine a chance to land before
	// asserting it didn't.
	time.Sleep(50 * time.Millisecond)
	if d := last.Load().(cibaPushDelivery); d.body != nil {
		t.Fatalf("push fired without a client_notification_token: %+v", d)
	}

	st, out := cibaTokenPoll(t, httpSrv, authReqID)
	if st != http.StatusOK {
		t.Fatalf("poll-only flow after resolve = %d %v, want 200", st, out)
	}
	if _, ok := out["access_token"]; !ok {
		t.Fatalf("no access_token from the poll-only flow: %v", out)
	}
}

// TestCIBAPush_DiscoveryAdvertisesPush proves discovery advertises "push"
// alongside "poll" once a CIBAPushNotifier is wired.
func TestCIBAPush_DiscoveryAdvertisesPush(t *testing.T) {
	_, httpSrv := newCIBAPushServer(t, http.DefaultClient, "https://unused.example/ciba/push")
	resp, err := http.Get(httpSrv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	modes, _ := doc["backchannel_token_delivery_modes_supported"].([]any)
	if len(modes) != 2 || modes[0] != "poll" || modes[1] != "push" {
		t.Fatalf("delivery modes = %v, want [poll push]", doc["backchannel_token_delivery_modes_supported"])
	}
}
