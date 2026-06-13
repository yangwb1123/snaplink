package ssotest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/metrics"
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
	defer func() { _ = resp.Body.Close() }()
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

// newSupervisedCIBAPingServer wires a CIBA server with an arbitrary
// notifier plus metrics + an audit sink, so the supervised detached ping
// goroutine (deliverCIBAPing) can be driven via ResolveBackchannelAuthRequest
// and its timeout/recover/metric/audit observed. Returns the server, its HTTP
// test server, the metrics handle, and the audit sink.
func newSupervisedCIBAPingServer(t *testing.T, notifier oauth.CIBAPingNotifier) (*sso.Server, *httptest.Server, *metrics.Metrics, *audit.MemorySink) {
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

	m := metrics.New()
	sink := audit.NewMemorySink(16)

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithCIBA(store, transport, 2*time.Minute, 0),
		sso.WithCIBAPingNotifier(notifier),
		sso.WithMetrics(m),
		sso.WithAuditRecorder(audit.New(sink)),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return srv, httpSrv, m, sink
}

// cibaPingMetricValue scrapes /metrics and returns the value of
// sso_ciba_ping_total for the given outcome label (0 when the series is
// absent). Scraping (vs. testutil.ToFloat64) keeps the test free of the
// prometheus testutil dep, which would pull a new indirect module into go.mod.
func cibaPingMetricValue(t *testing.T, httpSrv *httptest.Server, outcome string) float64 {
	t.Helper()
	resp, err := http.Get(httpSrv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	want := metrics.NameCIBAPingTotal + `{outcome="` + outcome + `"} `
	for _, line := range strings.Split(string(body), "\n") {
		if v, ok := strings.CutPrefix(line, want); ok {
			var f float64
			// Prometheus counter samples are plain decimals (no exponent here).
			for _, c := range v {
				if c >= '0' && c <= '9' {
					f = f*10 + float64(c-'0')
				}
			}
			return f
		}
	}
	return 0
}

// waitForCIBAPingError polls the sso_ciba_ping_total{outcome="error"} counter
// until it reaches want or the deadline elapses. Returns the observed value.
func waitForCIBAPingError(t *testing.T, httpSrv *httptest.Server, want float64) float64 {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var got float64
	for {
		got = cibaPingMetricValue(t, httpSrv, "error")
		if got >= want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestCIBAPing_PanickingNotifierIsRecovered injects a notifier that PANICS.
// The supervising goroutine's recover() must contain it: the process survives
// (this test returning at all proves the goroutine didn't crash the runtime),
// the error metric increments, and a ciba_ping_failed audit event is emitted.
func TestCIBAPing_PanickingNotifierIsRecovered(t *testing.T) {
	notifier := oauth.CIBAPingNotifierFunc(func(context.Context, string, string, string) error {
		panic("notifier blew up")
	})
	srv, httpSrv, _, sink := newSupervisedCIBAPingServer(t, notifier)
	id := pingRequestAuthReqID(t, httpSrv, "notif-tok-panic")

	if err := srv.ResolveBackchannelAuthRequest(context.Background(), id, true); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if got := waitForCIBAPingError(t, httpSrv, 1); got != 1 {
		t.Fatalf("ciba_ping_total{error} = %v, want 1 (recover() must count the panic)", got)
	}
	if got := cibaPingMetricValue(t, httpSrv, "success"); got != 0 {
		t.Errorf("ciba_ping_total{success} = %v, want 0", got)
	}
	if !auditHasCIBAPingFailed(sink) {
		t.Errorf("expected a ciba_ping_failed audit event after a panicking notifier")
	}
}

// TestCIBAPing_SlowNotifierDoesNotLeak injects a notifier that BLOCKS well
// past cibaPingDeliveryTimeout (10s). The bounded context must unblock it so
// the goroutine returns (signalled via the done channel) and the error metric
// increments — proving a hanging webhook can't leak the goroutine forever.
// The notifier observes ctx cancellation to model a well-behaved-but-slow
// transport; a notifier ignoring ctx is still bounded by the goroutine
// returning regardless (the timeout fires either way).
func TestCIBAPing_SlowNotifierDoesNotLeak(t *testing.T) {
	done := make(chan struct{})
	notifier := oauth.CIBAPingNotifierFunc(func(ctx context.Context, _, _, _ string) error {
		defer close(done)
		select {
		case <-ctx.Done():
			return ctx.Err() // timeout fired — clean error, goroutine returns.
		case <-time.After(60 * time.Second):
			return nil // would only hit this if the bound were missing.
		}
	})
	srv, httpSrv, _, _ := newSupervisedCIBAPingServer(t, notifier)
	id := pingRequestAuthReqID(t, httpSrv, "notif-tok-slow")

	start := time.Now()
	if err := srv.ResolveBackchannelAuthRequest(context.Background(), id, true); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Resolve must NOT block on the ping (fire-and-forget on the request path).
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("ResolveBackchannelAuthRequest blocked on the ping for %v; must be non-blocking", elapsed)
	}

	// The goroutine must return within the bound (+ slack), not leak for 60s.
	select {
	case <-done:
	case <-time.After(cibaPingDeliveryTimeoutSlack):
		t.Fatalf("ping goroutine did not return within the bounded timeout; it leaked")
	}
	if got := waitForCIBAPingError(t, httpSrv, 1); got != 1 {
		t.Fatalf("ciba_ping_total{error} = %v, want 1 (timeout must count as an error)", got)
	}
}

// cibaPingDeliveryTimeoutSlack is the supervised timeout (10s) plus headroom
// for scheduling so the leak assertion doesn't flake under -race.
const cibaPingDeliveryTimeoutSlack = 15 * time.Second

// auditHasCIBAPingFailed reports whether the sink recorded a ciba_ping_failed
// event. The detached goroutine records asynchronously off the resolve path,
// so callers should have already synchronized on the metric before checking.
func auditHasCIBAPingFailed(sink *audit.MemorySink) bool {
	events, _ := sink.Query(context.Background(), audit.Query{Type: audit.EventCIBAPingFailed})
	return len(events) > 0
}

func TestCIBAPing_DiscoveryAdvertisesPing(t *testing.T) {
	_, httpSrv, _, _ := newCIBAPingServer(t, nil)
	resp, err := http.Get(httpSrv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	modes, _ := doc["backchannel_token_delivery_modes_supported"].([]any)
	if len(modes) != 2 || modes[0] != "poll" || modes[1] != "ping" {
		t.Fatalf("delivery modes = %v, want [poll ping]", doc["backchannel_token_delivery_modes_supported"])
	}
}
