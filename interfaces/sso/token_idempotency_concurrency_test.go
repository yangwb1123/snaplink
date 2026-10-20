package sso_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant"
	tenantmemory "github.com/yangwb1123/snaplink/domains/tenant/memory"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

const cc04Client = "cc04-client"

// Only blocking/counting is wrapped; issuance and validation use real JWTs.
type cc04Issuer struct {
	core.TokenIssuer
	before   func(*core.Subject, []string) error
	attempts atomic.Int32
	success  atomic.Int32
}

func (i *cc04Issuer) Issue(ctx context.Context, subject *core.Subject, scopes []string) (*core.Token, error) {
	i.attempts.Add(1)
	if i.before != nil {
		if err := i.before(subject, scopes); err != nil {
			return nil, err
		}
	}
	token, err := i.TokenIssuer.Issue(ctx, subject, scopes)
	if err == nil {
		i.success.Add(1)
	}
	return token, err
}

func cc04Memory(t *testing.T) *defaultimpl.MemoryIdempotentCache {
	t.Helper()
	cache := defaultimpl.NewMemoryIdempotentCache(time.Minute)
	t.Cleanup(cache.Close)
	return cache
}

func cc04Request(scope string) oauth.TokenRequest {
	return oauth.TokenRequest{GrantType: sso.GrantClientCredentials, ClientID: cc04Client, ClientSecret: rcovSecret, Scope: scope}
}

func cc04Stripe(req oauth.TokenRequest, key string) byte {
	fingerprint := sso.TokenIdempotencyCacheKeyForTest(req.ClientID, key, req, "", "")
	return sha256.Sum256([]byte(fingerprint))[0]
}

// Search is bounded, and uses the unchanged complete cache fingerprint.
func cc04Pair(t *testing.T, a, b oauth.TokenRequest, collide bool) (string, string) {
	t.Helper()
	first := "cc04-first"
	stripe := cc04Stripe(a, first)
	for n := range 65536 {
		second := fmt.Sprintf("cc04-second-%d", n)
		if (cc04Stripe(b, second) == stripe) == collide {
			t.Logf("complete-key SHA256 first-byte stripes: A=%d B=%d; collision=%t; bounded candidate=%d", stripe, cc04Stripe(b, second), collide, n)
			return first, second
		}
	}
	t.Fatal("bounded stripe selection exhausted")
	return "", ""
}

type cc04Response struct {
	status int
	header http.Header
	token  core.Token
	code   string
	err    error
}

type cc04Requests struct {
	url     string
	client  *http.Client
	ctx     context.Context
	wg      sync.WaitGroup
	release func()
	arrived chan struct{}
}

func newCC04Requests(t *testing.T, issuer *cc04Issuer, cache core.IdempotentCache, release func(), opts ...sso.Option) (*cc04Requests, *defaultimpl.MemoryClientStore) {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: cc04Client, Secret: rcovSecret, Active: true, TokenStrategy: "jwt", AllowedScopes: []string{"read", "write"}})
	options := []sso.Option{sso.WithClientStore(clients), sso.WithTokenIssuer("jwt", issuer), sso.WithDefaultTokenStrategy("jwt"), sso.WithIdempotentStore(cache)}
	handler := sso.NewServer(append(options, opts...)...).Handler()
	arrived := make(chan struct{}, 128)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		handler.ServeHTTP(w, r)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	g := &cc04Requests{url: server.URL, client: server.Client(), ctx: ctx, release: release, arrived: arrived}
	t.Cleanup(func() {
		if g.release != nil {
			g.release()
		}
		cancel()
		done := make(chan struct{})
		go func() { g.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("request goroutines did not drain within existing one-second watchdog")
		}
		g.client.CloseIdleConnections()
		cc04CleanupEvent('B')
		defer cc04CleanupEvent('E')
		server.Close()
	})
	return g, clients
}

func (g *cc04Requests) send(req oauth.TokenRequest, key string, headers ...http.Header) cc04Response {
	// Omit assertion parameters entirely: explicit empty assertions are invalid auth.
	payload, err := json.Marshal(map[string]any{
		"grant_type": req.GrantType, "client_id": req.ClientID,
		"client_secret": req.ClientSecret, "scope": req.Scope, "resource": req.Resource,
	})
	if err != nil {
		return cc04Response{err: err}
	}
	r, err := http.NewRequestWithContext(g.ctx, http.MethodPost, g.url+"/token", bytes.NewReader(payload))
	if err != nil {
		return cc04Response{err: err}
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	for _, header := range headers {
		for name, values := range header {
			if strings.EqualFold(name, "Host") {
				r.Host = header.Get(name)
				continue
			}
			r.Header[name] = slices.Clone(values)
		}
	}
	response, err := g.client.Do(r)
	if err != nil {
		return cc04Response{err: err}
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	result := cc04Response{status: response.StatusCode, header: response.Header.Clone(), err: err}
	if err == nil {
		result.err = json.Unmarshal(raw, &result.token)
		var failure struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &failure)
		result.code = failure.Error
	}
	return result
}

func (g *cc04Requests) start(req oauth.TokenRequest, key string) <-chan cc04Response {
	result := make(chan cc04Response, 1)
	g.wg.Go(func() { result <- g.send(req, key) })
	return result
}

func cc04Await(t *testing.T, result <-chan cc04Response) cc04Response {
	t.Helper()
	select {
	case response := <-result:
		return response
	case <-time.After(time.Second):
		t.Fatal("request did not complete within existing one-second watchdog")
		return cc04Response{}
	}
}

func cc04Success(t *testing.T, issuer *cc04Issuer, response cc04Response, clientID, scope string) *core.TokenClaims {
	t.Helper()
	cc04NoStore(t, response)
	if response.err != nil || response.status != http.StatusOK || response.token.AccessToken == "" {
		t.Fatalf("token response: status=%d error=%s transport/decode=%v", response.status, response.code, response.err)
	}
	claims, err := issuer.Validate(t.Context(), response.token.AccessToken)
	if err != nil || claims == nil || claims.ClientID != clientID || claims.Subject != clientID || !slices.Equal(claims.Scopes, []string{scope}) {
		t.Fatal("JWT validation or client/subject/scope identity mismatch (credentials omitted)")
	}
	return claims
}

func cc04NoStore(t *testing.T, response cc04Response) {
	t.Helper()
	if response.header.Get("Cache-Control") != "no-store" || response.header.Get("Pragma") != "no-cache" {
		t.Error("credential response lost no-store headers")
	}
}

func TestClientCredentialsIdempotencyDifferentStripesProgress(t *testing.T) {
	if cc04Isolate(t) {
		return
	}
	entered, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(unblock) }) }
	issuer := &cc04Issuer{TokenIssuer: defaultimpl.NewEd25519JWTIssuer()}
	issuer.before = func(_ *core.Subject, scopes []string) error {
		if slices.Equal(scopes, []string{"read"}) {
			close(entered)
			<-unblock
		}
		return nil
	}
	g, _ := newCC04Requests(t, issuer, cc04Memory(t), release)
	a, b := cc04Request("read"), cc04Request("write")
	keyA, keyB := cc04Pair(t, a, b, false)
	first := g.start(a, keyA)
	select {
	case <-entered:
	case response := <-first:
		t.Fatalf("A returned before controlled issuance: status=%d code=%s error=%v", response.status, response.code, response.err)
	case <-time.After(time.Second):
		t.Fatal("A did not enter controlled real issuance")
	}
	second := g.start(b, keyB)
	select {
	case response := <-second:
		cc04Success(t, issuer, response, cc04Client, "write")
		select {
		case <-unblock:
			t.Fatal("A was released before B completed")
		default:
		}
	case <-time.After(time.Second):
		t.Fatal("different-stripe B blocked behind A while A remained in controlled issuance")
	}
	release()
	cc04Success(t, issuer, cc04Await(t, first), cc04Client, "read")
	if issuer.success.Load() != 2 {
		t.Fatal("expected two independent successful real issuances")
	}
}

func cc04Arrived(t *testing.T, g *cc04Requests) {
	t.Helper()
	select {
	case <-g.arrived:
	case <-time.After(time.Second):
		t.Fatal("HTTP request did not arrive within one-second watchdog")
	}
}

func TestClientCredentialsIdempotencyTwentyConcurrentRetriesIssueOnce(t *testing.T) {
	if cc04Isolate(t) {
		return
	}
	entered, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(unblock) }) }
	issuer := &cc04Issuer{TokenIssuer: defaultimpl.NewEd25519JWTIssuer()}
	issuer.before = func(_ *core.Subject, _ []string) error { close(entered); <-unblock; return nil }
	g, _ := newCC04Requests(t, issuer, cc04Memory(t), release)
	launch := make(chan struct{})
	results := make(chan cc04Response, 20)
	for range 20 {
		g.wg.Go(func() { <-launch; results <- g.send(cc04Request("read"), "twenty-retries") })
	}
	close(launch)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first issuance did not enter controlled barrier")
	}
	for range 20 {
		cc04Arrived(t, g)
	}
	if issuer.attempts.Load() != 1 {
		t.Fatal("same-fingerprint retry bypassed coordination")
	}
	release()
	var token string
	for range 20 {
		response := cc04Await(t, results)
		cc04Success(t, issuer, response, cc04Client, "read")
		if token != "" && response.token.AccessToken != token {
			t.Fatal("healthy same-key retries returned different tokens")
		}
		token = response.token.AccessToken
	}
	if issuer.attempts.Load() != 1 || issuer.success.Load() != 1 {
		t.Fatal("healthy twenty-request retry performed more than one real issuance")
	}
}

func TestClientCredentialsIdempotencyCollisionKeepsResponsesSeparate(t *testing.T) {
	if cc04Isolate(t) {
		return
	}
	entered, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(unblock) }) }
	issuer := &cc04Issuer{TokenIssuer: defaultimpl.NewEd25519JWTIssuer()}
	issuer.before = func(_ *core.Subject, scopes []string) error {
		if slices.Equal(scopes, []string{"read"}) {
			close(entered)
			<-unblock
		}
		return nil
	}
	g, _ := newCC04Requests(t, issuer, cc04Memory(t), release)
	a, b := cc04Request("read"), cc04Request("write")
	keyA, keyB := cc04Pair(t, a, b, true)
	first := g.start(a, keyA)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("A did not enter issuance")
	}
	second := g.start(b, keyB)
	cc04Arrived(t, g)
	cc04Arrived(t, g)
	select {
	case <-second:
		t.Fatal("colliding request completed before the stripe was released")
	case <-time.After(time.Second):
	}
	if issuer.attempts.Load() != 1 {
		t.Fatal("collision did not serialize issuance")
	}
	release()
	one, two := cc04Await(t, first), cc04Await(t, second)
	cc04Success(t, issuer, one, cc04Client, "read")
	cc04Success(t, issuer, two, cc04Client, "write")
	if one.token.AccessToken == two.token.AccessToken {
		t.Fatal("collision shared cache identity")
	}
	for _, test := range []struct {
		req               oauth.TokenRequest
		key, scope, token string
	}{
		{a, keyA, "read", one.token.AccessToken}, {b, keyB, "write", two.token.AccessToken},
	} {
		replay := cc04Await(t, g.start(test.req, test.key))
		cc04Success(t, issuer, replay, cc04Client, test.scope)
		if replay.token.AccessToken != test.token {
			t.Fatal("collision corrupted cached replay")
		}
	}
	if issuer.success.Load() != 2 {
		t.Fatal("collision/replay expected exactly two real issuances")
	}
}

type cc04Cache struct {
	core.IdempotentCache
	phase, fault string
	fired        atomic.Bool
	gets, sets   atomic.Int32
}

func (c *cc04Cache) fail(phase string) error {
	if c.phase != phase || !c.fired.CompareAndSwap(false, true) {
		return nil
	}
	if c.fault == "panic" {
		panic("controlled cc04 cache failure")
	}
	return errors.New("controlled cc04 cache error")
}

func (c *cc04Cache) Get(ctx context.Context, key string) ([]byte, bool, error) {
	c.gets.Add(1)
	if err := c.fail("get"); err != nil {
		return nil, false, err
	}
	return c.IdempotentCache.Get(ctx, key)
}

func (c *cc04Cache) Set(ctx context.Context, key string, body []byte, ttl time.Duration) error {
	c.sets.Add(1)
	if err := c.fail("set"); err != nil {
		return err
	}
	return c.IdempotentCache.Set(ctx, key, body, ttl)
}

func TestClientCredentialsIdempotencyFaultsReleaseSameKeyAndCollision(t *testing.T) {
	if cc04Isolate(t) {
		return
	}
	for _, phase := range []string{"get", "issue", "set"} {
		for _, fault := range []string{"panic", "error"} {
			t.Run(phase+"-"+fault, func(t *testing.T) {
				memory := cc04Memory(t)
				cache := &cc04Cache{IdempotentCache: memory, phase: phase, fault: fault}
				issuer := &cc04Issuer{TokenIssuer: defaultimpl.NewEd25519JWTIssuer()}
				var fired atomic.Bool
				if phase == "issue" {
					issuer.before = func(_ *core.Subject, _ []string) error {
						if !fired.CompareAndSwap(false, true) {
							return nil
						}
						if fault == "panic" {
							panic("controlled cc04 issuer failure")
						}
						return errors.New("controlled cc04 issuer error")
					}
				}
				g, _ := newCC04Requests(t, issuer, cache, nil)
				a, b := cc04Request("read"), cc04Request("write")
				keyA, keyB := cc04Pair(t, a, b, true)
				first := cc04Await(t, g.start(a, keyA))
				cc04NoStore(t, first)
				if phase == "issue" || (phase == "get" && fault == "panic") {
					if first.status != http.StatusInternalServerError {
						t.Fatal("failure did not reach existing error/recovery path")
					}
				} else if first.status != http.StatusOK {
					t.Fatal("cache error changed issuance response semantics")
				}
				fullKey := sso.TokenIdempotencyCacheKeyForTest(a.ClientID, keyA, a, "", "")
				_, cached, err := memory.Get(t.Context(), fullKey)
				wantCached := phase == "get" && fault == "error"
				if err != nil || cached != wantCached {
					t.Fatal("failed/unfinished response was cached or healthy Get-error fallback was lost")
				}
				cc04Success(t, issuer, cc04Await(t, g.start(a, keyA)), cc04Client, "read")
				cc04Success(t, issuer, cc04Await(t, g.start(b, keyB)), cc04Client, "write")
				wantSuccess := int32(2)
				if phase == "set" {
					wantSuccess = 3
				}
				if issuer.success.Load() != wantSuccess {
					t.Fatal("fault recovery minted/replayed an unexpected number of real tokens")
				}
			})
		}
	}
}

func cc04Denied(t *testing.T, response cc04Response, status int, code string) {
	t.Helper()
	cc04NoStore(t, response)
	if response.err != nil || response.status != status || response.code != code || response.token.AccessToken != "" {
		t.Fatalf("denial mismatch: status=%d error=%s transport/decode=%v", response.status, response.code, response.err)
	}
}

func TestClientCredentialsIdempotencyDifferentStripesShareTenantQuota(t *testing.T) {
	if cc04Isolate(t) {
		return
	}
	quotas := memorystoreidentity.NewMemoryTenantQuotaStore()
	if err := quotas.SetQuota(t.Context(), "cc04-tenant", &core.TenantQuota{MaxTokenRate: 1}); err != nil {
		t.Fatal(err)
	}
	if err := quotas.IncrementUsage(t.Context(), "cc04-tenant", core.ResourceTokenRate, 59); err != nil {
		t.Fatal(err)
	}
	entered, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(unblock) }) }
	issuer := &cc04Issuer{TokenIssuer: defaultimpl.NewEd25519JWTIssuer()}
	issuer.before = func(_ *core.Subject, scopes []string) error {
		if slices.Equal(scopes, []string{"read"}) {
			close(entered)
			<-unblock
		}
		return nil
	}
	memory := cc04Memory(t)
	g, clients := newCC04Requests(t, issuer, memory, release, sso.WithTenantQuotaStore(quotas))
	client, err := clients.Get(t.Context(), cc04Client)
	if err != nil {
		t.Fatal(err)
	}
	client.TenantID = "cc04-tenant"
	clients.AddSeed(client)
	a, b := cc04Request("read"), cc04Request("write")
	keyA, keyB := cc04Pair(t, a, b, false)
	first := g.start(a, keyA)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("quota-admitted A did not reach controlled issuance")
	}
	denied := cc04Await(t, g.start(b, keyB))
	cc04Denied(t, denied, http.StatusTooManyRequests, "rate_limited")
	if denied.header.Get("Retry-After") != "1" {
		t.Fatal("quota denial lost Retry-After")
	}
	fullKey := sso.TokenIdempotencyCacheKeyForTest(b.ClientID, keyB, b, "", "")
	if _, cached, err := memory.Get(t.Context(), fullKey); err != nil || cached {
		t.Fatal("quota rejection was cached")
	}
	release()
	one := cc04Await(t, first)
	claims := cc04Success(t, issuer, one, cc04Client, "read")
	if claims.TenantID != "cc04-tenant" {
		t.Fatal("tenant binding lost")
	}
	replay := cc04Await(t, g.start(a, keyA))
	cc04Success(t, issuer, replay, cc04Client, "read")
	if replay.token.AccessToken != one.token.AccessToken {
		t.Fatal("quota replay was reissued")
	}
	usage, err := quotas.GetUsage(t.Context(), "cc04-tenant")
	if err != nil || usage.TokenRate != 1 || issuer.success.Load() != 1 {
		t.Fatal("concurrent quota or replay accounting exceeded one remaining unit")
	}
	if err := quotas.DecrementUsage(t.Context(), "cc04-tenant", core.ResourceTokenRate, 1); err != nil {
		t.Fatal(err)
	}
	cc04Success(t, issuer, cc04Await(t, g.start(b, keyB)), cc04Client, "write")
	if issuer.success.Load() != 2 {
		t.Fatal("quota denial poisoned the stripe or cached the error")
	}
}

func TestClientCredentialsIdempotencyCachedAuthorizationAndIdentity(t *testing.T) {
	if cc04Isolate(t) {
		return
	}
	tenants := tenantmemory.New()
	t.Cleanup(func() { _ = tenants.Close() })
	for _, id := range []string{"cc04-a", "cc04-b"} {
		if err := tenants.PutTenant(t.Context(), &tenant.Tenant{ID: id, Slug: id}); err != nil {
			t.Fatal(err)
		}
		if err := tenants.PutDomain(t.Context(), &tenant.Domain{Hostname: id + ".example.test", TenantID: id}); err != nil {
			t.Fatal(err)
		}
	}
	issuer := &cc04Issuer{TokenIssuer: defaultimpl.NewEd25519JWTIssuer()}
	g, clients := newCC04Requests(t, issuer, cc04Memory(t), nil, sso.WithTenantStore(tenants))
	client, err := clients.Get(t.Context(), cc04Client)
	if err != nil {
		t.Fatal(err)
	}
	client.TenantID = "cc04-a"
	client.AllowedResources = []string{"https://api-one.example.test", "https://api-two.example.test"}
	clients.AddSeed(client)
	req := cc04Request("read")
	req.Resource = []string{"https://api-one.example.test"}
	headers := http.Header{"Host": {"cc04-a.example.test"}}
	key := "cached-security"
	first := g.send(req, key, headers)
	claims := cc04Success(t, issuer, first, cc04Client, "read")
	if claims.TenantID != "cc04-a" || !slices.Equal(claims.Audience, req.Resource) {
		t.Fatal("minted tenant/resource identity mismatch")
	}
	bad := req
	bad.ClientSecret = "wrong"
	cc04Denied(t, g.send(bad, key, headers), http.StatusUnauthorized, "invalid_client")
	bad.ClientID = "unknown-client"
	cc04Denied(t, g.send(bad, key, headers), http.StatusUnauthorized, "invalid_client")
	cc04Denied(t, g.send(req, key, http.Header{"Host": {"cc04-b.example.test"}}), http.StatusForbidden, "tenant_mismatch")
	if err := issuer.Revoke(t.Context(), first.token.AccessToken); err != nil {
		t.Fatal("real JWT revoke failed")
	}
	second := g.send(req, key, headers)
	cc04Success(t, issuer, second, cc04Client, "read")
	if first.token.AccessToken == second.token.AccessToken {
		t.Fatal("revoked cached token replayed")
	}
	resource := req
	resource.Resource = []string{"https://api-two.example.test"}
	distinct := g.send(resource, key, headers)
	claims = cc04Success(t, issuer, distinct, cc04Client, "read")
	if !slices.Equal(claims.Audience, resource.Resource) || distinct.token.AccessToken == second.token.AccessToken {
		t.Fatal("resource fingerprints shared a token")
	}
	other := *client
	other.ID = "cc04-other-client"
	clients.AddSeed(&other)
	otherReq := req
	otherReq.ClientID = other.ID
	otherResponse := g.send(otherReq, key, headers)
	cc04Success(t, issuer, otherResponse, other.ID, "read")
	if otherResponse.token.AccessToken == second.token.AccessToken {
		t.Fatal("clients shared cached credentials")
	}
	client.AllowedScopes = []string{"write"}
	clients.AddSeed(client)
	cc04Denied(t, g.send(req, key, headers), http.StatusBadRequest, "invalid_scope")
	client.AllowedScopes = []string{"read", "write"}
	client.GrantTypes = []string{sso.GrantRefreshToken}
	clients.AddSeed(client)
	cc04Denied(t, g.send(req, key, headers), http.StatusBadRequest, "unauthorized_client")
	client.GrantTypes = nil
	client.AllowedResources = []string{"https://api-two.example.test"}
	clients.AddSeed(client)
	cc04Denied(t, g.send(req, key, headers), http.StatusBadRequest, "invalid_target")
	client.Active = false
	clients.AddSeed(client)
	cc04Denied(t, g.send(resource, key, headers), http.StatusUnauthorized, "invalid_client")
	if issuer.success.Load() != 4 {
		t.Fatal("rejected retry minted or replayed an unauthorized response")
	}
}

func TestClientCredentialsIdempotencySenderProofStillRequired(t *testing.T) {
	if cc04Isolate(t) {
		return
	}
	issuer := &cc04Issuer{TokenIssuer: defaultimpl.NewEd25519JWTIssuer()}
	replayStore := defaultimpl.NewMemoryJTIReplayStore()
	t.Cleanup(func() { _ = replayStore.Close() })
	g, _ := newCC04Requests(t, issuer, cc04Memory(t), nil, sso.WithJTIReplayStore(replayStore))
	a, b := rcov2NewDPoPKey(t), rcov2NewDPoPKey(t)
	request, key := cc04Request("read"), "sender-isolation"
	proof := a.proof(t, http.MethodPost, g.url+"/token", "")
	first := g.send(request, key, http.Header{"DPoP": {proof}})
	one := cc04Success(t, issuer, first, cc04Client, "read")
	replay := g.send(request, key, http.Header{"DPoP": {a.proof(t, http.MethodPost, g.url+"/token", "")}})
	cc04Success(t, issuer, replay, cc04Client, "read")
	if replay.token.AccessToken != first.token.AccessToken {
		t.Fatal("fresh proof from same sender did not replay")
	}
	second := g.send(request, key, http.Header{"DPoP": {b.proof(t, http.MethodPost, g.url+"/token", "")}})
	two := cc04Success(t, issuer, second, cc04Client, "read")
	if one.ConfirmationJKT == "" || two.ConfirmationJKT == "" || one.ConfirmationJKT == two.ConfirmationJKT || first.token.AccessToken == second.token.AccessToken {
		t.Fatal("different verified senders shared cached token identity")
	}
	cc04Denied(t, g.send(request, key, http.Header{"DPoP": {"malformed"}}), http.StatusBadRequest, "invalid_dpop_proof")
	cc04Denied(t, g.send(request, key, http.Header{"DPoP": {proof}}), http.StatusBadRequest, "invalid_dpop_proof")
	if issuer.success.Load() != 2 {
		t.Fatal("invalid proof reached cached issuance/replay")
	}
}

func TestClientCredentialsIdempotencyCachedSenderStillNeedsNonce(t *testing.T) {
	if cc04Isolate(t) {
		return
	}
	nonce, err := sso.NewHMACNonceProvider(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &cc04Issuer{TokenIssuer: defaultimpl.NewEd25519JWTIssuer()}
	g, _ := newCC04Requests(t, issuer, cc04Memory(t), nil, sso.WithDPoPNonceProvider(nonce))
	sender := rcov2NewDPoPKey(t)
	request, key := cc04Request("read"), "nonce-retry"
	without := func() http.Header { return http.Header{"DPoP": {sender.proof(t, http.MethodPost, g.url+"/token", "")}} }
	challenge := g.send(request, key, without())
	cc04Denied(t, challenge, http.StatusBadRequest, "use_dpop_nonce")
	value := challenge.header.Get("DPoP-Nonce")
	if value == "" {
		t.Fatal("nonce challenge header missing")
	}
	proof := sender.proof(t, http.MethodPost, g.url+"/token", value)
	cc04Success(t, issuer, g.send(request, key, http.Header{"DPoP": {proof}}), cc04Client, "read")
	cc04Denied(t, g.send(request, key, without()), http.StatusBadRequest, "use_dpop_nonce")
	if issuer.success.Load() != 1 {
		t.Fatal("nonce failure bypassed cached-token security")
	}
}

type cc04CustomGrant struct{ issuer *cc04Issuer }

func (*cc04CustomGrant) GrantType() string { return sso.GrantClientCredentials }
func (h *cc04CustomGrant) Handle(ctx core.HandlerContext, client *core.Client, req oauth.TokenRequest, _, _ string) {
	token, err := h.issuer.Issue(ctx.Request().Context(), &core.Subject{ID: client.ID, ClientID: client.ID}, strings.Fields(req.Scope))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, token)
}

func TestClientCredentialsIdempotencyBypassPaths(t *testing.T) {
	if cc04Isolate(t) {
		return
	}
	for _, mode := range []string{"nil-cache", "no-header", "custom-cc"} {
		t.Run(mode, func(t *testing.T) {
			issuer := &cc04Issuer{TokenIssuer: defaultimpl.NewEd25519JWTIssuer()}
			cache := &cc04Cache{IdempotentCache: cc04Memory(t)}
			var store core.IdempotentCache = cache
			key := "bypass-retry"
			var opts []sso.Option
			if mode == "nil-cache" {
				store = nil
			}
			if mode == "no-header" {
				key = ""
			}
			if mode == "custom-cc" {
				opts = append(opts, sso.WithCustomGrant(&cc04CustomGrant{issuer: issuer}))
			}
			g, _ := newCC04Requests(t, issuer, store, nil, opts...)
			one := cc04Await(t, g.start(cc04Request("read"), key))
			two := cc04Await(t, g.start(cc04Request("read"), key))
			cc04Success(t, issuer, one, cc04Client, "read")
			cc04Success(t, issuer, two, cc04Client, "read")
			if issuer.success.Load() != 2 || one.token.AccessToken == two.token.AccessToken || cache.gets.Load() != 0 || cache.sets.Load() != 0 {
				t.Fatal("bypass path entered CC response cache coordination")
			}
		})
	}
}
