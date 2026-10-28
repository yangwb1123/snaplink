package ssotest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/internal/handler/tokengrant"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

type observedRefreshStore struct {
	*defaultimpl.MemoryRefreshTokenStore
	reused chan struct{}
	trace  *inflightTrace
}

func (s *observedRefreshStore) Consume(ctx context.Context, token string) (*oauth.RefreshToken, error) {
	defer s.trace.finish(s.trace.begin(inflightConsume))
	info, err := s.MemoryRefreshTokenStore.Consume(ctx, token)
	if errors.Is(err, oauth.ErrRefreshTokenReused) {
		select {
		case s.reused <- struct{}{}:
			s.trace.mark(inflightReuseSent)
		default:
		}
	}
	return info, err
}

type blockedRefreshIssuer struct {
	core.TokenIssuer
	first   atomic.Bool
	entered chan struct{}
	release chan struct{}
	trace   *inflightTrace
}

func (i *blockedRefreshIssuer) Issue(ctx context.Context, subject *core.Subject, scopes []string) (*core.Token, error) {
	defer i.trace.finish(i.trace.begin(inflightIssue))
	if i.first.CompareAndSwap(false, true) {
		i.trace.mark(inflightIssuerEntered)
		close(i.entered)
		select {
		case <-i.release:
			i.trace.mark(inflightIssuerReleased)
		case <-ctx.Done():
			i.trace.mark(inflightIssuerCanceled)
			return nil, ctx.Err()
		}
	}
	defer i.trace.finish(i.trace.begin(inflightSigning))
	return i.TokenIssuer.Issue(ctx, subject, scopes)
}

type inflightResponse struct {
	status int
	body   map[string]any
	raw    string
	err    error
}

func postInflightRefresh(url, clientID string) inflightResponse {
	return postInflightRefreshContext(context.Background(), url, clientID)
}

func postInflightRefreshContext(ctx context.Context, url, clientID string) inflightResponse {
	return postNamedRefresh(ctx, url, clientID, "original")
}

func postNamedRefresh(ctx context.Context, url, clientID, token string) inflightResponse {
	payload, _ := json.Marshal(map[string]string{"grant_type": "refresh_token", "refresh_token": token})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/token", strings.NewReader(string(payload)))
	if err != nil {
		return inflightResponse{err: err}
	}
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth(clientID, rfSecret)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		return inflightResponse{err: err}
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return inflightResponse{err: err}
	}
	var body map[string]any
	err = json.Unmarshal(data, &body)
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Pragma") != "no-cache" {
		err = errors.New("credential response omitted no-store headers")
	}
	return inflightResponse{status: response.StatusCode, body: body, raw: string(data), err: err}
}

type completedOnlyGraceStore struct{ store tokengrant.RefreshGraceStore }

func (s completedOnlyGraceStore) Remember(token string, body map[string]any, now time.Time) {
	s.store.Remember(token, body, now)
}

func (s completedOnlyGraceStore) Lookup(token string, now time.Time) (map[string]any, bool) {
	return s.store.Lookup(token, now)
}

func newInflightServers(t *testing.T, grace tokengrant.RefreshGraceStore) (*httptest.Server, *httptest.Server, *observedRefreshStore, *blockedRefreshIssuer) {
	t.Helper()
	trace := newInflightTrace()
	clients := defaultimpl.NewMemoryClientStore()
	for _, id := range []string{rfClientID, "other-client"} {
		clients.AddSeed(&sso.Client{ID: id, Secret: rfSecret, Active: true, TokenStrategy: "jwt"})
	}
	store := &observedRefreshStore{MemoryRefreshTokenStore: defaultimpl.NewMemoryRefreshTokenStore(), reused: make(chan struct{}, 1), trace: trace}
	for _, token := range []string{"original", "probe"} {
		if err := store.Issue(t.Context(), token, &oauth.RefreshToken{UserID: rfUser, ClientID: rfClientID, FamilyID: "family", Scopes: []string{"read"}, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	issuer := &blockedRefreshIssuer{TokenIssuer: defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute)), entered: make(chan struct{}), release: make(chan struct{}), trace: trace}
	opts := []sso.Option{sso.WithClientStore(&inflightTraceClients{MemoryClientStore: clients, trace: trace}), sso.WithTokenIssuer("jwt", issuer), sso.WithDefaultTokenStrategy("jwt"), sso.WithRefreshTokenStore(store, time.Hour), sso.WithRefreshRotationGraceStore(traceInflightGrace(grace, trace))}
	first := httptest.NewServer(traceInflightHandler(trace, inflightFirstHTTP, sso.NewServer(opts...).Handler()))
	second := httptest.NewServer(traceInflightHandler(trace, inflightSecondHTTP, sso.NewServer(opts...).Handler()))
	t.Cleanup(first.Close)
	t.Cleanup(second.Close)
	t.Cleanup(func() { trace.report(t.Failed(), t.Logf) })
	return first, second, store, issuer
}

func TestRefreshGraceInflightAcrossServers(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite", "redis", "postgres"} {
		for _, mode := range []string{"completed-during-wait", "bounded-pending", "canceled-pending", "wrong-client", "expired-pending", "feature-off", "legacy-store"} {
			t.Run(backend+"/"+mode, func(t *testing.T) {
				window := time.Minute
				if mode == "expired-pending" {
					window = 40 * time.Millisecond
				}
				grace, _ := newGraceBackend(t, backend, window)
				if mode == "feature-off" {
					grace = nil
				} else if mode == "legacy-store" {
					grace = completedOnlyGraceStore{store: grace}
				}
				first, second, store, issuer := newInflightServers(t, grace)
				trace := issuer.trace
				baselinePhase := trace.begin(inflightBaselineRequest)
				baseline := postNamedRefresh(t.Context(), second.URL, rfClientID, "missing")
				trace.finish(baselinePhase)
				if baseline.err != nil || baseline.status != http.StatusBadRequest || baseline.body[core.KeyError] != core.ErrInvalidGrant {
					t.Fatal("unknown refresh did not return the oracle-safe baseline")
				}
				var release sync.Once
				unblock := func() {
					release.Do(func() {
						phase := trace.begin(inflightFixtureRelease)
						close(issuer.release)
						trace.finish(phase)
					})
				}
				defer unblock()
				winner := make(chan inflightResponse, 1)
				trace.mark(inflightWinnerLaunch)
				go func() {
					phase := trace.begin(inflightWinnerRequest)
					response := postInflightRefresh(first.URL, rfClientID)
					trace.finish(phase)
					winner <- response
				}()
				select {
				case <-issuer.entered:
					trace.mark(inflightIssuerObserved)
				case <-time.After(3 * time.Second):
					t.Fatal("winner did not reach blocked issuance")
				}
				if mode == "expired-pending" {
					time.Sleep(80 * time.Millisecond)
				}
				client := rfClientID
				if mode == "wrong-client" {
					client = "other-client"
				}
				loser := make(chan inflightResponse, 1)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				trace.mark(inflightLoserLaunch)
				go func() {
					phase := trace.begin(inflightLoserRequest)
					response := postInflightRefreshContext(ctx, second.URL, client)
					trace.finish(phase)
					loser <- response
				}()
				select {
				case <-store.reused:
					trace.mark(inflightReuseObserved)
				case <-time.After(3 * time.Second):
					t.Fatal("loser did not observe atomic consume reuse")
				}
				if mode == "completed-during-wait" {
					unblock()
				} else if mode == "canceled-pending" {
					cancel()
				}
				other := <-loser
				if mode == "canceled-pending" && !errors.Is(other.err, context.Canceled) {
					t.Fatal("canceled retry did not honor its request context")
				}
				if mode != "canceled-pending" && other.err != nil {
					t.Fatal(other.err)
				}
				if mode != "completed-during-wait" && mode != "canceled-pending" && (other.status != http.StatusBadRequest || other.raw != baseline.raw) {
					t.Fatalf("incomplete/invalid request = %d", other.status)
				}
				if mode == "wrong-client" || mode == "expired-pending" || mode == "feature-off" || mode == "legacy-store" {
					if _, err := store.Inspect(t.Context(), "probe"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
						t.Fatal("invalid pending evidence suppressed family revocation")
					}
					unblock()
					<-winner
					return
				}
				if _, err := store.Inspect(t.Context(), "probe"); err != nil {
					t.Fatal("valid in-flight intent did not preserve the family")
				}
				unblock()
				issued := <-winner
				if issued.err != nil || issued.status != http.StatusOK || issued.body[core.KeyRefreshToken] == nil {
					t.Fatalf("valid winner lost its refresh family: status=%d err=%v", issued.status, issued.err)
				}
				if mode == "completed-during-wait" && (other.status != http.StatusOK || other.body[core.KeyRefreshToken] != issued.body[core.KeyRefreshToken]) {
					t.Fatal("concurrent retry did not replay the completed successor")
				}
				retryPhase := trace.begin(inflightRetryRequest)
				retry := postInflightRefresh(second.URL, rfClientID)
				trace.finish(retryPhase)
				if retry.err != nil || retry.status != http.StatusOK || retry.body[core.KeyRefreshToken] != issued.body[core.KeyRefreshToken] {
					t.Fatal("bounded pending denial killed the valid family")
				}
				for key := range retry.body {
					if strings.HasPrefix(key, "_grant_") {
						t.Fatal("internal intent leaked into token response")
					}
				}
			})
		}
	}
}
