package remote

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient"
)

const (
	defaultBrowserFlowTTL     = 10 * time.Minute
	defaultBrowserStateLimit  = 10_000
	defaultBrowserStateCookie = "snaplink_oauth_state"
)

// AuthorizationStateStore persists short-lived state and PKCE verifiers.
// Consume must atomically return and delete a state so callbacks cannot replay.
type AuthorizationStateStore interface {
	Save(ctx context.Context, state, verifier string, expiresAt time.Time) error
	Consume(ctx context.Context, state string) (verifier string, found bool, err error)
}

type browserState struct {
	verifier string
	expires  time.Time
}

type memoryAuthorizationStateStore struct {
	mu     sync.Mutex
	states map[string]browserState
	limit  int
}

func newMemoryAuthorizationStateStore(limit int) *memoryAuthorizationStateStore {
	return &memoryAuthorizationStateStore{states: make(map[string]browserState), limit: limit}
}

func (s *memoryAuthorizationStateStore) Save(
	_ context.Context, state, verifier string, expiresAt time.Time,
) error {
	if state == "" || verifier == "" {
		return errors.New("ssoclient/remote: state and PKCE verifier required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeExpired(time.Now())
	if len(s.states) >= s.limit {
		return errors.New("ssoclient/remote: authorization state capacity exceeded")
	}
	s.states[state] = browserState{verifier: verifier, expires: expiresAt}
	return nil
}

func (s *memoryAuthorizationStateStore) Consume(
	_ context.Context, state string,
) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	flow, ok := s.states[state]
	delete(s.states, state)
	if !ok || time.Now().After(flow.expires) {
		return "", false, nil
	}
	return flow.verifier, true, nil
}

func (s *memoryAuthorizationStateStore) removeExpired(now time.Time) {
	for state, flow := range s.states {
		if now.After(flow.expires) {
			delete(s.states, state)
		}
	}
}

// BrowserFlow owns the reusable HTTP mechanics of Authorization Code + PKCE.
// Apps remain responsible for routing and handling the successful token result.
type BrowserFlow struct {
	tokens     *TokenClient
	store      AuthorizationStateStore
	scopes     []string
	cookieName string
	cookiePath string
	ttl        time.Duration
	secure     bool
}

type BrowserOption func(*BrowserFlow)

func WithBrowserStateStore(store AuthorizationStateStore) BrowserOption {
	return func(flow *BrowserFlow) {
		if store != nil {
			flow.store = store
		}
	}
}

func WithBrowserScopes(scopes ...string) BrowserOption {
	return func(flow *BrowserFlow) { flow.scopes = append([]string(nil), scopes...) }
}

func WithBrowserCookie(name, path string) BrowserOption {
	return func(flow *BrowserFlow) {
		if name != "" {
			flow.cookieName = name
		}
		if path != "" {
			flow.cookiePath = path
		}
	}
}

func WithBrowserFlowTTL(ttl time.Duration) BrowserOption {
	return func(flow *BrowserFlow) {
		if ttl > 0 {
			flow.ttl = ttl
		}
	}
}

func NewBrowserFlow(tokens *TokenClient, options ...BrowserOption) (*BrowserFlow, error) {
	if tokens == nil {
		return nil, errors.New("ssoclient/remote: token client required")
	}
	redirect, err := url.Parse(tokens.redirectURI)
	if err != nil || redirect.Scheme == "" || redirect.Host == "" {
		return nil, errors.New("ssoclient/remote: absolute redirect URI required")
	}
	flow := &BrowserFlow{
		tokens: tokens, store: newMemoryAuthorizationStateStore(defaultBrowserStateLimit),
		cookieName: defaultBrowserStateCookie, cookiePath: "/",
		ttl: defaultBrowserFlowTTL, secure: redirect.Scheme == "https",
	}
	for _, option := range options {
		option(flow)
	}
	return flow, nil
}

func (f *BrowserFlow) Begin(w http.ResponseWriter, r *http.Request) error {
	f.noStore(w)
	state, err := randomBrowserToken(32)
	if err != nil {
		return err
	}
	target, verifier, err := f.tokens.AuthorizationCodeURL(state, f.scopes...)
	if err != nil {
		return err
	}
	if err := f.store.Save(r.Context(), state, verifier, time.Now().Add(f.ttl)); err != nil {
		return err
	}
	f.setStateCookie(w, state, int(f.ttl.Seconds()))
	http.Redirect(w, r, target, http.StatusFound)
	return nil
}

func (f *BrowserFlow) Callback(w http.ResponseWriter, r *http.Request) (*ssoclient.TokenResponse, error) {
	f.noStore(w)
	defer f.clearStateCookie(w)
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie(f.cookieName)
	if err != nil || !sameBrowserState(state, cookie.Value) {
		return nil, ssoclient.ErrInvalidAuthorizationFlow
	}
	verifier, found, err := f.store.Consume(r.Context(), state)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ssoclient.ErrInvalidAuthorizationFlow
	}
	if code := r.URL.Query().Get("error"); code != "" {
		return nil, &ssoclient.AuthorizationError{
			Code: code, Description: r.URL.Query().Get("error_description"),
		}
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, ssoclient.ErrInvalidAuthorizationFlow
	}
	return f.tokens.ExchangeCode(r.Context(), code, verifier)
}

func sameBrowserState(state, cookie string) bool {
	if state == "" || cookie == "" || len(state) != len(cookie) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(state), []byte(cookie)) == 1
}

func (f *BrowserFlow) setStateCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: f.cookieName, Value: value, Path: f.cookiePath,
		HttpOnly: true, Secure: f.secure, SameSite: http.SameSiteLaxMode,
		MaxAge: maxAge,
	})
}

func (f *BrowserFlow) clearStateCookie(w http.ResponseWriter) {
	f.setStateCookie(w, "", -1)
}

func (f *BrowserFlow) noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func randomBrowserToken(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
