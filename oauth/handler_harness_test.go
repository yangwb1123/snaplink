package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/security"
)

// This file holds REAL in-memory store implementations + a HandlerContext
// builder shared by the handler-level tests in this package. They are NOT
// mocks: each store is a functioning in-memory implementation of the SPI
// (the oauth package cannot import defaultimpl — defaultimpl imports oauth,
// so a defaultimpl reference would cycle). The behavior mirrors the
// production Memory* stores: single-use Consume, atomic delete, oracle-safe
// not-found sentinels.

// ctFormURLEncoded is the OAuth wire content type. core has no constant for
// it, so the tests carry their own (BindParams matches the literal).
const ctFormURLEncoded = "application/x-www-form-urlencoded"

// newCtx builds a real *core.Context backed by an httptest recorder. The
// body + content-type drive BindParams.
func newCtx(method, contentType, body string) (*core.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, "/", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set(core.HeaderContentType, contentType)
	}
	rec := httptest.NewRecorder()
	return core.NewContext(rec, req), rec
}

// decodeBody decodes the recorder JSON body into a generic map.
func decodeBody(t interface{ Fatalf(string, ...any) }, rec *httptest.ResponseRecorder) map[string]any {
	out := map[string]any{}
	b, _ := io.ReadAll(rec.Body)
	if len(bytes.TrimSpace(b)) == 0 {
		return out
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode body %q: %v", string(b), err)
	}
	return out
}

// --- in-memory ClientStore -------------------------------------------------

type memClientStore struct {
	mu      sync.Mutex
	clients map[string]*core.Client
	secrets map[string]string
}

func newMemClientStore() *memClientStore {
	return &memClientStore{
		clients: map[string]*core.Client{},
		secrets: map[string]string{},
	}
}

// put registers a client with the given plaintext secret.
func (s *memClientStore) put(c *core.Client, secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID] = c
	s.secrets[c.ID] = secret
}

func (s *memClientStore) Get(_ context.Context, id string) (*core.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return nil, core.ErrNoSuchClient
	}
	return c, nil
}

func (s *memClientStore) ValidateSecret(_ context.Context, id, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	want, ok := s.secrets[id]
	if !ok {
		return core.ErrNoSuchClient
	}
	if want != secret {
		return errors.New("oauth_test: bad secret")
	}
	return nil
}

func (s *memClientStore) List(_ context.Context) ([]*core.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*core.Client, 0, len(s.clients))
	for _, c := range s.clients {
		out = append(out, c)
	}
	return out, nil
}

func (s *memClientStore) Add(_ context.Context, c *core.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[c.ID]; ok {
		return core.ErrClientExists
	}
	s.clients[c.ID] = c
	return nil
}

func (s *memClientStore) Update(_ context.Context, c *core.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[c.ID]; !ok {
		return core.ErrNoSuchClient
	}
	s.clients[c.ID] = c
	return nil
}

func (s *memClientStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, id)
	delete(s.secrets, id)
	return nil
}

func (s *memClientStore) RotateSecret(_ context.Context, id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[id]; !ok {
		return "", core.ErrNoSuchClient
	}
	ns := "rotated-" + id
	s.secrets[id] = ns
	return ns, nil
}

var _ core.ClientStore = (*memClientStore)(nil)

// --- in-memory PARStore ----------------------------------------------------

type memPARStore struct {
	mu      sync.Mutex
	entries map[string]*PARRequest
	seq     int
	issErr  error // forced error from Issue for the failure-path test
}

func newMemPARStore() *memPARStore { return &memPARStore{entries: map[string]*PARRequest{}} }

func (s *memPARStore) Issue(_ context.Context, req *PARRequest) (string, error) {
	if s.issErr != nil {
		return "", s.issErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	uri := PARURIPrefix + "tok" + itoa(s.seq)
	cp := *req
	s.entries[uri] = &cp
	return uri, nil
}

func (s *memPARStore) Consume(_ context.Context, uri string) (*PARRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[uri]
	if !ok || e.IsExpired() {
		delete(s.entries, uri)
		return nil, ErrPARNotFound
	}
	delete(s.entries, uri)
	return e, nil
}

var _ PARStore = (*memPARStore)(nil)

// --- in-memory RefreshTokenStore (+ inspector + subject index) -------------

// memRefreshStore implements RefreshTokenStore plus the optional inspector
// and subject-index extensions, so introspection / revocation / revoke-all
// exercise the full path.
type memRefreshStore struct {
	mu      sync.Mutex
	entries map[string]*RefreshToken
}

func newMemRefreshStore() *memRefreshStore {
	return &memRefreshStore{entries: map[string]*RefreshToken{}}
}

func (s *memRefreshStore) Issue(_ context.Context, token string, info *RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *info
	s.entries[token] = &cp
	return nil
}

func (s *memRefreshStore) Consume(_ context.Context, token string) (*RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[token]
	if !ok {
		return nil, ErrRefreshTokenNotFound
	}
	delete(s.entries, token)
	return e, nil
}

func (s *memRefreshStore) Inspect(_ context.Context, token string) (*RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[token]
	if !ok || e.IsExpired() {
		return nil, ErrRefreshTokenNotFound
	}
	return e, nil
}

func (s *memRefreshStore) Delete(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, token)
	return nil
}

func (s *memRefreshStore) DeleteAllForSubject(_ context.Context, userID, clientID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for tok, e := range s.entries {
		if e.UserID == userID && (clientID == "" || e.ClientID == clientID) {
			delete(s.entries, tok)
			n++
		}
	}
	return n, nil
}

var (
	_ RefreshTokenStore        = (*memRefreshStore)(nil)
	_ RefreshTokenInspector    = (*memRefreshStore)(nil)
	_ RefreshTokenSubjectIndex = (*memRefreshStore)(nil)
)

// bareRefresh implements ONLY RefreshTokenStore — no inspector, no subject
// index — so the handler "extension not implemented" fallbacks
// (introspectRefresh → false, revokeRefresh → no-op, revoke-all → 501)
// are exercised.
type bareRefresh struct {
	mu      sync.Mutex
	entries map[string]*RefreshToken
}

func newBareRefresh() *bareRefresh { return &bareRefresh{entries: map[string]*RefreshToken{}} }

func (b *bareRefresh) Issue(_ context.Context, t string, i *RefreshToken) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := *i
	b.entries[t] = &cp
	return nil
}

func (b *bareRefresh) Consume(_ context.Context, t string) (*RefreshToken, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.entries[t]
	if !ok {
		return nil, ErrRefreshTokenNotFound
	}
	delete(b.entries, t)
	return e, nil
}

var _ RefreshTokenStore = (*bareRefresh)(nil)

// --- in-memory CIBAStore ---------------------------------------------------

type memCIBAStore struct {
	mu      sync.Mutex
	entries map[string]*CIBARequest
	seq     int
	issErr  error // forced Issue failure for the failure-path test
}

func newMemCIBAStore() *memCIBAStore { return &memCIBAStore{entries: map[string]*CIBARequest{}} }

func (s *memCIBAStore) Issue(_ context.Context, req *CIBARequest) (string, error) {
	if s.issErr != nil {
		return "", s.issErr
	}
	if req.SubjectID == "" || req.ClientID == "" {
		return "", ErrCIBARequestInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	id := AuthReqIDPrefix + itoa(s.seq)
	cp := *req
	cp.AuthReqID = id
	s.entries[id] = &cp
	return id, nil
}

func (s *memCIBAStore) Get(_ context.Context, id string) (*CIBARequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok || e.IsExpired() {
		return nil, ErrCIBARequestNotFound
	}
	return e, nil
}

func (s *memCIBAStore) SetStatus(_ context.Context, id string, status CIBAStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return ErrCIBARequestNotFound
	}
	if e.Status != CIBAPending {
		return ErrCIBARequestResolved
	}
	e.Status = status
	return nil
}

func (s *memCIBAStore) UpdateLastPoll(_ context.Context, id string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[id]; ok {
		e.LastPoll = t
	}
	return nil
}

func (s *memCIBAStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, id)
	return nil
}

var _ CIBAStore = (*memCIBAStore)(nil)

// --- in-memory JTIReplayStore ----------------------------------------------

type memJTIStore struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func newMemJTIStore() *memJTIStore { return &memJTIStore{seen: map[string]struct{}{}} }

func (s *memJTIStore) MarkSeen(_ context.Context, jti string, _ time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[jti]; ok {
		return false, nil
	}
	s.seen[jti] = struct{}{}
	return true, nil
}

var _ security.JTIReplayStore = (*memJTIStore)(nil)

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
