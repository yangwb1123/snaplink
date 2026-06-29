package authenticators

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
)

// TempTokenStore stores opaque, single-use tokens that map to a subject identity.
type TempTokenStore interface {
	Issue(ctx context.Context, token string, subject *sso.Subject, ttl time.Duration) error
	Consume(ctx context.Context, token string) (*sso.Subject, error)
}

// MemoryTempTokenStore is a process-local TempTokenStore.
type MemoryTempTokenStore struct {
	mu      sync.Mutex
	entries map[string]tempEntry
}

type tempEntry struct {
	subject   *sso.Subject
	expiresAt time.Time
}

func NewMemoryTempTokenStore() *MemoryTempTokenStore {
	return &MemoryTempTokenStore{entries: make(map[string]tempEntry)}
}

func (m *MemoryTempTokenStore) Issue(_ context.Context, token string, subject *sso.Subject, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[token] = tempEntry{subject: subject, expiresAt: time.Now().Add(ttl)}
	return nil
}

func (m *MemoryTempTokenStore) Consume(_ context.Context, token string) (*sso.Subject, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[token]
	delete(m.entries, token)
	if !ok || time.Since(e.expiresAt) > 0 {
		return nil, ErrCodeInvalid
	}
	return e.subject, nil
}

// TempTokenAuthenticator authenticates the bearer of a one-time, opaque token.
// Use it for magic links, password reset confirmations, device transfer codes,
// or service-to-user handoff.
type TempTokenAuthenticator struct {
	store TempTokenStore
	ttl   time.Duration
}

func NewTempTokenAuthenticator(store TempTokenStore, ttl time.Duration) *TempTokenAuthenticator {
	if ttl <= 0 {
		ttl = DefaultTempTokenTTL
	}
	return &TempTokenAuthenticator{store: store, ttl: ttl}
}

func (t *TempTokenAuthenticator) Name() string { return MethodTempToken }

// Issue mints a fresh single-use token bound to the given subject.
func (t *TempTokenAuthenticator) Issue(ctx context.Context, subject *sso.Subject) (string, error) {
	if subject == nil || subject.ID == "" {
		return "", errors.New("temp_token: subject required")
	}
	buf := make([]byte, DefaultTempTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("temp_token: generate: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	if err := t.store.Issue(ctx, token, subject, t.ttl); err != nil {
		return "", fmt.Errorf("temp_token: store: %w", err)
	}
	return token, nil
}

func (t *TempTokenAuthenticator) Authenticate(ctx context.Context, req *sso.AuthRequest) (*sso.AuthResult, error) {
	token := req.Credential["token"]
	if token == "" {
		return nil, errors.New("temp_token: token required")
	}
	subject, err := t.store.Consume(ctx, token)
	if err != nil {
		return nil, err
	}
	return &sso.AuthResult{
		UserID:      subject.ID,
		Provider:    t.Name(),
		Attributes:  subject.Claims,
		AuthMethods: []string{AuthMethodOTPLink},
	}, nil
}

func (t *TempTokenAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, errors.New("temp_token: callback not supported")
}

func (t *TempTokenAuthenticator) LoginURL(_ string) string { return "" }
