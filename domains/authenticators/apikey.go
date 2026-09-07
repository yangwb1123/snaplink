package authenticators

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// APIKeyResolver looks up the secret hash + identity bound to an API key ID.
// Stored secrets MUST be hashed (sha256 or stronger).
type APIKeyResolver interface {
	Resolve(ctx context.Context, keyID string) (secretHash []byte, subject *sso.Subject, err error)
}

// MemoryAPIKeyStore is a process-local APIKeyResolver. Hashes secrets on registration
// and snapshots the associated identity so callers cannot mutate auth state.
type MemoryAPIKeyStore struct {
	mu      sync.RWMutex
	entries map[string]apiKeyEntry
}

type apiKeyEntry struct {
	hash    []byte
	subject *sso.Subject
}

func NewMemoryAPIKeyStore() *MemoryAPIKeyStore {
	return &MemoryAPIKeyStore{entries: make(map[string]apiKeyEntry)}
}

// Register stores a key/secret pair. The secret is hashed and not retained in plaintext.
func (s *MemoryAPIKeyStore) Register(keyID, secret string, subject *sso.Subject) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := sha256.Sum256([]byte(secret))
	s.entries[keyID] = apiKeyEntry{
		hash:    append([]byte(nil), h[:]...),
		subject: cloneSubject(subject),
	}
}

func (s *MemoryAPIKeyStore) Resolve(_ context.Context, keyID string) ([]byte, *sso.Subject, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[keyID]
	if !ok {
		return nil, nil, errors.New("apikey: unknown key_id")
	}
	return append([]byte(nil), e.hash...), cloneSubject(e.subject), nil
}

// APIKeyAuthenticator authenticates a client by a (key_id, secret) pair —
// the simplest "key/value" credential. Secret comparison is constant-time.
type APIKeyAuthenticator struct {
	resolver APIKeyResolver
}

func NewAPIKeyAuthenticator(resolver APIKeyResolver) *APIKeyAuthenticator {
	return &APIKeyAuthenticator{resolver: resolver}
}

func (a *APIKeyAuthenticator) Name() string { return MethodAPIKey }

func (a *APIKeyAuthenticator) Authenticate(ctx context.Context, req *sso.AuthRequest) (*sso.AuthResult, error) {
	keyID := req.Credential["key_id"]
	secret := req.Credential["secret"]
	if keyID == "" || secret == "" {
		return nil, errors.New("apikey: key_id and secret required")
	}
	hash, subject, err := a.resolver.Resolve(ctx, keyID)
	if err != nil {
		return nil, err
	}
	got := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(hash, got[:]) != 1 {
		return nil, errors.New("apikey: invalid secret")
	}
	if subject == nil {
		subject = &sso.Subject{ID: subjectPrefixAPIKey + keyID}
	}
	return &sso.AuthResult{
		UserID:      subject.ID,
		ExternalID:  keyID,
		Provider:    a.Name(),
		Attributes:  subject.Claims,
		AuthMethods: []string{AuthMethodAPIKey},
	}, nil
}

func (a *APIKeyAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, fmt.Errorf("apikey: callback not supported")
}

func (a *APIKeyAuthenticator) LoginURL(_ string) string { return "" }
