package authenticators

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// TempTokenStore stores opaque, single-use tokens that map to a subject identity.
type TempTokenStore interface {
	Issue(ctx context.Context, token string, subject *sso.Subject, ttl time.Duration) error
	Consume(ctx context.Context, token string) (*sso.Subject, error)
}

// tempTokenSweepInterval bounds how stale the in-process entry map may grow.
// Abandoned or expired tokens are purged by a write-path sweep at most this
// often, so repeated Issue calls cannot leak memory without bound while keeping
// the sweep cost amortized and off the hot read path.
const tempTokenSweepInterval = time.Minute

// MemoryTempTokenStore is a process-local TempTokenStore.
type MemoryTempTokenStore struct {
	mu        sync.Mutex
	entries   map[string]tempEntry
	nextSweep atomic.Int64 // unix nanos; CAS gate so only one writer sweeps per interval
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
	now := time.Now()
	m.maybeSweepLocked(now)
	m.entries[token] = tempEntry{subject: cloneSubject(subject), expiresAt: now.Add(ttl)}
	return nil
}

func cloneSubject(subject *sso.Subject) *sso.Subject {
	if subject == nil {
		return nil
	}
	clone := *subject
	clone.Claims = maps.Clone(subject.Claims)
	clone.Resources = slices.Clone(subject.Resources)
	clone.AMR = slices.Clone(subject.AMR)
	clone.AuthorizationDetails = slices.Clone(subject.AuthorizationDetails)
	clone.Roles = slices.Clone(subject.Roles)
	clone.RequestedClaims = slices.Clone(subject.RequestedClaims)
	clone.Actor = cloneActorClaim(subject.Actor, make(map[*sso.ActorClaim]*sso.ActorClaim))
	return &clone
}

func cloneActorClaim(actor *sso.ActorClaim, seen map[*sso.ActorClaim]*sso.ActorClaim) *sso.ActorClaim {
	if actor == nil {
		return nil
	}
	if clone, ok := seen[actor]; ok {
		return clone
	}
	clone := &sso.ActorClaim{Subject: actor.Subject}
	seen[actor] = clone
	clone.Actor = cloneActorClaim(actor.Actor, seen)
	return clone
}

func (m *MemoryTempTokenStore) Consume(_ context.Context, token string) (*sso.Subject, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maybeSweepLocked(time.Now())
	e, ok := m.entries[token]
	delete(m.entries, token)
	if !ok || time.Since(e.expiresAt) > 0 {
		return nil, ErrCodeInvalid
	}
	return e.subject, nil
}

// maybeSweepLocked purges entries expired strictly before now. Callers must hold
// mu. The atomic gate lets exactly one writer per interval run the sweep; every
// other writer skips so the O(n) purge stays amortized.
func (m *MemoryTempTokenStore) maybeSweepLocked(now time.Time) {
	next := m.nextSweep.Load()
	if now.UnixNano() < next {
		return
	}
	if !m.nextSweep.CompareAndSwap(next, now.Add(tempTokenSweepInterval).UnixNano()) {
		return // another writer already claimed this interval's sweep
	}
	for k, e := range m.entries {
		if e.expiresAt.Before(now) {
			delete(m.entries, k)
		}
	}
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
