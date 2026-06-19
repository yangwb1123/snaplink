package consent

import (
	"crypto/rand"
	"encoding/base64"
	"slices"
	"sync"
	"time"
)

// ChallengeTTL is the lifetime of a server-issued consent challenge.
// The SPA must present the challenge ID within this window.
const ChallengeTTL = 5 * time.Minute

// Challenge is a short-lived server-issued token that binds a consent gate
// decision to a specific (UserID, ClientID, Scopes) tuple. The SPA must
// present the challenge ID back in the next /auth/login call instead of a
// bare consent_approved boolean — this proves the AS computed the need for
// consent before accepting the approval signal.
type Challenge struct {
	UserID    string
	ClientID  string
	Scopes    []string
	ExpiresAt time.Time
}

// ChallengeStore holds server-issued single-use consent challenge tokens.
// Each entry is bound to (UserID, ClientID, Scopes) and expires after
// ChallengeTTL. Thread-safe.
type ChallengeStore struct {
	mu         sync.Mutex
	challenges map[string]*Challenge
}

// NewChallengeStore returns an initialized ChallengeStore.
func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{}
}

// Issue generates and stores a single-use challenge bound to
// (userID, clientID, scopes). Returns the opaque challenge ID.
func (s *ChallengeStore) Issue(userID, clientID string, scopes []string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := base64.RawURLEncoding.EncodeToString(b)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.challenges == nil {
		s.challenges = make(map[string]*Challenge)
	}
	s.challenges[id] = &Challenge{
		UserID:    userID,
		ClientID:  clientID,
		Scopes:    slices.Clone(scopes),
		ExpiresAt: time.Now().Add(ChallengeTTL),
	}
	return id
}

// Consume validates and atomically removes the challenge with the given ID.
// Returns true only if the challenge exists, matches (userID, clientID,
// exact scopes), and has not expired.
func (s *ChallengeStore) Consume(id, userID, clientID string, scopes []string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.challenges == nil {
		return false
	}

	now := time.Now()
	for k, v := range s.challenges {
		if now.After(v.ExpiresAt) {
			delete(s.challenges, k)
		}
	}

	ch, ok := s.challenges[id]
	if !ok || now.After(ch.ExpiresAt) {
		return false
	}
	if ch.UserID != userID || ch.ClientID != clientID || !ScopesMatch(ch.Scopes, scopes) {
		return false
	}
	delete(s.challenges, id)
	return true
}
