package consent

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"slices"
	"sync"
	"time"
)

// ChallengeTTL is the lifetime of a server-issued consent challenge.
// The SPA must present the challenge ID within this window.
const ChallengeTTL = 5 * time.Minute

// Challenge is a short-lived server-issued token that binds a consent gate
// decision to a specific (UserID, ClientID, Scopes, AuthorizationDetails)
// tuple. The SPA must present the challenge ID back in the next /auth/login
// call — this proves the AS computed the need for consent before accepting
// the approval signal. AuthorizationDetails is included so a client cannot
// change the RAR payload between the consent prompt and the re-POST (RFC 9396
// §7 modification-of-authorization_details threat).
type Challenge struct {
	UserID               string
	ClientID             string
	Scopes               []string
	AuthorizationDetails json.RawMessage
	ExpiresAt            time.Time
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
// (userID, clientID, scopes, authorizationDetails). Returns the opaque
// challenge ID.
func (s *ChallengeStore) Issue(userID, clientID string, scopes []string, authorizationDetails json.RawMessage) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := base64.RawURLEncoding.EncodeToString(b)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.challenges == nil {
		s.challenges = make(map[string]*Challenge)
	}
	s.challenges[id] = &Challenge{
		UserID:               userID,
		ClientID:             clientID,
		Scopes:               slices.Clone(scopes),
		AuthorizationDetails: bytes.Clone(authorizationDetails),
		ExpiresAt:            time.Now().Add(ChallengeTTL),
	}
	return id
}

// Consume validates and atomically removes the challenge with the given ID.
// Returns true only if the challenge exists, matches (userID, clientID,
// exact scopes, exact authorizationDetails), and has not expired.
func (s *ChallengeStore) Consume(id, userID, clientID string, scopes []string, authorizationDetails json.RawMessage) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.challenges == nil {
		return false
	}

	// Prune expired challenges using monotonic-clock-safe comparison.
	// time.Since incorporates Go's monotonic offset, so a wall-clock
	// rewind cannot resurrect an expired challenge.
	for k, v := range s.challenges {
		if time.Since(v.ExpiresAt) > 0 {
			delete(s.challenges, k)
		}
	}

	ch, ok := s.challenges[id]
	if !ok || time.Since(ch.ExpiresAt) > 0 {
		return false
	}
	if ch.UserID != userID || ch.ClientID != clientID || !ScopesMatch(ch.Scopes, scopes) {
		return false
	}
	// RFC 9396 §7: authorizationDetails must match exactly — the client must
	// not be able to change the RAR payload between the consent prompt and
	// the re-POST that presents the challenge.
	if !rawJSONEqual(ch.AuthorizationDetails, authorizationDetails) {
		return false
	}
	delete(s.challenges, id)
	return true
}

// rawJSONEqual reports whether two raw JSON blobs are byte-identical,
// treating nil and empty as equal (both represent "no value").
func rawJSONEqual(a, b json.RawMessage) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return bytes.Equal(a, b)
}
