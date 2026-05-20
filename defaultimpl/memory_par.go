package defaultimpl

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"

	"github.com/snaplink/sso"
)

// parURIBytes is the random suffix size for request_uri tokens. 24
// bytes / 192 bits is overkill for a 90-second TTL but cheap, and
// matches the entropy floor of the other short-lived OAuth artifacts
// in this codebase (auth codes, device codes).
const parURIBytes = 24

// MemoryPARStore is an in-process [sso.PARStore]. Production
// deployments with multiple replicas should swap for a Redis or
// shared-DB backend — a request_uri minted on one replica MUST be
// consumable on the replica handling the subsequent /auth/login
// redirect.
type MemoryPARStore struct {
	mu      sync.Mutex
	entries map[string]*sso.PARRequest
}

func NewMemoryPARStore() *MemoryPARStore {
	return &MemoryPARStore{entries: make(map[string]*sso.PARRequest)}
}

func (m *MemoryPARStore) Issue(_ context.Context, req *sso.PARRequest) (string, error) {
	if req == nil {
		return "", sso.ErrPARNotFound
	}
	tok, err := GeneratePARToken()
	if err != nil {
		return "", err
	}
	uri := sso.PARURIPrefix + tok
	// Defensive slice copies so post-Issue mutation by the caller
	// doesn't leak into stored state.
	stored := &sso.PARRequest{
		ClientID:             req.ClientID,
		ResponseType:         req.ResponseType,
		RedirectURI:          req.RedirectURI,
		Scope:                append([]string(nil), req.Scope...),
		State:                req.State,
		Nonce:                req.Nonce,
		CodeChallenge:        req.CodeChallenge,
		CodeChallengeMethod:  req.CodeChallengeMethod,
		Resource:             append([]string(nil), req.Resource...),
		AuthorizationDetails: cloneRawBytes(req.AuthorizationDetails),
		LoginHint:            req.LoginHint,
		ResponseMode:         req.ResponseMode,
		ACRValues:            req.ACRValues,
		UILocales:            req.UILocales,
		ExpiresAt:            req.ExpiresAt,
	}
	m.mu.Lock()
	m.entries[uri] = stored
	m.mu.Unlock()
	return uri, nil
}

func (m *MemoryPARStore) Consume(_ context.Context, requestURI string) (*sso.PARRequest, error) {
	m.mu.Lock()
	entry, ok := m.entries[requestURI]
	delete(m.entries, requestURI)
	m.mu.Unlock()
	if !ok {
		return nil, sso.ErrPARNotFound
	}
	if entry.IsExpired() {
		return nil, sso.ErrPARNotFound
	}
	return entry, nil
}

// GeneratePARToken mints a cryptographically random base64url
// suffix for the request_uri urn:...:request_uri:<token> string.
// Exposed so custom PARStore implementations can reuse it.
func GeneratePARToken() (string, error) {
	buf := make([]byte, parURIBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

var _ sso.PARStore = (*MemoryPARStore)(nil)
