package defaultimpl

import "github.com/snaplink/sso/protocols/oauth"

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"
)

// parURIBytes is the random suffix size for request_uri tokens. 24
// bytes / 192 bits is overkill for a 90-second TTL but cheap, and
// matches the entropy floor of the other short-lived OAuth artifacts
// in this codebase (auth codes, device codes).
const parURIBytes = 24

// MemoryPARStore is an in-process [oauth.PARStore]. Production
// deployments with multiple replicas should swap for a Redis or
// shared-DB backend — a request_uri minted on one replica MUST be
// consumable on the replica handling the subsequent /auth/login
// redirect.
type MemoryPARStore struct {
	mu      sync.Mutex
	entries map[string]*oauth.PARRequest
}

func NewMemoryPARStore() *MemoryPARStore {
	return &MemoryPARStore{entries: make(map[string]*oauth.PARRequest)}
}

func (m *MemoryPARStore) Issue(_ context.Context, req *oauth.PARRequest) (string, error) {
	if req == nil {
		return "", oauth.ErrPARNotFound
	}
	tok, err := GeneratePARToken()
	if err != nil {
		return "", err
	}
	uri := oauth.PARURIPrefix + tok
	// Defensive slice copies so post-Issue mutation by the caller
	// doesn't leak into stored state.
	stored := &oauth.PARRequest{
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
		Claims:               cloneRawBytes(req.Claims),
		ExpiresAt:            req.ExpiresAt,
	}
	m.mu.Lock()
	m.entries[uri] = stored
	m.mu.Unlock()
	return uri, nil
}

func (m *MemoryPARStore) Consume(_ context.Context, requestURI string) (*oauth.PARRequest, error) {
	m.mu.Lock()
	entry, ok := m.entries[requestURI]
	delete(m.entries, requestURI)
	m.mu.Unlock()
	if !ok {
		return nil, oauth.ErrPARNotFound
	}
	if entry.IsExpired() {
		return nil, oauth.ErrPARNotFound
	}
	return entry, nil
}

// GeneratePARToken mints a cryptographically random base64url
// suffix for the request_uri urn:...:request_uri:<token> string.
// Exposed so custom oauth.PARStore implementations can reuse it.
func GeneratePARToken() (string, error) {
	buf := make([]byte, parURIBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

var _ oauth.PARStore = (*MemoryPARStore)(nil)
