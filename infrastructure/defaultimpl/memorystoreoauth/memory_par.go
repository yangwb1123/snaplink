package memorystoreoauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl/memreaper"
	"github.com/snaplink/sso/protocols/oauth"
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
//
// entries is sharded (see sharded_map.go) — same rationale as
// MemoryAuthCodeStore: single-key Issue/Consume, no cross-request_uri
// scan, so splitting the lock across independent shards is safe and
// cuts contention on the PAR issue+consume round trip.
//
// MaxEntries (0 = unbounded, the default) and StartReaper are optional:
// Consume already lazily drops an expired entry on the specific
// request_uri a caller presents, but a request_uri nobody ever redeems
// (e.g. an abandoned authorization flow) has no such caller, so it would
// otherwise sit in a shard forever. Neither changes behavior unless
// explicitly configured.
type MemoryPARStore struct {
	MaxEntries int

	entries *shardedMap[*oauth.PARRequest]
	reaper  *memreaper.Reaper
}

func NewMemoryPARStore() *MemoryPARStore {
	return &MemoryPARStore{entries: newShardedMap[*oauth.PARRequest]()}
}

// StartReaper launches a background sweep of expired, never-redeemed
// request_uris every interval. A non-positive interval is a no-op.
// Idempotent — calling it again stops the previous reaper first.
func (m *MemoryPARStore) StartReaper(interval time.Duration) {
	_ = m.reaper.Close()
	m.reaper = memreaper.Start(interval, func(time.Time) {
		m.entries.DeleteExpired(func(v *oauth.PARRequest) bool { return v.IsExpired() })
	})
}

// Close stops the background reaper started via StartReaper, if any.
func (m *MemoryPARStore) Close() error {
	return m.reaper.Close()
}

func (m *MemoryPARStore) Issue(_ context.Context, req *oauth.PARRequest) (string, error) {
	if req == nil {
		return "", oauth.ErrPARNotFound
	}
	if m.MaxEntries > 0 && m.entries.Len() >= m.MaxEntries {
		return "", ErrStoreAtCapacity
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
	m.entries.Store(uri, stored)
	return uri, nil
}

func (m *MemoryPARStore) Consume(_ context.Context, requestURI string) (*oauth.PARRequest, error) {
	entry, ok := m.entries.LoadAndDelete(requestURI)
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

var (
	_ oauth.PARStore = (*MemoryPARStore)(nil)
	_ io.Closer      = (*MemoryPARStore)(nil)
)
