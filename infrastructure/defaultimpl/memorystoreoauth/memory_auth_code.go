package memorystoreoauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"maps"

	"github.com/snaplink/sso/protocols/oauth"
)

// authCodeBytes is the size in bytes of generated codes (32 → 43 base64url
// chars). Larger than the typical OAuth code; matches the temp_token
// generator so brute-force costs are consistent across one-shot tokens.
const authCodeBytes = 32

// MemoryAuthCodeStore is an in-process oauth.AuthCodeStore. Production
// deployments with multiple replicas should swap a Redis or SQL backend
// — codes issued on one replica must be consumable on any other.
//
// entries is sharded (see sharded_map.go) — every code is looked up by
// its own key with no cross-code scan, so partitioning the lock across
// mapShardCount independent mutexes is safe and cuts contention on the
// hottest OAuth path (issued + consumed on every authorization_code
// login) without changing Issue/Consume's behavior at all.
type MemoryAuthCodeStore struct {
	entries *shardedMap[*oauth.AuthCode]
}

// NewMemoryAuthCodeStore returns a ready-to-use store with no TTL of its
// own — TTLs are stamped per-oauth.AuthCode at Issue time.
func NewMemoryAuthCodeStore() *MemoryAuthCodeStore {
	return &MemoryAuthCodeStore{entries: newShardedMap[*oauth.AuthCode]()}
}

func (m *MemoryAuthCodeStore) Issue(_ context.Context, code string, info *oauth.AuthCode) error {
	if code == "" || info == nil {
		return oauth.ErrAuthCodeNotFound
	}
	// Copy slice to avoid aliasing caller's underlying array — a future
	// mutation of info.Scopes by the caller must not be visible at
	// Consume time.
	scopes := append([]string(nil), info.Scopes...)
	resources := append([]string(nil), info.Resources...)
	attrs := copyMap(info.Attributes)
	var authDetails json.RawMessage
	if len(info.AuthorizationDetails) > 0 {
		authDetails = append(json.RawMessage(nil), info.AuthorizationDetails...)
	}
	m.entries.Store(code, &oauth.AuthCode{
		UserID:               info.UserID,
		ClientID:             info.ClientID,
		RedirectURI:          info.RedirectURI,
		Scopes:               scopes,
		Nonce:                info.Nonce,
		Provider:             info.Provider,
		AuthTime:             info.AuthTime,
		AuthMethods:          append([]string(nil), info.AuthMethods...),
		ACR:                  info.ACR,
		Attributes:           attrs,
		CodeChallenge:        info.CodeChallenge,
		CodeChallengeMethod:  info.CodeChallengeMethod,
		Resources:            resources,
		AuthorizationDetails: authDetails,
		SID:                  info.SID,
		ConfirmationJKT:      info.ConfirmationJKT,
		ExpiresAt:            info.ExpiresAt,
	})
	return nil
}

func (m *MemoryAuthCodeStore) Consume(_ context.Context, code string) (*oauth.AuthCode, error) {
	entry, ok := m.entries.LoadAndDelete(code) // single-use — delete on every Consume attempt

	if !ok {
		return nil, oauth.ErrAuthCodeNotFound
	}
	// Expired entries already removed above; just signal the same not-found
	// outcome so callers can't distinguish stale-vs-unknown from the wire.
	if entry.IsExpired() {
		return nil, oauth.ErrAuthCodeNotFound
	}
	return entry, nil
}

// GenerateAuthCode mints a cryptographically random base64url-encoded
// code suitable for the OAuth 2.0 authorization_code grant. Exposed so
// custom oauth.AuthCodeStore implementations can reuse it.
func GenerateAuthCode() (string, error) {
	buf := make([]byte, authCodeBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// copyMap returns a shallow copy of m, or nil when m is nil. Used so
// oauth.AuthCode.Attributes don't alias the caller's map.
func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	maps.Copy(out, m)
	return out
}

// cloneRawBytes returns a defensive copy of the byte slice (typically
// a json.RawMessage). nil-safe — returns nil when b is nil so a
// "no value" caller stays distinguishable from a zero-length slice
// downstream. Memory stores hand back what they were given by
// reference; without this, the caller's later mutation of the slice
// would leak into the stored entry.
func cloneRawBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// Compile-time interface check.
var _ oauth.AuthCodeStore = (*MemoryAuthCodeStore)(nil)
