package security

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"sync"

	"github.com/snaplink/sso/core"
)

// SubjectTypePublic and SubjectTypePairwise are the two values OIDC
// Core §8 defines for a Client's subject_type metadata. Public is
// the default — the `sub` claim is the user's local identifier and
// every client receives the same `sub` for the same end user.
// Pairwise produces a per-sector opaque `sub` so colluding clients
// can't correlate users across services by comparing `sub` values.
const (
	SubjectTypePublic   = "public"
	SubjectTypePairwise = "pairwise"
)

// PairwiseSubjectStore persists the mapping from a pairwise `sub`
// value (the opaque per-sector identifier the RP sees) back to the
// local subject identifier the AS knows the user by. Required for
// resource-side handlers (/userinfo, /token/revoke-all, /end_session)
// that need to load the local user record from a bearer token whose
// `sub` claim is pairwise.
//
// MapPairwise is called at issuance — idempotent upsert; calling
// twice for the same pairwise → local pair MUST succeed without
// error. LocalSubject is called at resource time; ErrPairwiseUnknown
// (or any non-nil error) means the AS cannot resolve the inbound sub
// to a local user and the handler MUST reject the request with the
// same wire shape it uses for unknown tokens (oracle resistance).
type PairwiseSubjectStore interface {
	MapPairwise(ctx context.Context, pairwiseSub, localSub string) error
	LocalSubject(ctx context.Context, pairwiseSub string) (string, error)
}

// ErrPairwiseUnknown is the sentinel a PairwiseSubjectStore returns
// when no mapping exists for the given pairwise sub. Wrapped by
// errors.Is so layered backends (cache + persistent) can surface it
// from any layer without losing the typed comparison.
var ErrPairwiseUnknown = errors.New("pairwise: subject not mapped")

// MemoryPairwiseSubjectStore is an in-process PairwiseSubjectStore.
// Suitable for single-replica deployments + tests. Multi-replica
// deployments MUST plug a shared backend — a user who gets issued a
// pairwise sub on replica A and presents it at /userinfo on
// replica B would otherwise see ErrPairwiseUnknown and fail
// authentication. Multi-second propagation delays via the YAML
// snapshot subsystem partially address this for setup-time mappings
// but don't solve the per-issuance race.
type MemoryPairwiseSubjectStore struct {
	mu      sync.RWMutex
	entries map[string]string
}

// NewMemoryPairwiseSubjectStore returns a ready-to-use instance with
// no eviction.
func NewMemoryPairwiseSubjectStore() *MemoryPairwiseSubjectStore {
	return &MemoryPairwiseSubjectStore{entries: make(map[string]string)}
}

// MapPairwise implements PairwiseSubjectStore.
func (m *MemoryPairwiseSubjectStore) MapPairwise(_ context.Context, pairwiseSub, localSub string) error {
	if pairwiseSub == "" || localSub == "" {
		return errors.New("pairwise: empty sub")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[pairwiseSub] = localSub
	return nil
}

// LocalSubject implements PairwiseSubjectStore.
func (m *MemoryPairwiseSubjectStore) LocalSubject(_ context.Context, pairwiseSub string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	local, ok := m.entries[pairwiseSub]
	if !ok {
		return "", ErrPairwiseUnknown
	}
	return local, nil
}

// DefaultPairwiseSalt is used when an operator wires the pairwise
// store without overriding the salt. Stable across restarts so
// previously-issued pairwise subs continue to map to the same local
// subject. Operators SHOULD set their own — the default is fine for
// tests but publicly known.
const DefaultPairwiseSalt = "snaplink-default-pairwise-salt"

// SectorIdentifier returns the OIDC Core §8.1.1 sector identifier
// for client. Precedence:
//
//  1. If client.SectorIdentifierURI is set, the URL's host.
//  2. Otherwise, the host of the first redirect_uri.
//  3. Otherwise, the client.ID (defensive fallback so two clients
//     never accidentally share a sector via empty config).
//
// Sectors are about *grouping* clients (so colluding clients in one
// sector see the same pairwise sub for a user); not setting either
// field means the client stands alone in its sector.
func SectorIdentifier(client *core.Client) string {
	if client == nil {
		return ""
	}
	if client.SectorIdentifierURI != "" {
		if u, err := url.Parse(client.SectorIdentifierURI); err == nil && u.Host != "" {
			return u.Host
		}
	}
	for _, ru := range client.RedirectURIs {
		if u, err := url.Parse(ru); err == nil && u.Host != "" {
			return u.Host
		}
	}
	return client.ID
}

// ComputePairwiseSubject hashes sector + local + salt into a stable
// opaque identifier. Deterministic — same inputs always yield the
// same output, so the store mapping is idempotent across re-
// issuances for the same user-client pair. Base64-URL no-pad
// encoding keeps the value `sub`-claim safe (no equals signs, no
// JSON-escape requirements).
func ComputePairwiseSubject(sector, localSub, salt string) string {
	if sector == "" || localSub == "" {
		return ""
	}
	if salt == "" {
		salt = DefaultPairwiseSalt
	}
	h := sha256.New()
	h.Write([]byte(sector))
	h.Write([]byte{0}) // separator so "a"+"bc" and "ab"+"c" don't collide
	h.Write([]byte(localSub))
	h.Write([]byte{0})
	h.Write([]byte(salt))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
