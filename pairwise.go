package sso

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"sync"
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
// no eviction. The map grows linearly in active-pairwise count;
// production deployments serving large user bases under pairwise
// SHOULD plug a TTL-capable backend or a shared persistent store.
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

// DefaultPairwiseSalt is used when an operator wires
// [WithPairwiseSubjectStore] without [WithPairwiseSalt]. Stable across
// restarts so previously-issued pairwise subs continue to map to the
// same local subject in the wired store. Operators SHOULD set their
// own via [WithPairwiseSalt] — the default is fine for tests but
// publicly known.
const DefaultPairwiseSalt = "snaplink-default-pairwise-salt"

// sectorIdentifier returns the OIDC Core §8.1.1 sector identifier
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
func sectorIdentifier(client *Client) string {
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

// computePairwiseSubject hashes sector + local + salt into a stable
// opaque identifier. Deterministic — same inputs always yield the
// same output, so the store mapping is idempotent across re-
// issuances for the same user-client pair. Base64-URL no-pad
// encoding keeps the value `sub`-claim safe (no equals signs, no
// JSON-escape requirements).
func computePairwiseSubject(sector, localSub, salt string) string {
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

// applyPairwiseSubject computes the pairwise sub for (client, localSub)
// and persists the reverse mapping in the wired store. Returns the
// pairwise sub when the client opted in AND the store is wired;
// returns localSub unchanged otherwise. Called at every issuance
// path that mints a token whose sub claim the RP will see.
//
// Fail-open: when the store's MapPairwise fails, the function still
// returns the computed pairwise sub but logs the error via the
// supplied error sink. The token MINTS with the pairwise sub —
// resource-side lookups will fail (`invalid_token`) until the next
// successful map. The alternative (fail-closed) would block
// issuance, which is worse than a token whose userinfo path
// temporarily fails.
func (s *Server) applyPairwiseSubject(ctx context.Context, client *Client, localSub string) string {
	if client == nil || s.pairwiseStore == nil {
		return localSub
	}
	if !strings.EqualFold(client.SubjectType, SubjectTypePairwise) {
		return localSub
	}
	sector := sectorIdentifier(client)
	pairwise := computePairwiseSubject(sector, localSub, s.pairwiseSalt)
	if pairwise == "" {
		return localSub
	}
	if err := s.pairwiseStore.MapPairwise(ctx, pairwise, localSub); err != nil {
		s.logger.Error("pairwise: map failed (continuing — resource lookups may fail)", "error", err, "client_id", client.ID)
	}
	return pairwise
}

// resolveLocalSubject reverses a pairwise sub on inbound resource
// requests. When pairwise is wired AND the sub looks like a pairwise
// value (not present in UserProvider as a local id), the store is
// consulted; ErrPairwiseUnknown surfaces to the caller which maps it
// to the standard invalid_token response.
//
// When pairwise is NOT wired or the sub is a known local id, the
// input is returned unchanged — pairwise opt-in is per-client, so
// non-pairwise clients keep their public sub semantics.
//
// The cheap-path optimization (looking up local first) means
// non-pairwise deployments pay nothing beyond what they already paid
// before this feature existed.
func (s *Server) resolveLocalSubject(ctx context.Context, sub string) (string, error) {
	if sub == "" {
		return sub, nil
	}
	if s.pairwiseStore == nil {
		return sub, nil
	}
	local, err := s.pairwiseStore.LocalSubject(ctx, sub)
	if err == nil {
		return local, nil
	}
	if errors.Is(err, ErrPairwiseUnknown) {
		// Not a pairwise sub — caller's claim is already local.
		return sub, nil
	}
	return sub, err
}

// WithPairwiseSubjectStore enables OIDC Core §8 pairwise subject
// identifiers. Per-client subject_type metadata gates use: clients
// with SubjectType="pairwise" get an opaque per-sector sub in their
// tokens; "public" (default) clients continue to receive the local
// subject identifier. Resource-side handlers (/userinfo, etc.) use
// the store's reverse map to recover the local sub for lookups.
//
// Discovery doc advertises both "public" and "pairwise" in
// subject_types_supported when this option is wired.
//
// Single-replica memory backend is provided
// (NewMemoryPairwiseSubjectStore); multi-replica deployments need a
// shared backend so pairwise subs issued on replica A resolve on
// replica B.
func WithPairwiseSubjectStore(store PairwiseSubjectStore) Option {
	return func(s *Server) { s.pairwiseStore = store }
}

// WithPairwiseSalt overrides the deterministic salt mixed into
// pairwise sub computation. Operators SHOULD set this to a
// deployment-stable secret distributed out-of-band — the default is
// publicly known and lets attackers pre-compute pairwise sub →
// local sub mappings if they ever see a local sub in some other
// channel. Empty value falls back to DefaultPairwiseSalt.
func WithPairwiseSalt(salt string) Option {
	return func(s *Server) { s.pairwiseSalt = salt }
}
