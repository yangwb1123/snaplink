package defaultimpl

import (
	"context"
	"sync"
	"time"
)

// Exp-bounded in-process revocation deny-set helpers, shared by the three
// JWT issuers (Ed25519 / ECDSA / RSA).
//
// THE BUG THIS FIXES. The historical deny-set was a map[string]struct{}
// keyed by the full token, added to on Revoke and consulted in Validate —
// but never pruned. A long-running server accumulated one entry per revoked
// token forever, an unbounded memory leak.
//
// THE FIX. Key the deny-set by the token's `exp` (unix SECONDS — the same
// unit the issuers stamp into the `exp` claim and compare in Validate). A
// revoked entry is only ever NEEDED until that exp: once exp <= now, Validate
// rejects the token on expiry anyway (`now-skew >= exp`), so the deny-set
// entry is redundant and droppable. Pruning is lazy — swept on each Revoke
// under the caller's existing write lock — so there is no extra goroutine,
// timer, or lock.
//
// THE SAFETY GATE (prune-not-early). pruneRevoked MUST NEVER drop an entry
// whose exp is still in the future relative to the prune instant: doing so
// would let a still-valid, deliberately-revoked token validate again — a
// security regression. The cutoff comparison is strict-less-than against the
// prune instant, so an entry expiring exactly now is the only borderline case
// and dropping it is safe (Validate's own `now-skew >= exp` already rejects
// it). To stay conservative under clock skew the issuer passes a cutoff that
// has NOT been widened by maxClockSkew — pruning uses the raw wall clock, so
// an entry is retained at least until its exp regardless of the verify-time
// skew leeway.

// markRevoked records token in the deny-set keyed by its exp (unix seconds),
// then lazily prunes entries that have already expired. The caller MUST hold
// the write lock guarding m. exp is the token's `exp` claim; a non-positive
// exp (a token with no exp — not minted by these issuers, but defensively
// handled) is stored as 0, which pruneRevoked treats as "expires at the unix
// epoch" and drops on the next sweep, never retaining it longer than a real
// future exp.
func markRevoked(m map[string]int64, token string, exp int64) {
	m[token] = exp
	pruneRevoked(m, time.Now().Unix())
}

// pruneRevoked drops every entry whose exp is STRICTLY in the past relative to
// nowUnix (exp < nowUnix). It NEVER drops an entry whose exp >= nowUnix — that
// entry names a token that is still within its validity window and whose
// revocation must still be honored (the prune-not-early safety gate). The
// caller MUST hold the write lock guarding m.
//
// Entries with exp == 0 (no/zero exp) are < any positive nowUnix and so are
// dropped; that is correct — a token with no exp can't be honored-until-exp
// anyway, and Validate has no expiry to reject it on, so it should not linger
// in the deny-set indefinitely (the unbounded-growth bug). These issuers
// always stamp a positive exp, so this branch is defensive only.
func pruneRevoked(m map[string]int64, nowUnix int64) {
	for tok, exp := range m {
		if exp < nowUnix {
			delete(m, tok)
		}
	}
}

// RevocationStore is an OPTIONAL durable backing for the JWT issuers'
// in-process revocation deny-set. Without one, a revoked-but-unexpired access
// token RESURRECTS after a process restart / rolling deploy (the in-process
// map starts empty) and on a late-joining replica — exactly when a stolen
// token is most valuable. Wiring SQLite closes the single-replica restart gap;
// shared Redis closes restart, late-join, and bus-recovery gaps in a fleet. The
// issuer PERSISTS each Revoke and RE-SEEDS its in-process map from the store at
// boot via SeedRevocations. Validate still consults ONLY the fast in-process
// map — the store is never on the per-validation hot path. Live cross-replica
// propagation is the separate cluster bus (WithCrossReplicaRevocation).
//
// All exp values are unix SECONDS (the issuers' `exp` unit). Impls MUST be
// safe for concurrent use.
type RevocationStore interface {
	// Revoke records token as revoked until expUnix. Idempotent.
	Revoke(ctx context.Context, token string, expUnix int64) error
	// Load returns every still-relevant revocation (token -> expUnix).
	Load(ctx context.Context) (map[string]int64, error)
	// Prune drops entries whose exp is strictly before nowUnix.
	Prune(ctx context.Context, nowUnix int64) error
}

// MemoryRevocationStore is the in-process RevocationStore. It is "durable" only
// for the life of the process — useful in tests + single-process deployments
// that want the SeedRevocations seam exercised; restart and recovery safety
// across a multi-replica fleet needs the shared Redis store.
type MemoryRevocationStore struct {
	mu sync.Mutex
	m  map[string]int64
}

// NewMemoryRevocationStore returns an empty in-process RevocationStore.
func NewMemoryRevocationStore() *MemoryRevocationStore {
	return &MemoryRevocationStore{m: make(map[string]int64)}
}

func (s *MemoryRevocationStore) Revoke(_ context.Context, token string, expUnix int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[token] = expUnix
	pruneRevoked(s.m, time.Now().Unix())
	return nil
}

func (s *MemoryRevocationStore) Load(_ context.Context) (map[string]int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pruneRevoked(s.m, time.Now().Unix())
	out := make(map[string]int64, len(s.m))
	for k, v := range s.m {
		out[k] = v
	}
	return out, nil
}

func (s *MemoryRevocationStore) Prune(_ context.Context, nowUnix int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pruneRevoked(s.m, nowUnix)
	return nil
}

// seedRevokedFromStore bulk-loads still-valid revocations from store and merges
// them into the in-process map m. The store Load — durable I/O (sqlite query /
// redis round-trip) — runs WITHOUT mu held: it touches only its own returned
// map, not m, so keeping the write lock across it would needlessly stall every
// concurrent Validate (RLock) behind store latency. This matters because
// re-seed runs on a LIVE replica during invalidation-bus recovery, not only at
// boot before traffic. mu is taken ONLY around the in-memory merge. Seeding is
// additive + idempotent, so a Validate racing between the Load and the merge is
// safe (it observes either the pre-seed set or the seeded one, never a torn
// entry). Already-expired entries are skipped — the prune-not-early gate: only
// an entry whose exp is still >= now must keep being honored. A nil store is a
// no-op; mu may be nil ONLY when store is nil.
func seedRevokedFromStore(ctx context.Context, mu *sync.RWMutex, m map[string]int64, store RevocationStore) error {
	if store == nil {
		return nil
	}
	loaded, err := store.Load(ctx)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	mu.Lock()
	defer mu.Unlock()
	for tok, exp := range loaded {
		if exp >= now {
			m[tok] = exp
		}
	}
	return nil
}
