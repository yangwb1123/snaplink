package defaultimpl

import "time"

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
