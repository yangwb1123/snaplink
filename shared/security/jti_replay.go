package security

import (
	"context"
	"time"
)

// JTIReplayStore tracks seen `jti` values within their expiry window
// to defend against JWT replay attacks. RFC 9101 §10.8 RECOMMENDS this
// for JWT-Secured Authorization Requests; the same primitive applies
// to any signed JWT carrying a jti — DPoP proofs, JWT bearer client
// assertions, token-exchange actor_tokens, etc.
//
// The store MUST implement single-pass atomic semantics: a caller
// sending the same jti twice gets one (firstSighting=true) and one
// (firstSighting=false), regardless of concurrency. Implementations
// SHOULD garbage-collect entries past their expiry (memory and
// non-TTL backends both benefit).
//
// Empty jti SHOULD short-circuit at the call site, not the store
// implementation — the spec leaves jti optional, and silently
// accepting "" as a sentinel "never replay" would let attackers
// strip the claim to bypass the defense.
type JTIReplayStore interface {
	// MarkSeen atomically records the jti with the given expiry.
	// Returns (true, nil) on the first sighting — caller proceeds.
	// Returns (false, nil) when the jti has been seen within its
	// expiry window — caller MUST reject the request. Errors are
	// fail-open: store failures shouldn't block valid requests, but
	// callers SHOULD log them so operators can spot a degraded
	// replay-defense backend.
	MarkSeen(ctx context.Context, jti string, expiresAt time.Time) (firstSighting bool, err error)
}

// JTIReplayForgetter is an OPTIONAL extension that releases a previously
// MarkSeen jti. It exists for the narrow case where a caller consumed a jti
// fail-closed (replay defense, BEFORE acting) but the subsequent action failed
// RETRYABLY: rolling the jti back lets the retried request through instead of
// dropping it as a replay. Used by the CAEP/SSF receiver so a transient
// revoke-store outage can't permanently lose a real security event. Stores that
// can atomically delete a key SHOULD implement it (memory map delete, Redis
// DEL); the receiver type-asserts and degrades gracefully when it is absent.
type JTIReplayForgetter interface {
	Forget(ctx context.Context, jti string) error
}

// DefaultJTIReplayWindow is the fallback expiry used when a caller
// has no `exp` claim to anchor against. Matches the typical
// authorization-request lifetime (PAR's default TTL is 90s; JAR
// JWTs SHOULD have an exp not far past that).
const DefaultJTIReplayWindow = 5 * time.Minute
