// Package redis provides Redis-backed implementations of the snaplink/sso
// hot-path stores — the session, refresh-token, authorization-code, PAR,
// and JTI-replay SPIs — for the throughput / multi-replica scale layer
// (>1k QPS, many replicas sharing one logical store).
//
// # Why a separate Go module
//
// This package lives in its own nested module
// (github.com/snaplink/sso/redis) so the github.com/redis/go-redis
// dependency NEVER enters the core sso module's go.mod. The core's
// zero-external-SDK invariant is a firm property of the repo: operators
// who need Redis opt in by importing this submodule from their own cmd
// binary. This mirrors kms/awskms (which keeps aws-sdk-go-v2 out of the
// core). There is deliberately no go.work — a workspace would merge the
// build lists and surface go-redis in the core's `go list -m all`. The
// submodule resolves the core via a `replace github.com/snaplink/sso =>
// ../` directive; CI builds + race-tests it via the Makefile `ci-modules`
// target, against an in-process miniredis fake (no real Redis needed).
//
// # Why Redis is the throughput layer
//
// SQLite (defaultimpl/sqlite) is the embedded, cluster-shareable default
// and stays the fallback for every deployment that fits a single file or
// a small fleet. Redis is the next step up: a network store with
// microsecond ops, native per-key TTL, and atomic server-side scripting,
// purpose-built for auth-heavy loads where many replicas hammer the same
// single-use / session / replay state.
//
// # Wiring
//
// Build a *redis.Client (or ClusterClient — any redis.Cmdable) once and
// hand it to each store constructor, then pass the store to the matching
// sso.WithXxx option:
//
//	rdb := goredis.NewClient(&goredis.Options{Addr: "redis:6379"})
//
//	sm  := redis.NewSessionManager(rdb, redis.WithSessionTTL(24*time.Hour))
//	rts := redis.NewRefreshTokenStore(rdb)
//	acs := redis.NewAuthCodeStore(rdb)
//	par := redis.NewPARStore(rdb)
//	jti := redis.NewJTIReplayStore(rdb)
//
//	srv := sso.NewServer(
//	    sso.WithSessionManager(sm),
//	    sso.WithRefreshTokenStore(rts, 30*24*time.Hour),
//	    sso.WithAuthCodeStore(acs, 10*time.Minute),
//	    sso.WithPARStore(par, oauth.DefaultPARTTL),
//	    sso.WithJTIReplayStore(jti),
//	)
//
// Each store also exposes Ping(ctx) so it can back sso.WithReadyCheck.
//
// # Atomicity guarantees (the §2 invariants these stores preserve)
//
// The §2 oracle-leak / single-use / session-refresh / family-rotation /
// replay invariants are NOT advisory — a wrong Redis op (a non-atomic
// SELECT-then-DELETE, or a Refresh that extends an expired session) is a
// security regression. Each store therefore mirrors its SQLite peer's
// atomic primitive exactly:
//
//   - SessionManager.Refresh is a Lua script (loaded via redis.Script,
//     so it runs server-side as one atomic unit). It re-reads the stored
//     revoked flag + expiry and extends the TTL ONLY when revoked==0 AND
//     not-yet-expired — the "captured expired session id can't be
//     resurrected" invariant, identical to the SQLite UPDATE ... WHERE
//     expires_at>now AND revoked=0 ... RETURNING. TTL plus an explicit
//     expires_at field together guarantee an expired key reads as
//     "not found" even in the millisecond before Redis evicts it.
//
//   - RefreshTokenStore.Consume / AuthCodeStore.Consume / PARStore.Consume
//     are single GETDEL calls (atomic get-and-delete, Redis 6.2+). One
//     round trip removes-and-returns; a second Consume of the same key
//     finds nothing. Unknown / expired (TTL-evicted) / already-consumed /
//     client-mismatch all collapse to ONE "not found" result — the
//     oracle-leak hardening. (Auth codes and PAR have no client binding
//     to check; refresh tokens carry ClientID inside the value and the
//     handler — not the store — enforces the binding, exactly as the
//     SQLite peer does.)
//
//   - Refresh-token families ride a parallel ledger (a per-family SET of
//     member token ids that survives the active key's Consume DELETE) plus
//     a "consumed" marker key. A Consume that misses the active key but
//     hits the consumed-marker returns ErrRefreshTokenReused with the
//     FamilyID stamped, so the handler kills the whole family via
//     DeleteFamily — OAuth Security BCP §4.13/§4.14, identical to the
//     SQLite refresh_token_families table.
//
//   - JTIReplayStore.MarkSeen is a single SET key NX EX ttl. The SET
//     succeeds (first-sighting=true) iff the key did not already exist;
//     NX makes the test-and-set atomic and EX bounds the key to the jti's
//     expiry window. Identical first-sighting semantics to the SQLite
//     INSERT ... ON CONFLICT DO NOTHING.
//
// # Failover + cross-region semantics
//
// Per §2, /token fails CLOSED: if Redis is unreachable, refresh rotation
// and single-use Consume return an error and the grant is rejected (500)
// rather than minting a token against unknown state — a Redis outage must
// never let a replayed code/refresh-token through. (Audit, geo, and other
// best-effort lookups remain fail-open per their own contracts.)
//
// Cross-region replication lag is a correctness caveat for single-use
// state: Redis async replication means a code/refresh-token/jti written
// on the primary may not yet be visible on a replica that serves the
// follow-up request. Run single-use + replay traffic against the primary
// (or a strongly-consistent setup) within one region; do NOT split a
// single auth flow across asynchronously-replicated regions, or a replay
// could momentarily evade detection. Sessions tolerate lag better (a
// briefly-stale session is a UX hiccup, not a security hole) but the same
// primary-affinity guidance applies to Refresh.
//
// # Scope
//
// Implemented here: SessionManager, RefreshTokenStore (+ Inspector,
// SubjectIndex, SubjectCounter, ClientPurger, FamilyTracker), AuthCodeStore,
// PARStore, JTIReplayStore. Rate-limit (ratelimit.Limiter), device-code,
// MFA-challenge, and CIBA stores are the same single-use / TTL pattern and
// are planned same-pattern follow-ups; until then those subsystems use
// their memory or sqlite backends.
package redis
