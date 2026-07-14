package tokenexchange

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// ChainHop is one durable, queryable record of a single RFC 8693 §4.1
// token-exchange hop: actor ActorSubject exchanged the inbound subject_token
// (ParentJTI) into a freshly minted token (JTI), acting as SubjectID via
// ClientID. It is the flattened, JTI-linked, PERSISTABLE counterpart of
// core.ActorClaim (shared/core/types_token.go) — that struct only ever
// carries the CURRENT token's nested act chain in memory (and is gone the
// instant the token itself expires); ChainHop instead links hop-to-hop by
// JTI so a [ChainStore] can answer "what produced token X" ([ChainStore.
// GetChain]) or "what did token X later become" ([ChainStore.
// GetDescendants]) long after any of the tokens involved have expired.
//
// This is PURE, APPEND-ONLY OBSERVABILITY (see [RecordHopFailOpen]): it adds
// no new token-exchange semantics, no cascade-revocation, and no
// cycle-detection beyond what internal/handler/tokengrant already enforces
// unconditionally (MaxActChainDepth + tokExActorChainHasCycle) — this is
// scoped deliberately narrower than those, as follow-on work.
type ChainHop struct {
	// JTI is this hop's own newly minted access token's `jti` (RFC 9068) —
	// a ChainStore's natural primary key. A hop whose issuer couldn't be
	// identified (an opaque/non-JWT strategy) has no JTI and is never
	// recorded (see RecordHopFailOpen) — an unkeyed row could never be
	// looked back up by GetChain/GetDescendants.
	JTI string `json:"jti"`
	// ParentJTI is the subject_token's `jti` — the token THIS hop exchanged
	// FROM. Empty when the subject_token carried no jti (an opaque bearer,
	// or the first hop of a chain no earlier hop was ever recorded for) —
	// GetChain then treats JTI as a chain root even though it may not be
	// the delegation's true origin.
	ParentJTI string `json:"parent_jti,omitempty"`
	// SubjectID is the subject_token's Subject — the principal being acted
	// upon / delegated for (mirrors Hop.SubjectID above).
	SubjectID string `json:"subject_id,omitempty"`
	// ActorSubject is the actor_token's Subject — who is acting. Empty when
	// the exchange carried no actor_token (a plain re-issuance, not a
	// delegation).
	ActorSubject string `json:"actor_subject,omitempty"`
	// ClientID is the downstream OAuth client performing the exchange.
	ClientID string `json:"client_id,omitempty"`
	// ChainDepth is the core.ActorClaim chain length on the newly minted
	// token AFTER this hop's prepend (0 = no delegation at all) — lets an
	// operator see "how deep did this get" without walking every ancestor
	// first.
	ChainDepth int `json:"chain_depth"`
	// RecordedAt is the wall-clock instant this hop was recorded (the
	// exchange request's own time, NOT the minted token's iat/exp).
	RecordedAt time.Time `json:"recorded_at"`
}

// ChainStore is the OPTIONAL RFC 8693 token-exchange delegation-chain
// persistence + read-visibility SPI. Nil (the default, unwired) is a
// complete no-op: no hop is ever recorded, and the admin read endpoint
// (interfaces/admin.HandleTokenExchangeChain) is not mounted.
//
// Distinct from [Policy] above: Policy is a synchronous, in-request-path,
// FAIL-CLOSED authorization gate consulted BEFORE a token is minted;
// ChainStore is an out-of-band, FAIL-OPEN, AFTER-the-fact observability
// record consulted only by an operator investigating an incident. Neither
// depends on the other, and wiring one never implies the other.
type ChainStore interface {
	// RecordHop persists one hop. Called once per successful token-exchange
	// issuance (see RecordHopFailOpen — always fail-open at the call site).
	// Implementations MUST be safe to call from the request hot path (no
	// unbounded blocking): the exchange response has already been decided
	// by the time this runs, but a slow RecordHop still delays it.
	RecordHop(ctx context.Context, hop ChainHop) error
	// GetChain returns the recorded ancestor chain for jti, ordered from the
	// ROOT (oldest, first) to jti itself (last), inclusive. Returns a nil
	// (empty) slice, not an error, when jti was never recorded.
	GetChain(ctx context.Context, jti string) ([]ChainHop, error)
	// GetDescendants returns every recorded hop whose lineage passes
	// through jti — i.e. every token later derived, directly or
	// transitively, FROM jti — newest-recorded first, bounded to at most
	// limit rows. limit <= 0 means no cap; callers exposing this to an
	// admin surface SHOULD pass a positive limit.
	GetDescendants(ctx context.Context, jti string, limit int) ([]ChainHop, error)
}

// RecordHopFailOpen best-effort records hop to store. It NEVER returns an
// error and NEVER changes token-exchange behavior: a nil store is a no-op, a
// hop with no JTI (see ChainHop.JTI's doc) is skipped, and any store error
// is passed to logf (when non-nil) and otherwise swallowed. Mirrors the
// audit.Recorder.Record fail-open idiom (platform/audit/recorder.go) this
// package's AGENTS.md invariant is modeled on: this SPI exists purely for
// after-the-fact observability, never a gate, so an operator wiring a
// flaky/unavailable ChainStore must never see the exchange grant itself
// fail because of it.
func RecordHopFailOpen(ctx context.Context, store ChainStore, hop ChainHop, logf func(msg string, args ...any)) {
	if store == nil || hop.JTI == "" {
		return
	}
	if err := store.RecordHop(ctx, hop); err != nil && logf != nil {
		logf("token exchange chain hop recording failed (fail-open, observability only)",
			"error", err, "jti", hop.JTI)
	}
}

// RecordExchangeHopFailOpen is the convenience assembly point
// HandleTokenExchangeGrant's single call site uses: it derives JTI (from the
// freshly minted access token — see JTIFromJWTUnsafe) and ActorSubject (from
// actor, the resolved *core.ActorClaim, nil-safe) so the grant-handler call
// site stays a one-line hand-off rather than duplicating ChainHop assembly
// there. Delegates to RecordHopFailOpen for the actual fail-open contract.
func RecordExchangeHopFailOpen(ctx context.Context, store ChainStore, mintedAccessToken, parentJTI, subjectID string, actor *core.ActorClaim, clientID string, chainDepth int, logf func(msg string, args ...any)) {
	actorSubject := ""
	if actor != nil {
		actorSubject = actor.Subject
	}
	RecordHopFailOpen(ctx, store, ChainHop{
		JTI:          JTIFromJWTUnsafe(mintedAccessToken),
		ParentJTI:    parentJTI,
		SubjectID:    subjectID,
		ActorSubject: actorSubject,
		ClientID:     clientID,
		ChainDepth:   chainDepth,
		RecordedAt:   time.Now(),
	}, logf)
}

// JTIFromJWTUnsafe extracts the `jti` claim from a compact JWS WITHOUT
// verifying its signature. Safe ONLY because every call site hands this the
// token this SAME process just minted and signed a moment earlier in the
// same request — there is no untrusted input here, unlike a bearer token
// arriving over the wire. Mirrors internal/handler.JWTExpUnsafe's
// established "peek one claim for bookkeeping, never a trust decision"
// idiom (cross_replica.go). Returns "" for a non-JWT (opaque/session) token
// or a decode failure — RecordHopFailOpen then skips recording entirely.
func JTIFromJWTUnsafe(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return ""
	}
	return claims.JTI
}
