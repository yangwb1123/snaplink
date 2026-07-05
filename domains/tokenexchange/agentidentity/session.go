package agentidentity

import (
	"context"
	"errors"
	"time"
)

// AgentSession is the bounded, revocable delegation record created when a
// human authorizes an agent to act on their behalf: WHO delegated
// (HumanSubject), WHICH agent (AgentID), for WHAT (GrantedScopes — already
// narrowed to <= HumanSubject's entitlement at grant-creation time by
// whatever consent/admin flow calls Create), and for HOW LONG (ExpiresAt).
// It is the delegation_token grant's mint-time authorization gate (see
// grant.go's checkSessionLive): an expired or Revoked session can NEVER
// mint, checked unconditionally before anything else (fail-closed,
// AGENTS.md §3).
type AgentSession struct {
	ID            string
	HumanSubject  string
	AgentID       string
	GrantedScopes []string
	CreatedAt     time.Time
	// ExpiresAt bounds the session's lifetime. Zero means "no expiry" —
	// callers creating a session SHOULD always set one; Validate does not
	// reject a zero value because a revocation-only session (no natural
	// expiry, relying solely on an explicit Revoke) is a legitimate, if
	// unusual, operator choice.
	ExpiresAt time.Time
	Revoked   bool
	RevokedAt time.Time
}

// Validate sanity-checks an AgentSession before persistence.
func (s *AgentSession) Validate() error {
	if s.ID == "" {
		return errors.Join(ErrInvalidSession, errors.New("id required"))
	}
	if s.HumanSubject == "" {
		return errors.Join(ErrInvalidSession, errors.New("human_subject required"))
	}
	if s.AgentID == "" {
		return errors.Join(ErrInvalidSession, errors.New("agent_id required"))
	}
	return nil
}

// ErrInvalidSession wraps AgentSession.Validate failures.
var ErrInvalidSession = errors.New("agentidentity: invalid agent session")

// ErrNoSuchSession is the sentinel Get returns for an unknown session ID.
// HandleGrant collapses this — along with an expired or revoked session —
// to the SAME wire invalid_grant (oracle-leak hardening, AGENTS.md §3): a
// caller must never be able to distinguish "never existed" from "expired"
// from "revoked".
var ErrNoSuchSession = errors.New("agentidentity: no such agent session")

// AgentSessionStore persists [AgentSession] delegation records.
// MemoryAgentSessionStore is the in-process reference implementation; a
// durable backend (sqlite/etcd) implements the same interface.
type AgentSessionStore interface {
	// Create persists a new session after Validate. Returns the wrapped
	// ErrInvalidSession on a malformed record.
	Create(ctx context.Context, sess *AgentSession) error

	// Get resolves a session by ID, or ErrNoSuchSession when unknown.
	// Returns the record REGARDLESS of expiry/revocation state — callers
	// (grant.go's checkSessionLive) decide liveness; Get itself never
	// filters, so an admin listing/audit tool can still see a revoked
	// session's history.
	Get(ctx context.Context, id string) (*AgentSession, error)

	// Revoke marks the session Revoked (stamping RevokedAt) so it can
	// never mint again. Idempotent: revoking an already-revoked or
	// unknown session returns nil — no oracle on whether the ID ever
	// existed, mirroring oauth.RefreshTokenFamilyTracker.DeleteFamily's
	// contract.
	Revoke(ctx context.Context, id string) error

	// RevokeAllForHuman revokes EVERY live session HumanSubject has
	// extended — the "revoke a whole cohort" hook (mirrors
	// (*sso.Server).RevokeTenantRefreshTokens's bulk-revocation shape) for
	// an operator/self-service flow reacting to a compromised or
	// offboarded human account. Returns the count actually transitioned
	// (already-revoked sessions are not re-counted).
	RevokeAllForHuman(ctx context.Context, humanSubject string) (int, error)
}
