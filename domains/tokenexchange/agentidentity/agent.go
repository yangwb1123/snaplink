// Package agentidentity implements first-class AI-agent identities and the
// bounded, revocable delegation sessions that let a human authorize an
// agent to act on their behalf — the delegation_token /token grant's
// domain model. It is the same delegation SHAPE
// domains/tokenexchange's Hop/Policy SPI already formalizes (a bounded
// grant of authority from one principal to another, minted with full
// act-chain provenance), through a DIFFERENT entry point: a dedicated
// /token grant type that MINTS a fresh delegated token, rather than an
// exchange of an existing one.
//
// Nested under domains/tokenexchange (rather than its own top-level
// domains/agentidentity) because domains/ is at its frozen per-directory
// subdir-fanout ceiling (directory_fanout_test.go) — the same rationale
// domains/tenant/tenant_collab.go documents for cross-tenant B2B
// collaboration, and the same "give a new, related-but-distinct concern its
// own nested package" idiom platform/lifecycle/{webhook,sessionhub,...}
// use once platform/ hit the SAME ceiling. A further nested memory/
// sub-package (the pattern domains/tokenexchange/memory itself uses) is
// NOT an option here: domains/tokenexchange/agentidentity is already at
// the repo's directory-depth ceiling of 3 (maxdepth_test.go), so the
// Memory* reference implementations below live as sibling files in THIS
// package instead of a nested one.
//
// Two cooperating records model the feature (mirrors domains/tenant's
// GuestRecord + TenantCollaboration split):
//
//   - [Agent] is the STATIC identity: a stable id (the value that ends up
//     as a minted token's `sub`), a human-readable DisplayName/Description,
//     and AllowedScopes — the ABSOLUTE ceiling on what this agent may ever
//     be delegated, independent of any one human.
//   - [AgentSession] is the BOUNDED, per-delegation grant: one human
//     authorizing one agent to act on their behalf for a limited time,
//     carrying its OWN GrantedScopes (already narrowed to <= that human's
//     entitlement at grant-creation time).
//
// HandleGrant (grant.go) folds THREE sets down to one at every mint —
// Agent.AllowedScopes, AgentSession.GrantedScopes, and the human's CURRENT
// entitlement (re-resolved live, never trusted from the session's original
// snapshot) — via IntersectScopes, so a delegated agent's authority can
// never exceed, and never outlive, the delegating human's own: any one of
// the three narrowing (an operator tightening an agent's policy, a
// revoked session, or the human losing a permission) narrows or kills the
// token on its very NEXT mint. Revocation is fail-closed (AGENTS.md §3):
// an expired or Revoked AgentSession can never mint, checked
// unconditionally before anything else.
package agentidentity

import (
	"context"
	"errors"
	"time"
)

// Agent is a first-class identity for an AI agent acting in this system —
// distinct from both a human core.User and an OAuth core.Client. ID is the
// stable value that ends up as a minted delegation_token's `sub`;
// DisplayName/Description are for admin/consent UI. AllowedScopes is the
// ABSOLUTE ceiling on what this agent may ever be delegated, independent
// of any one human's own entitlement — HandleGrant additionally narrows by
// the delegating human's CURRENT entitlement and by the specific
// AgentSession's GrantedScopes (see grant.go's IntersectScopes fold).
type Agent struct {
	ID            string
	DisplayName   string
	Description   string
	AllowedScopes []string
	CreatedAt     time.Time
}

// Validate sanity-checks an Agent before registration.
func (a *Agent) Validate() error {
	if a.ID == "" {
		return errors.Join(ErrInvalidAgent, errors.New("id required"))
	}
	if a.DisplayName == "" {
		return errors.Join(ErrInvalidAgent, errors.New("display_name required"))
	}
	return nil
}

// ErrInvalidAgent wraps Agent.Validate failures.
var ErrInvalidAgent = errors.New("agentidentity: invalid agent")

// ErrNoSuchAgent is the sentinel Get returns for an unregistered agent ID.
var ErrNoSuchAgent = errors.New("agentidentity: no such agent")

// AgentProvider registers and resolves AI-agent identities — the SPI a
// deployment wires so agent identities live in whatever backend it already
// operates (in-process for tests/single-replica, or a durable store keyed
// the same way core.ClientStore/core.UserProvider are).
// MemoryAgentProvider is the in-process reference implementation.
type AgentProvider interface {
	// Get resolves an agent by ID, or ErrNoSuchAgent when unregistered.
	Get(ctx context.Context, agentID string) (*Agent, error)

	// Register upserts an agent identity (create or update-in-place, keyed
	// by ID) after Validate. Idempotent by design — re-registering the
	// same ID replaces its DisplayName/Description/AllowedScopes, mirroring
	// core.ClientStore's upsert discipline for a small, operator-curated
	// identity set.
	Register(ctx context.Context, agent *Agent) error

	// List returns every registered agent. Order unspecified.
	List(ctx context.Context) ([]*Agent, error)
}
