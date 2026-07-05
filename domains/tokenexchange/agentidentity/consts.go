package agentidentity

// Audit metadata keys (audit.SetMeta) this package stamps. Named here
// (rather than inlined) per AGENTS.md §4 — no literal leaks.
const (
	// MetaAgentSessionID is the AgentSession.ID a delegation_token mint or
	// revoke event pertains to.
	MetaAgentSessionID = "agent_session_id"
	// MetaRevokedCount is the count of sessions a cohort revoke
	// (RevokeAllForHuman) transitioned.
	MetaRevokedCount = "revoked_count"
)
