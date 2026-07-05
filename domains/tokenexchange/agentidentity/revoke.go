package agentidentity

import (
	"context"
	"strconv"

	"github.com/snaplink/sso/platform/audit"
)

// RevokeSession revokes one AgentSession by id and records the action in
// the audit trail (SetMeta, never a raw map literal, AGENTS.md §4) — the
// call site an integrator's admin surface (or a future self-service "turn
// off my agent" endpoint) should use INSTEAD of calling
// AgentSessionStore.Revoke directly, so a delegation's revocation is never
// silently unaudited. Idempotent (see AgentSessionStore.Revoke doc). A nil
// auditor is a no-op audit — the store-side revocation still applies.
func RevokeSession(ctx context.Context, sessions AgentSessionStore, auditor *audit.Recorder, sessionID string) error {
	err := sessions.Revoke(ctx, sessionID)
	auditRevoke(ctx, auditor, sessionID, err)
	return err
}

// RevokeAllForHuman revokes EVERY delegation session humanSubject has
// extended — the "revoke a whole cohort" hook mirroring
// (*sso.Server).RevokeTenantRefreshTokens's bulk-revocation shape: an
// operator/self-service flow reacting to a compromised or offboarded human
// account can kill every agent delegation in one call rather than tracking
// down each session id. Like RevokeSession, this is the audited call site —
// prefer it over AgentSessionStore.RevokeAllForHuman directly.
func RevokeAllForHuman(ctx context.Context, sessions AgentSessionStore, auditor *audit.Recorder, humanSubject string) (int, error) {
	n, err := sessions.RevokeAllForHuman(ctx, humanSubject)
	auditRevokeCohort(ctx, auditor, humanSubject, n, err)
	return n, err
}

// auditRevoke records a single-session revocation (or its failure).
func auditRevoke(ctx context.Context, auditor *audit.Recorder, sessionID string, err error) {
	if auditor == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventAgentSessionRevoked,
		Outcome: outcomeOf(err),
		ActorID: sessionID,
	}
	audit.SetMeta(evt, MetaAgentSessionID, sessionID)
	auditor.Record(ctx, evt)
}

// auditRevokeCohort records a bulk per-human revocation. A zero count
// still records — a SIEM sees the revocation was attempted even when the
// human held no live delegation sessions (mirrors
// (*sso.Server).auditTenantSessionsRevoked's same zero-count discipline).
func auditRevokeCohort(ctx context.Context, auditor *audit.Recorder, humanSubject string, count int, err error) {
	if auditor == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventAgentSessionRevoked,
		Outcome: outcomeOf(err),
		ActorID: humanSubject,
	}
	audit.SetMeta(evt, MetaRevokedCount, strconv.Itoa(count))
	auditor.Record(ctx, evt)
}

func outcomeOf(err error) audit.Outcome {
	if err != nil {
		return audit.OutcomeFailure
	}
	return audit.OutcomeSuccess
}
