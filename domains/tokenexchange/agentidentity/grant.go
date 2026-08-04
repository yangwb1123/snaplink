package agentidentity

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// EntitlementsFunc resolves humanSubject's CURRENT scope entitlement — the
// authoritative "what can this person do right now" source (e.g. wrapping
// an operator's permissions.Provider role expansion, or a static per-user
// scope lookup). HandleGrant calls this on EVERY mint, never a cached
// value, so a human's shrunk entitlement (role change, permission
// revocation, offboarding) is reflected on the agent's very next token.
type EntitlementsFunc func(ctx context.Context, humanSubject string) ([]string, error)

// Request is the /token parameter subset the delegation_token grant reads
// (interfaces/sso maps oauth.TokenRequest onto this).
type Request struct {
	// AgentSessionID names the AgentSession the human's authorization
	// created — the delegation "handle" this grant redeems.
	AgentSessionID string
	// Scope optionally narrows (never widens) the minted token below the
	// full three-way intersection (Agent.AllowedScopes ∩
	// AgentSession.GrantedScopes ∩ live human entitlement). Empty requests
	// the whole intersection.
	Scope string
	// Resource carries RFC 8707 resource indicators through to the issued
	// token's audience, same as every other grant.
	Resource []string
}

// Deps is what HandleGrant needs. Every method is REQUIRED — unlike the
// nil-is-a-no-op OPTIONAL hooks elsewhere in this codebase (e.g.
// tokenexchange.Policy), a Deps missing any one capability could only mint
// an under-checked delegation token, so interfaces/sso's
// WithAgentDelegationGrant refuses to register the grant at all unless
// every piece (AgentProvider, AgentSessionStore, EntitlementsFunc) is
// supplied — an unwired build stays byte-identical (grant_type never
// registered, falls through to unsupported_grant_type).
type Deps interface {
	Agents() AgentProvider
	Sessions() AgentSessionStore
	HumanScopes(ctx context.Context, humanSubject string) ([]string, error)
	IssuerForClient(c *core.Client) (string, core.TokenIssuer, error)
	DPoPTokenTypeOr(defaultType, jkt string) string
	RecordTokenIssued(ctx core.HandlerContext, clientID, strategy, subjectID string)
	Auditor() *audit.Recorder
	SrvLogger() spi.Logger
}

// HandleGrant processes the delegation_token grant
// (core.GrantTypeAgentDelegation): an AI agent redeems a previously-created
// AgentSession for an access token whose `sub` is the AGENT's own identity
// but whose `act` claim (RFC 8693 §4.1) points back to the delegating
// human — the SAME act-chain shape internal/handler/tokengrant's
// token-exchange grant uses (core.ActorClaim), reused here rather than
// inventing a new delegation claim shape.
//
// Oracle-leak collapse (AGENTS.md §3): missing agent_session_id ->
// invalid_request; ANY of unknown/expired/revoked session, unknown agent,
// or a human-entitlement-resolution error -> the SAME invalid_grant (a
// caller must never be able to distinguish these); a requested scope
// outside the resolved intersection, or an intersection that comes out
// empty -> invalid_scope.
//
// Fail-closed throughout (AGENTS.md §3): every failure denies the mint;
// there is no partial-success path.
func HandleGrant(d Deps, ctx core.HandlerContext, client *core.Client, req Request, dpopJKT, mtlsX5T string) {
	if req.AgentSessionID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	reqCtx := ctx.Request().Context()

	sess, agent, ok := resolveSessionAndAgent(d, reqCtx, req.AgentSessionID)
	if !ok {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return
	}

	granted, err := resolveGrantedScopes(d, reqCtx, agent, sess, req.Scope)
	if err != nil {
		// Entitlement resolution failing is a STORE/DEPENDENCY error, not a
		// property of this specific request — collapse it into the SAME
		// invalid_grant every other session/agent-resolution failure above
		// returns (oracle-leak collapse, AGENTS.md §3), rather than
		// invalid_scope which would tell a caller the session+agent DID
		// resolve. An empty or caller-over-reaching scope result is a
		// distinct, request-shape problem — invalid_scope.
		if errors.Is(err, errEntitlementResolution) {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
			return
		}
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))
		return
	}

	mintDelegationToken(d, ctx, client, agent, sess, granted, req.Resource, dpopJKT, mtlsX5T)
}

// resolveSessionAndAgent fetches + fail-closed-validates the AgentSession,
// then resolves its Agent. Both failure classes collapse to the same
// caller-visible ok=false (see HandleGrant's oracle-leak collapse); the
// internal reason is logged (never returned) so an operator can still tell
// WHICH check failed from server-side logs.
func resolveSessionAndAgent(d Deps, ctx context.Context, sessionID string) (*AgentSession, *Agent, bool) {
	sess, err := d.Sessions().Get(ctx, sessionID)
	if err == nil {
		err = checkSessionLive(sess, time.Now())
	}
	if err != nil {
		d.SrvLogger().Info("agent delegation: session not usable; denying (fail-closed)", "error", err)
		return nil, nil, false
	}
	agent, err := d.Agents().Get(ctx, sess.AgentID)
	if err != nil || agent == nil {
		d.SrvLogger().Error("agent delegation: agent lookup failed for a live session",
			"agent_id", sess.AgentID, "error", err)
		return nil, nil, false
	}
	return sess, agent, true
}

// errEntitlementResolution marks a HumanScopes failure specifically — see
// HandleGrant's err-classification comment: this collapses to invalid_grant
// (a dependency/store failure), never invalid_scope (which would confirm
// the session+agent resolved and only the scope math failed).
var errEntitlementResolution = errors.New("agentidentity: human entitlement resolution failed")

// errScopeDenied marks an empty or caller-over-reaching scope outcome —
// collapses to invalid_scope.
var errScopeDenied = errors.New("agentidentity: no usable scope for this delegation")

// resolveGrantedScopes computes the fail-closed three-way intersection
// (Agent.AllowedScopes ∩ AgentSession.GrantedScopes ∩ live human
// entitlement), then applies an optional caller-requested narrowing. A
// requested scope OUTSIDE the intersection is REJECTED rather than
// silently dropped — mirrors internal/handler/tokengrant's cross-tenant
// guest-hop narrowing: silently narrowing would hide a misconfigured or
// over-reaching caller from its operator.
func resolveGrantedScopes(d Deps, ctx context.Context, agent *Agent, sess *AgentSession, requestedScope string) ([]string, error) {
	humanScopes, err := d.HumanScopes(ctx, sess.HumanSubject)
	if err != nil {
		d.SrvLogger().Error("agent delegation: human entitlement resolution failed; denying (fail-closed)",
			"human", sess.HumanSubject, "error", err)
		return nil, errEntitlementResolution
	}
	granted := IntersectScopes(agent.AllowedScopes, sess.GrantedScopes, humanScopes)
	if requestedScope == "" {
		if len(granted) == 0 {
			return nil, errScopeDenied
		}
		return granted, nil
	}
	requested := strings.Fields(requestedScope)
	for _, s := range requested {
		if !slices.Contains(granted, s) {
			return nil, errScopeDenied
		}
	}
	if len(requested) == 0 {
		return nil, errScopeDenied
	}
	return requested, nil
}

// mintDelegationToken issues the access token: sub = the agent's own
// identity, act = {sub: HumanSubject} (RFC 8693 §4.1 — a single-hop chain;
// this grant mints from an AgentSession, never from an inbound token, so
// there is no deeper existing chain to prepend onto).
func mintDelegationToken(d Deps, ctx core.HandlerContext, client *core.Client, agent *Agent, sess *AgentSession, granted, resources []string, dpopJKT, mtlsX5T string) {
	strategy, ti, err := d.IssuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrNoTokenStrategy))
		return
	}
	token, err := ti.Issue(ctx.Request().Context(), &core.Subject{
		ID:                  agent.ID,
		ClientID:            client.ID,
		TenantID:            client.TenantID,
		Resources:           resources,
		TTL:                 client.AccessTokenTTL,
		Actor:               &core.ActorClaim{Subject: sess.HumanSubject},
		ConfirmationJKT:     dpopJKT,
		ConfirmationX5TS256: mtlsX5T,
	}, granted)
	if err != nil {
		d.SrvLogger().Error("agent delegation token issuance failed", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	d.RecordTokenIssued(ctx, client.ID, strategy, agent.ID)
	auditDelegationMint(d, ctx, client, agent, sess, granted)
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyAccessToken:   token.AccessToken,
		core.KeyTokenType:     d.DPoPTokenTypeOr(token.TokenType, dpopJKT),
		core.KeyExpiresIn:     token.ExpiresIn,
		core.KeyScope:         token.Scope,
		core.KeyTokenStrategy: strategy,
	})
}

// auditDelegationMint records the delegation trail: which agent minted a
// token, acting for which human, under which AgentSession, with which
// scopes — SetMeta only, never a raw map literal (AGENTS.md §4).
func auditDelegationMint(d Deps, ctx core.HandlerContext, client *core.Client, agent *Agent, sess *AgentSession, granted []string) {
	if d.Auditor() == nil {
		return
	}
	evt := &audit.Event{
		Type:     audit.EventAgentDelegationTokenIssued,
		Outcome:  audit.OutcomeSuccess,
		ActorID:  agent.ID,
		ClientID: client.ID,
		ActorIP:  audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, core.KeyOriginalSubject, sess.HumanSubject)
	audit.SetMeta(evt, MetaAgentSessionID, sess.ID)
	audit.SetMeta(evt, core.KeyScope, strings.Join(granted, " "))
	d.Auditor().Record(ctx.Request().Context(), evt)
}
