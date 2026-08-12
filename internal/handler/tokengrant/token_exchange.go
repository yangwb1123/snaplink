package tokengrant

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/domains/tokenexchange"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/protocols/oauth/scoperegistry"
	"github.com/yangwb1123/snaplink/protocols/oidc"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// TokenExchangeRequest is the subset of /token parameters the RFC 8693
// token-exchange grant cares about. Pulled out of the main /token request struct
// so the grant reads cleanly; defined here (not in root) so the extracted grant
// handler can reference it without a root->handler import cycle.
type TokenExchangeRequest struct {
	SubjectToken       string
	SubjectTokenType   string
	ActorToken         string
	ActorTokenType     string
	Resource           []string
	Audience           []string
	Scope              string
	RequestedTokenType string
	// RFC 9470 step-up: caller-asserted ACR floor for the exchanged token.
	// Space-separated values; the inbound subject_token's ACR claim MUST be a
	// member of this set or the exchange fails with
	// insufficient_user_authentication. Empty = no demand (inbound ACR
	// transparently propagates as today).
	ACRValues string
	// DPoPJKT / MTLSX5T are the sender-constraint thumbprints captured from the
	// /token request (RFC 9449 DPoP proof JKT / RFC 8705 mTLS x5t#S256). When a
	// proof/cert was presented, the exchanged access token is cnf-bound to it,
	// exactly as the authorization_code / refresh / CIBA / client_credentials
	// grants do. Empty = no sender-constraint (unbound token, as before).
	DPoPJKT string
	MTLSX5T string
}

// TokenExchangeDeps is what HandleTokenExchangeGrant needs. *sso.Server
// satisfies it via accessors_token_grant.go with a compile-time guard there.
type TokenExchangeDeps interface {
	RefreshTokenStore() oauth.RefreshTokenStore
	DeviceSecretStore() core.DeviceSecretStore
	IssuerForClient(c *core.Client) (string, core.TokenIssuer, error)
	IDTokenIssuerForClient(c *core.Client) (oidc.IDTokenIssuer, bool, error)
	ValidateAnyToken(ctx context.Context, token string) (*core.TokenClaims, string, error)
	ResolveLocalSubject(ctx context.Context, sub string) (string, error)
	ApplyPairwiseSubject(ctx context.Context, client *core.Client, localSub string) string
	IssueRefreshToken(ctx context.Context, userID, clientID, provider string, scopes []string, attributes map[string]string, familyID string, resources []string, authDetails []byte, sid string, authCtx oauth.RefreshAuthContext, clientTTLOverride time.Duration, confirmationJKT string) (string, error)
	MaybeEncryptIDToken(ctx context.Context, client *core.Client, signed string) (string, bool)
	DPoPTokenTypeOr(defaultType, jkt string) string
	SPIFFEValidator() *security.SPIFFEValidator
	SPIFFEAudience() string
	JTIReplayStore() security.JTIReplayStore
	JTIReplayFailClosed() bool
	Auditor() *audit.Recorder
	HandleDeviceSecretExchange(ctx core.HandlerContext, idTokenClaims *core.TokenClaims, rawIDToken, deviceSecret string, client *core.Client, req TokenExchangeRequest)
	RecordTokenIssued(ctx core.HandlerContext, clientID, strategy, subjectID string)
	RecordRefreshTokenIssued(ctx core.HandlerContext, clientID, subjectID string, rotation bool)
	RecordIDTokenIssued(ctx core.HandlerContext, clientID, subjectID string)
	RecordSubjectClientAccess(ctx context.Context, subject, clientID string)
	SrvLogger() spi.Logger
	// MaxTokenExchangeChainLifetime returns the OPTIONAL hard ceiling on how
	// old the delegation chain's underlying credential (subject_token's
	// AuthTime — the original end-user login or SPIFFE SVID presentation,
	// which every exchange hop propagates UNCHANGED) may be. 0 disables the
	// check — byte-identical to pre-feature behavior. See
	// tokExEnforceChainLifetime.
	MaxTokenExchangeChainLifetime() time.Duration
	// TokenExchangePolicy returns the OPTIONAL hop-authorization SPI (nil =
	// unwired, every hop allowed — byte-identical to pre-feature behavior).
	// See tokExEnforcePolicy.
	TokenExchangePolicy() tokenexchange.Policy
	// ExternalUserStore returns the OPTIONAL cross-tenant guest-record store
	// (WithExternalUserStore, domains/tenantcollab). Nil = the cross-tenant
	// B2B collaboration gate is a complete no-op — byte-identical to a build
	// without this feature. See tokExEnforceTenantCollaboration.
	ExternalUserStore() tenant.ExternalUserStore
	// TenantCollaborationStore returns the OPTIONAL tenant-to-tenant trust
	// allow-list (WithTenantCollaborationStore, domains/tenantcollab). Nil is
	// the same no-op as a nil ExternalUserStore above — BOTH must be wired
	// for the cross-tenant gate to activate.
	TenantCollaborationStore() tenant.CollaborationStore
	// HomeTenantForClient resolves the TenantID of the client identified by
	// clientID (i.e. the client a subject_token's ClientID claim names — the
	// client it was ORIGINALLY issued to), used to discover a token-exchange
	// subject's home tenant. Returns "" for an unknown/untenanted client or
	// an unwired ClientStore — treated as "no home tenant to police" by the
	// cross-tenant gate, exactly like an empty exchanging-client TenantID.
	HomeTenantForClient(ctx context.Context, clientID string) string
	// TokenExchangeChainStore returns the OPTIONAL RFC 8693 delegation-chain
	// persistence + read-visibility store (WithTokenExchangeChainStore,
	// domains/tokenexchange). Nil (the default) = tokExRecordChainHop is a
	// no-op — byte-identical to a build without this feature. Pure
	// observability; never consulted by any authorization decision.
	TokenExchangeChainStore() tokenexchange.ChainStore
	// ScopeRegistry returns the wired global scope registry (nil = unwired
	// no-op, the default-off byte-compat baseline).
	ScopeRegistry() scoperegistry.Registry
}

// HandleTokenExchangeGrant processes the RFC 8693 token-exchange grant. Behavior
// is byte-identical to the prior root handler.
//
// Oracle-leak collapse (AGENTS.md §3): missing/unsupported subject_token_type →
// invalid_request; subject_token validation failure → invalid_grant; actor_token
// validation/jti-replay failure → invalid_grant; unregistered resource/audience →
// invalid_target; scope expansion → invalid_scope; unsupported
// requested_token_type (and an id_token request with OIDC not configured) →
// invalid_request. RFC 8693 §4.1 act-chain nesting, RFC 9470 step-up, RFC 9396
// authorization_details, and OIDC §8 pairwise subject resolution are preserved.
func HandleTokenExchangeGrant(d TokenExchangeDeps, ctx core.HandlerContext, client *core.Client, req TokenExchangeRequest) {
	// Stages run in the SAME order as the prior monolith; each emits the exact
	// wire code it did at its gate position (see token_exchange_stages.go). The
	// per-stage collapse codes DIFFER and must NOT drift: invalid_request
	// (pre-flight types), invalid_grant (subject), insufficient_user_authentication
	// (RFC 9470 step-up), invalid_target / invalid_scope (targets+scopes).
	if tokExValidateRequestTypes(d, ctx, client, req) {
		return
	}
	st := &tokExState{confJKT: req.DPoPJKT, confX5T: req.MTLSX5T}
	// tokExRefuseNonDelegable rejects a NON-DELEGABLE break-glass subject_token
	// before any mint; short-circuited so st.claims is read only after resolve.
	if tokExResolveSubject(d, ctx, req, st) || tokExRefuseNonDelegable(ctx, st) {
		return
	}
	// Chain-level TTL (independent of any single hop's token TTL): the whole
	// delegation chain traces back to one credential-establishing event
	// (AuthTime), so this is checked as soon as st.claims is resolved.
	if lifecycleGrantBlocked(d, ctx, st.claims.Subject) || tokExEnforceChainLifetime(d, ctx, st) {
		return
	}
	if tokExStepUp(ctx, req, st) {
		return
	}
	if tokExResolveActorAndAuthorize(d, ctx, client, req, st) {
		return
	}
	if tokExResolveSubjectAndIssue(d, ctx, client, st) {
		return
	}
	tokExRecordChainHop(d, ctx, client, st)
	tokExAuditSPIFFE(d, ctx, client, st)

	st.resp = map[string]any{
		core.KeyAccessToken:     st.token.AccessToken,
		core.KeyIssuedTokenType: core.TokenTypeAccessToken,
		core.KeyTokenType:       d.DPoPTokenTypeOr(st.token.TokenType, req.DPoPJKT),
		core.KeyExpiresIn:       st.token.ExpiresIn,
		core.KeyScope:           st.token.Scope,
		core.KeyTokenStrategy:   st.strategy,
	}
	// Refresh path is FAIL-OPEN (caller keeps the access token on error).
	tokExIssueRefresh(d, ctx, client, req, st)
	// id_token path is FAIL-CLOSED (JWE-required-else-internal-error).
	if tokExIssueIDToken(d, ctx, client, req, st) {
		return
	}

	ctx.JSON(http.StatusOK, st.resp)
}

// tokExResolveActorAndAuthorize runs the three stages between step-up and
// issuance: actor resolution (including RFC 8693 §4.1.1 act-chain prepend +
// cycle detection), target/scope resolution, and the OPTIONAL operator-
// defined hop-policy hook. Extracted from HandleTokenExchangeGrant to keep it
// within the function-length budget; behavior/gate order is unchanged.
// Returns true when it has written a response (or fully handled a delegated
// device-secret exchange) and the caller must stop.
func tokExResolveActorAndAuthorize(d TokenExchangeDeps, ctx core.HandlerContext, client *core.Client, req TokenExchangeRequest, st *tokExState) bool {
	// Actor resolution: both-or-neither presence, the Native SSO device-secret
	// delegated path (which fully handles + returns), JTI-replay, and the act
	// chain prepend.
	if done, delegated := tokExResolveActor(d, ctx, client, req, st); done || delegated {
		return true
	}
	// Cycle detection (A -> B -> ... -> A): st.actor is the chain AFTER
	// tokExResolveActor's prepend, so this catches a newly-added actor that
	// already appears deeper in the chain it was just linked onto.
	if tokExActorChainHasCycle(st.actor) {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return true
	}
	if tokExResolveTargetsAndScopes(d, ctx, client, req, st) {
		return true
	}
	// Cross-tenant B2B collaboration gate (opt-in; nil stores are a no-op).
	if tokExEnforceTenantCollaboration(d, ctx, client, st) {
		return true
	}
	// Operator-defined hop authorization (opt-in; nil Policy is a no-op).
	return tokExEnforcePolicy(d, ctx, client, req, st)
}

// tokExRefuseNonDelegable refuses to exchange a subject_token that carries the
// break-glass live-impersonation marker. Such a credential is deliberately
// NON-DELEGABLE: exchanging it would mint a fresh token that keeps sub=target but
// (a) escapes the AdminSession revocation cascade (never registered under
// ImpersonationTokens), (b) sheds the act=admin attribution, and (c) takes the
// issuer-default TTL instead of the <=15m grant window. Oracle-safe: collapses to
// the SAME invalid_request the pre-flight type gates emit, revealing nothing about
// the token beyond "this request is not allowed". Returns true when it has written
// a response and the caller must stop — BEFORE any new token is minted.
func tokExRefuseNonDelegable(ctx core.HandlerContext, st *tokExState) bool {
	if core.IsBreakGlassImpersonationClaims(st.claims) {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return true
	}
	return false
}

// tokExRecordChainHop is the ONE call site bridging the act-chain
// construction above (tokExResolveActor) to durable, queryable chain
// history via the OPTIONAL tokenexchange.ChainStore
// (WithTokenExchangeChainStore). PURE OBSERVABILITY: fail-open
// (tokenexchange.RecordExchangeHopFailOpen — a store error or
// unavailability NEVER fails an already-successful grant), and a nil store
// (the default) is a no-op. Scoped deliberately to persistence + read
// visibility only — no cascade-revocation, no new cycle-detection beyond
// tokExActorChainHasCycle above.
func tokExRecordChainHop(d TokenExchangeDeps, ctx core.HandlerContext, client *core.Client, st *tokExState) {
	tokenexchange.RecordExchangeHopFailOpen(ctx.Request().Context(), d.TokenExchangeChainStore(),
		st.token.AccessToken, st.claims.JTI, st.claims.Subject, st.actor, client.ID,
		actChainDepth(st.actor), d.SrvLogger().Error)
}

// tokExIssueIDToken mints an id_token when requested_token_type is id_token.
// This path is FAIL-CLOSED: a non-openid scope is invalid_request, and any
// issuer/issuance/JWE-required failure collapses to the internal error. Returns
// true when it has written a response and the caller must stop.
func tokExIssueIDToken(d TokenExchangeDeps, ctx core.HandlerContext, client *core.Client, req TokenExchangeRequest, st *tokExState) bool {
	// RFC 8693 §2.2.1 id_token output. The access token is always returned. The
	// IDTokenIssuer was confirmed wired up-front (fail-closed invalid_request
	// above), so a resolution failure here is a genuine internal/tenant
	// misconfiguration, NOT a feature-off case.
	//
	// An id_token is only meaningful for an OIDC exchange — one carrying the
	// `openid` scope. A service-to-service exchange (no openid scope; e.g. a
	// SPIFFE SVID) has no user to assert, so demanding an id_token for it is a
	// malformed request → invalid_request (oracle-safe: identical to the
	// unsupported-type collapse).
	if req.RequestedTokenType != core.TokenTypeIDToken {
		return false
	}
	if !slices.Contains(st.scopes, core.ScopeOpenID) {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return true
	}
	enc, ok := tokExMintIDToken(d, ctx, client, st)
	if !ok {
		// tokExMintIDToken already wrote the fail-closed internal-error response
		// at whichever sub-gate (issuer resolution / issuance / JWE-required) it
		// failed at.
		return true
	}
	st.resp[core.KeyIDToken] = enc
	// issued_token_type reports the REQUESTED token type (id_token) — what the
	// caller asked the exchange to issue — while the access token is ALSO
	// returned alongside in access_token (RFC 8693 §2.2.1: requested_token_type
	// names what issued_token_type reports, not the exclusive output). The
	// requested id_token is delivered in the dedicated id_token member. This is
	// a deliberate non-exclusive-output design (see TestTokenExchange_IDTokenOutput).
	st.resp[core.KeyIssuedTokenType] = core.TokenTypeIDToken
	d.RecordIDTokenIssued(ctx, client.ID, st.claims.Subject)
	return false
}

// tokExMintIDToken resolves the per-client issuer, mints the id_token, and
// applies per-client JWE. This whole path is FAIL-CLOSED: any issuer-resolution,
// issuance, or JWE-required failure writes the internal error and returns
// ok=false. Returns the (possibly encrypted) id_token on success.
func tokExMintIDToken(d TokenExchangeDeps, ctx core.HandlerContext, client *core.Client, st *tokExState) (string, bool) {
	idIssuer, _, idErr := d.IDTokenIssuerForClient(client)
	if idErr != nil || idIssuer == nil {
		d.SrvLogger().Error("token exchange id_token issuer resolution failed", "client", client.ID, "error", idErr)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return "", false
	}
	// auth_time / acr / amr / sid propagate from the inbound subject_token
	// exactly as the access token above. AccessToken is the one just minted
	// so the issuer stamps OIDC Core §3.1.3.6 at_hash. No nonce: there is no
	// authorization request in a token-exchange.
	idToken, iErr := idIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
		Subject:       st.issuedSub,
		Audience:      client.ID,
		AuthTime:      st.claims.AuthTime,
		ACR:           st.claims.ACR,
		AMR:           append([]string(nil), st.claims.AMR...),
		Claims:        st.claims.Extra,
		SID:           st.claims.SID,
		ServingRegion: servingRegionFrom(ctx),
		AccessToken:   st.token.AccessToken,
		GrantedScopes: st.scopes, GrantedResources: st.resources, AuthorizationDetails: st.claims.AuthorizationDetails,
	})
	if iErr != nil {
		d.SrvLogger().Error("token exchange id_token issue failed", "client", client.ID, "error", iErr)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return "", false
	}
	// Per-client id_token JWE (OIDC §10.2) when configured — a no-op
	// pass-through when the client has no encrypted-response metadata.
	enc, ok := d.MaybeEncryptIDToken(ctx.Request().Context(), client, idToken)
	if !ok {
		// Encryption requested but no encrypter wired — omitting a requested
		// id_token silently would be a confusing partial success, so collapse
		// to the internal error.
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return "", false
	}
	return enc, true
}

// tokExEnforceChainLifetime enforces the OPTIONAL hard ceiling on the
// delegation chain's total age, independent of any single hop's access-token
// TTL. st.claims.AuthTime is the ORIGINAL credential-establishing moment (the
// end-user login, or the instant a SPIFFE JWT-SVID was presented) — every
// token-exchange hop propagates it UNCHANGED (RFC 9068 §2.2, AGENTS.md §3),
// so it is the one signal that survives no matter how many times the chain
// has already been re-exchanged; the per-token TTL/exp does NOT (each hop
// gets a fresh one). Returns true (invalid_grant already written, fail-
// closed, oracle-leak collapse) when the cap is exceeded. A non-positive cap
// (disabled, the default) or a zero AuthTime (a service-to-service subject
// with no end-user/SPIFFE anchor — e.g. a plain client_credentials-derived
// token) skip the check entirely: there is nothing to measure the chain's
// age from, so this is byte-identical to pre-feature behavior for those.
func tokExEnforceChainLifetime(d TokenExchangeDeps, ctx core.HandlerContext, st *tokExState) bool {
	maxAge := d.MaxTokenExchangeChainLifetime()
	if maxAge <= 0 || st.claims.AuthTime.IsZero() {
		return false
	}
	if time.Since(st.claims.AuthTime) <= maxAge {
		return false
	}
	ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
	return true
}

// tokExActorChainHasCycle detects an RFC 8693 §4.1 act-chain delegation
// cycle: the same actor identity appearing twice in one chain (A -> B -> A).
// A legitimate multi-hop delegation always ADDS a new, distinct link; a
// repeat most plausibly signals either a compromised/looping service
// topology or a replayed/crafted subject_token — worth refusing outright
// rather than letting the chain grow unboundedly cyclic. actor is st.actor
// AFTER tokExResolveActor's prepend (actor.Subject is the just-added link,
// actor.Actor is the chain it was linked onto); nil (no actor_token
// presented this hop) can never cycle.
func tokExActorChainHasCycle(actor *core.ActorClaim) bool {
	if actor == nil {
		return false
	}
	for a := actor.Actor; a != nil; a = a.Actor {
		if a.Subject == actor.Subject {
			return true
		}
	}
	return false
}

// tokExEnforcePolicy consults the OPTIONAL operator-defined
// tokenexchange.Policy after the hop's actor/scopes/resources are fully
// resolved — the last gate before anything is minted. Nil Policy (unwired,
// the default) is a no-op. An error OR an explicit deny both collapse to the
// SAME invalid_grant every other token-exchange failure returns (fail-
// closed + oracle-leak collapse, AGENTS.md §3): this SPI's whole purpose is
// to let an operator BLOCK specific delegations, so silently allowing on an
// evaluation error would defeat it. Returns true when it has written a
// response and the caller must stop.
func tokExEnforcePolicy(d TokenExchangeDeps, ctx core.HandlerContext, client *core.Client, req TokenExchangeRequest, st *tokExState) bool {
	policy := d.TokenExchangePolicy()
	if policy == nil {
		return false
	}
	actorSubject := ""
	if st.actor != nil {
		actorSubject = st.actor.Subject
	}
	allow, err := policy.Allow(ctx.Request().Context(), tokenexchange.Hop{
		SubjectID:          st.claims.Subject,
		ActorSubject:       actorSubject,
		ClientID:           client.ID,
		RequestedTokenType: req.RequestedTokenType,
		Scopes:             st.scopes,
		Resources:          st.resources,
	})
	if err != nil {
		d.SrvLogger().Error("token exchange policy evaluation failed; denying (fail-closed)",
			"error", err, "client", client.ID)
	}
	if err != nil || !allow {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return true
	}
	return false
}

// tokExEnforceTenantCollaboration is the OPTIONAL cross-tenant B2B gate
// (domains/tenantcollab): it activates only when BOTH an ExternalUserStore
// and a TenantCollaborationStore are wired AND the subject_token's home
// tenant differs from the exchanging client's — a genuine cross-tenant hop.
// Same-tenant exchanges and store-less exchanges are UNAFFECTED (this gate
// only ever NARROWS, never widens, tenant isolation). A hop requires BOTH a
// TenantCollaboration trust row AND a GuestRecord registration; either miss
// collapses to the SAME invalid_grant every other exchange failure returns
// (oracle-leak collapse — no signal about WHICH check failed). On success
// the guest's registered Roles further narrow the resolved scope set (a
// scope outside Roles is invalid_scope, mirroring tokExResolveScope). The
// hop is audited with guest + home-tenant context. Returns true when it has
// written a response and the caller must stop.
func tokExEnforceTenantCollaboration(d TokenExchangeDeps, ctx core.HandlerContext, client *core.Client, st *tokExState) bool {
	extStore := d.ExternalUserStore()
	collabStore := d.TenantCollaborationStore()
	if extStore == nil || collabStore == nil {
		return false
	}
	guestTenant := client.TenantID
	if guestTenant == "" {
		return false
	}
	homeTenant := d.HomeTenantForClient(ctx.Request().Context(), st.claims.ClientID)
	if homeTenant == "" || homeTenant == guestTenant {
		return false
	}
	guest, ok := tokExAuthorizeGuestHop(ctx, collabStore, extStore, guestTenant, homeTenant, st.claims.Subject)
	if !ok {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return true
	}
	if len(guest.Roles) > 0 {
		for _, s := range st.scopes {
			if !slices.Contains(guest.Roles, s) {
				// A requested scope exceeds this guest's entitlement — REJECT
				// rather than silently narrow (same philosophy as
				// oauthvalidate.GrantedScopes rule 3: silent narrowing would
				// hide a misconfigured/over-reaching caller from its operator).
				ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))
				return true
			}
		}
	}
	// Global scope registry (opt-in): the guest-narrowed set is the effective
	// scope for the hop — post-entitlement, pre-issuance.
	if scoperegistry.RejectUnregistered(ctx, d.ScopeRegistry(), st.scopes) {
		return true
	}
	tokExAuditCrossTenant(d, ctx, client, homeTenant, guestTenant, st.claims.Subject)
	return false
}

// tokExAuthorizeGuestHop consults the trust + registration stores for a
// genuine cross-tenant hop. ok=false (deny) on ANY error or missing record —
// fail-closed, no partial trust. guest.HomeTenantID is cross-checked against
// the independently-resolved homeTenant so a registration claiming a
// DIFFERENT home tenant than the subject_token's actual origin is treated as
// tampering/misconfiguration, not a trusted guest hop.
func tokExAuthorizeGuestHop(ctx core.HandlerContext, collabStore tenant.CollaborationStore, extStore tenant.ExternalUserStore, guestTenant, homeTenant, subjectID string) (*tenant.GuestRecord, bool) {
	trusted, terr := collabStore.IsTrusted(ctx.Request().Context(), guestTenant, homeTenant)
	if terr != nil || !trusted {
		return nil, false
	}
	guest, gerr := extStore.Get(ctx.Request().Context(), guestTenant, subjectID)
	if gerr != nil || guest == nil || guest.HomeTenantID != homeTenant {
		return nil, false
	}
	return guest, true
}

// tokExAuditCrossTenant records the cross-tenant B2B collaboration audit
// trail: the guest-tenant context (ClientID, guest_tenant_id) AND the
// originating home-tenant identity (original_subject, original_tenant) so a
// SIEM can always trace a guest action back to its home account.
func tokExAuditCrossTenant(d TokenExchangeDeps, ctx core.HandlerContext, client *core.Client, homeTenant, guestTenant, subjectID string) {
	if d.Auditor() == nil {
		return
	}
	evt := &audit.Event{
		Type:     audit.EventCrossTenantTokenExchange,
		Outcome:  audit.OutcomeSuccess,
		ActorID:  subjectID,
		ClientID: client.ID,
		ActorIP:  audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, core.KeyOriginalSubject, subjectID)
	audit.SetMeta(evt, core.KeyOriginalTenant, homeTenant)
	audit.SetMeta(evt, core.KeyGuestTenantID, guestTenant)
	d.Auditor().Record(ctx.Request().Context(), evt)
}
