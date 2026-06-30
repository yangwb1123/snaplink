package tokengrant

import (
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
)

// MaxActChainDepth caps the RFC 8693 §4.1 `act` delegation chain length.
// A subject_token whose act chain has already reached this depth cannot
// accept another prepend; unbounded nesting risks exponential processing
// on each subsequent exchange hop.
const MaxActChainDepth = 10

// actChainDepth counts the links in an *core.ActorClaim chain.
// nil (no delegation) returns 0.
func actChainDepth(actor *core.ActorClaim) int {
	depth := 0
	for actor != nil {
		depth++
		actor = actor.Actor
	}
	return depth
}

// tokExState carries the values resolved across the RFC 8693 token-exchange
// stage helpers. It exists only to keep each stage under the per-function
// budgets while leaving every wire code emitted at its original gate position;
// it holds no behavior of its own.
type tokExState struct {
	claims    *core.TokenClaims
	spiffeID  *security.SPIFFEID
	actor     *core.ActorClaim
	resources []string
	scopes    []string
	strategy  string
	ti        core.TokenIssuer
	issuedSub string
	token     *core.Token
	resp      map[string]any
	// confJKT / confX5T are the sender-constraint thumbprints (DPoP JKT / mTLS
	// x5t#S256) captured from the /token request; set on the issued access token's
	// cnf so a sender-constrained exchange yields a bound token, not an unbound one.
	confJKT string
	confX5T string
}

// tokExValidateRequestTypes runs the RFC 8693 pre-flight type validation. Every
// gate here collapses to invalid_request (or the dedicated not-configured codes
// for refresh/id_token outputs) BEFORE any token is inspected. Returns true when
// it has already written a response and the caller must stop.
func tokExValidateRequestTypes(d TokenExchangeDeps, ctx core.HandlerContext, client *core.Client, req TokenExchangeRequest) bool {
	if req.SubjectToken == "" || req.SubjectTokenType == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return true
	}
	if req.SubjectTokenType != core.TokenTypeAccessToken &&
		req.SubjectTokenType != core.TokenTypeJWT &&
		req.SubjectTokenType != core.TokenTypeIDToken {
		// RFC 8693 §2.1 lists more token types; this server handles signed
		// access tokens + JWTs, plus id_token for the Native SSO 1.0 device-
		// secret exchange (handled in the actor branch below).
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return true
	}
	if req.RequestedTokenType != "" &&
		req.RequestedTokenType != core.TokenTypeAccessToken &&
		req.RequestedTokenType != core.TokenTypeRefreshToken &&
		req.RequestedTokenType != core.TokenTypeIDToken {
		// Access + Refresh + ID token supported; SAML1/2 are future work.
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return true
	}
	// Refresh-token output requires a wired refresh store — without it there's no
	// way to honor the resulting rotation grant. Fail fast rather than silently
	// downgrade to access-only.
	if req.RequestedTokenType == core.TokenTypeRefreshToken && d.RefreshTokenStore() == nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrRefreshTokenNotConfigured))
		return true
	}
	// RFC 8693 §2.2.1 id_token output requires a wired IDTokenIssuer. Without one
	// this AS instance cannot produce the requested representation — collapse to
	// invalid_request so no oracle reveals whether OIDC is configured. Resolved
	// against the per-client (tenant-aware) issuer so a tenant whose strategy is
	// non-OIDC also fails closed here rather than at issuance time.
	if req.RequestedTokenType == core.TokenTypeIDToken {
		if _, emit, idErr := d.IDTokenIssuerForClient(client); idErr != nil || !emit {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
			return true
		}
	}
	return false
}

// tokExResolveSubject validates the subject_token, applying the SPIFFE JWT-SVID
// fallback, and collapses any failure to invalid_grant. On success it stores the
// resolved claims (and any SPIFFE id) on st. Returns true when it has written a
// response and the caller must stop.
func tokExResolveSubject(d TokenExchangeDeps, ctx core.HandlerContext, req TokenExchangeRequest, st *tokExState) bool {
	claims, _, err := d.ValidateAnyToken(ctx.Request().Context(), req.SubjectToken)
	// SPIFFE JWT-SVID fallback (cluster C1). Tried ONLY when the local-issuer path
	// FAILED, the validator is wired, and the inbound type is the standard `jwt`
	// type SVIDs use. The validator requires the `sub` to be a spiffe:// URI in
	// the configured trust domain, so a foreign non-SVID JWT still fails and
	// collapses to the SAME invalid_grant below. On success the SVID is mapped
	// onto a synthetic claims set the existing issuance path reuses.
	if (err != nil || claims == nil) && d.SPIFFEValidator() != nil && req.SubjectTokenType == core.TokenTypeJWT {
		if id, verr := d.SPIFFEValidator().Validate(ctx.Request().Context(), req.SubjectToken, d.SPIFFEAudience()); verr == nil {
			st.spiffeID = id
			// Build the subject claims from the SVID. AMR=["spiffe"] tells
			// downstream services this was a mesh-workload authentication (RFC
			// 8176). AuthTime=now because the exchange is the moment the workload
			// presented a valid SVID.
			claims = &core.TokenClaims{
				Subject:  id.URI,
				Extra:    id.Attributes(),
				AuthTime: time.Now(),
				AMR:      []string{core.AMRSpiffe},
			}
			err = nil
		}
	}
	if err != nil || claims == nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return true
	}
	st.claims = claims
	// RFC 8693 §2.1 + RFC 9449 §5: the exchange MUST NOT reduce the protection
	// level below the subject_token. A DPoP-bound subject (cnf.jkt present) MUST
	// be exchanged by a requester that also presents a DPoP proof — absence would
	// issue an unbound (bearer) token from a bound one. We do NOT require the SAME
	// key; an intermediary may legitimately bind to its own key. The violation is
	// presenting NO proof at all. Mirrors the key-continuity check at refresh:79
	// but uses a presence-only guard rather than an exact-match guard. Same rule
	// for mTLS-bound subjects (cnf.x5t#S256 — a client cert must be presented).
	if st.claims.ConfirmationJKT != "" && req.DPoPJKT == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return true
	}
	if st.claims.ConfirmationX5TS256 != "" && req.MTLSX5T == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return true
	}
	return false
}

// tokExStepUp enforces the RFC 9470 step-up demand. A failure collapses to the
// DISTINCT insufficient_user_authentication code (NOT invalid_grant) so SPAs
// branch on it uniformly across grants. Returns true when it has written a
// response and the caller must stop.
func tokExStepUp(ctx core.HandlerContext, req TokenExchangeRequest, st *tokExState) bool {
	// RFC 9470 step-up: when the caller demands a minimum ACR via `acr_values`,
	// the inbound subject_token's ACR claim MUST match at least one value in the
	// demand set. Otherwise the AS would have to re-authenticate the user, which
	// token-exchange (server-to-server) can't do. Same wire shape as the
	// resource-server challenge so SPAs branch on it uniformly across grants.
	if req.ACRValues != "" {
		demanded := strings.Fields(req.ACRValues)
		if !oauth.ACRMatchesAny(st.claims.ACR, demanded) {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(security.ErrInsufficientUserAuthentication))
			return true
		}
	}
	return false
}

// tokExResolveActor handles the actor_token: the both-or-neither presence rule,
// the dedicated Native SSO device-secret delegated path, actor validation, the
// JTI-replay defense (with its own fail-open/fail-closed switch), and the RFC
// 8693 §4.1.1 act-chain prepend. Returns (done, delegated): done=true when a
// response is already written; delegated=true when the device-secret path fully
// handled the exchange and the caller must return without further work.
func tokExResolveActor(d TokenExchangeDeps, ctx core.HandlerContext, client *core.Client, req TokenExchangeRequest, st *tokExState) (done, delegated bool) {
	// RFC 8693 §2.1: actor_token and actor_token_type MUST both be present, or
	// both absent. Mismatch = invalid_request.
	if (req.ActorToken == "") != (req.ActorTokenType == "") {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return true, false
	}
	// OpenID Connect Native SSO 1.0 §3.2: a device_secret actor takes a
	// dedicated, self-contained path — the secret is not a JWT; it is validated
	// against the device-secret store + the id_token's ds_hash. Requires a wired
	// store (else the feature is off).
	if req.ActorToken != "" && req.ActorTokenType == core.TokenTypeDeviceSecret {
		if d.DeviceSecretStore() == nil {
			ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrDeviceSecretNotConfigured))
			return true, false
		}
		d.HandleDeviceSecretExchange(ctx, st.claims, req.SubjectToken, req.ActorToken, client, req)
		return false, true
	}
	if req.ActorToken == "" {
		return false, false
	}
	if req.ActorTokenType != core.TokenTypeAccessToken && req.ActorTokenType != core.TokenTypeJWT {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return true, false
	}
	actorClaims, done := tokExValidateActor(d, ctx, req, st)
	if done {
		return true, false
	}
	// RFC 8693 §4.1.1: when the subject_token already carries an `act` claim
	// (it was itself a delegated token), the new act prepends the current
	// actor and nests the previous chain beneath, preserving full provenance.
	// Guard: reject before prepending so the resulting chain stays within the
	// depth cap — unbounded nesting risks exponential cost on further hops.
	if actChainDepth(st.claims.Actor) >= MaxActChainDepth {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return true, false
	}
	st.actor = &core.ActorClaim{Subject: actorClaims.Subject, Actor: st.claims.Actor}
	return false, false
}

// tokExValidateActor validates the actor_token JWT and enforces the RFC 8693
// §4.4 `may_act` constraint from the subject_token. Returns the resolved actor
// claims and done=true (response already written) when any check fails.
func tokExValidateActor(d TokenExchangeDeps, ctx core.HandlerContext, req TokenExchangeRequest, st *tokExState) (actorClaims *core.TokenClaims, done bool) {
	actorClaims, _, aerr := d.ValidateAnyToken(ctx.Request().Context(), req.ActorToken)
	if aerr != nil || actorClaims == nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return nil, true
	}
	if tokExActorJTIReplay(d, ctx, actorClaims) {
		return nil, true
	}
	// RFC 8693 §4.4: only the actor named in may_act may impersonate the subject.
	// Oracle-safe: same error code as expired/unknown subject (no disclosure).
	if st.claims.MayAct != nil && st.claims.MayAct.Subject != actorClaims.Subject {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return nil, true
	}
	return actorClaims, false
}

// tokExActorJTIReplay applies the actor_token jti-replay defense. Returns true
// when it has written an invalid_grant response (confirmed reuse, or store error
// under the fail-closed switch). Empty jti / no store / store-error-fail-open
// all fall through.
func tokExActorJTIReplay(d TokenExchangeDeps, ctx core.HandlerContext, actorClaims *core.TokenClaims) bool {
	// Defense-in-depth: when a security.JTIReplayStore is wired AND the
	// actor_token carries a `jti`, refuse to honor the same delegation
	// assertion twice within its expiry window. Mirrors the same defense JAR
	// + DPoP + client_assertion already opt into; namespace prevents
	// collision with those jti spaces. Empty jti / no store / store error all
	// fall through (RFC 8693 doesn't mandate the check; collapse to
	// invalid_grant on confirmed reuse).
	if d.JTIReplayStore() == nil || actorClaims.JTI == "" {
		return false
	}
	// Remember the jti until the LATEST instant the actor_token would still be
	// accepted, not just its raw exp: token validation tolerates clock skew, so a
	// jti expiring exactly at exp leaves a skew-sized replay gap (same misalignment
	// class as the DPoP / CAEP jti windows). Add a generous safe margin so the
	// remembered span always covers the validator's acceptance span; a zero-exp
	// actor_token falls back to a window from now.
	expiry := actorClaims.ExpiresAt
	if expiry.IsZero() {
		expiry = time.Now()
	}
	expiry = expiry.Add(security.DefaultJTIReplayWindow)
	first, rerr := d.JTIReplayStore().MarkSeen(ctx.Request().Context(), "tokex-act:"+actorClaims.JTI, expiry)
	switch {
	case rerr != nil:
		// Store error — default fail-OPEN (continue). Fail-CLOSED (opt-in)
		// treats store-uncertainty AS a replay and rejects with the SAME
		// invalid_grant a detected replay returns (no oracle).
		if d.JTIReplayFailClosed() {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
			return true
		}
	case !first:
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return true
	}
	return false
}

// tokExResolveTargetsAndScopes merges resource+audience targets, validates them
// (invalid_target), narrows scope against the subject_token then the downstream
// client allowlist (invalid_scope), and resolves the issuer. Returns true when
// it has written a response and the caller must stop.
func tokExResolveTargetsAndScopes(d TokenExchangeDeps, ctx core.HandlerContext, client *core.Client, req TokenExchangeRequest, st *tokExState) bool {
	// Merge `resource` + `audience` into the new token's aud claim. Both forms
	// are accepted (RFC 8693 + RFC 8707 overlap on intent); deduplicated in-order
	// so the first occurrence wins for deterministic output.
	st.resources = oauth.MergeTargets(req.Resource, req.Audience)
	if !client.AreResourcesAllowed(st.resources) {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidTarget))
		return true
	}

	if tokExResolveScope(ctx, client, req, st) {
		return true
	}

	strategy, ti, err := d.IssuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrNoTokenStrategy))
		return true
	}
	st.strategy = strategy
	st.ti = ti
	return false
}

// tokExResolveScope narrows the exchanged scope to the subject and bounds it by
// the downstream client's allowlist. Returns true when it has written an error
// response (invalid_scope) and the caller must stop.
func tokExResolveScope(ctx core.HandlerContext, client *core.Client, req TokenExchangeRequest, st *tokExState) bool {
	// Scope narrowing per RFC 8693 §2.1: when `scope` is supplied it MUST be a
	// subset of the subject_token's scopes; expansion is forbidden. Empty scope =
	// keep the subject's scopes.
	scopes := st.claims.Scopes
	if req.Scope != "" {
		requested := strings.Split(req.Scope, " ")
		if !oauth.IsScopeSubset(requested, st.claims.Scopes) {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))
			return true
		}
		scopes = requested
	}
	// RFC 8693 §2.1: the exchanged token MUST NOT exceed the subject. When the
	// resolved scope is EMPTY (a scope-less subject — id_token, SPIFFE JWT-SVID,
	// or any access token with no scopes — and no narrowing `scope` param), the
	// result MUST be empty. It must NOT fall through to GrantedScopes' rule-4
	// "nothing requested -> default to the client's full AllowedScopes", which
	// would ESCALATE a scope-less subject to the downstream client's entire
	// entitlement (e.g. accounts:admin) bound to the subject's identity.
	if len(scopes) == 0 {
		st.scopes = nil
		return false
	}
	// Non-empty: bound the exchanged scope to the DOWNSTREAM client's
	// AllowedScopes (RFC 6749 §3.3) — subset of the subject_token scopes (above)
	// AND of the client's allowlist. Empty allowlist = unrestricted.
	boundScopes, exScopeErr := oauth.GrantedScopes(scopes, client)
	if exScopeErr != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))
		return true
	}
	st.scopes = boundScopes
	return false
}

// tokExResolveSubjectAndIssue runs the OIDC §8 pairwise resolution and issues
// the access token, recording the issuance + access. Returns true when it has
// written a response (pairwise/issuance failure) and the caller must stop.
func tokExResolveSubjectAndIssue(d TokenExchangeDeps, ctx core.HandlerContext, client *core.Client, st *tokExState) bool {
	// OIDC §8 pairwise: the inbound subject_token's `sub` may be pairwise (issued
	// for the originating client's sector); resolve to the local sub, then
	// re-apply pairwise for the new (downstream) client's sector. The exchange
	// does not change the principal but the wire sub differs whenever the
	// downstream client lives in a different sector. Non-pairwise deployments are
	// a no-op pair.
	localSub, perr := d.ResolveLocalSubject(ctx.Request().Context(), st.claims.Subject)
	if perr != nil {
		d.SrvLogger().Error("pairwise resolve failed at token-exchange", "error", perr, "subject", st.claims.Subject)
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return true
	}
	st.issuedSub = d.ApplyPairwiseSubject(ctx.Request().Context(), client, localSub)
	token, err := st.ti.Issue(ctx.Request().Context(), tokExSubject(client, st), st.scopes)
	if err != nil {
		d.SrvLogger().Error("token exchange issuance failed", "strategy", st.strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return true
	}
	st.token = token
	d.RecordTokenIssued(ctx, client.ID, st.strategy, st.claims.Subject)
	// Index by the LOCAL id, not the (possibly pairwise) inbound subject_token
	// sub. The subject_client_index is local-keyed at every other write site and
	// at every back-channel/front-channel logout read site, so recording a
	// pairwise-origin client under its foreign pseudonym here would silently omit
	// the exchanged RP from the logout fan-out (its session never torn down).
	d.RecordSubjectClientAccess(ctx.Request().Context(), localSub, client.ID)
	return false
}

// tokExSubject assembles the core.Subject for the exchanged access token from
// the resolved exchange state. Extracted from tokExResolveSubjectAndIssue to keep
// that stage within the function-length budget.
func tokExSubject(client *core.Client, st *tokExState) *core.Subject {
	return &core.Subject{
		ID:        st.issuedSub,
		Claims:    st.claims.Extra,
		Resources: st.resources,
		ClientID:  client.ID,
		// auth_time + amr propagate from the original subject_token — the
		// exchange doesn't represent a fresh end-user auth event; carrying the
		// originals lets downstream services see the actual factor strength.
		AuthTime: st.claims.AuthTime,
		ACR:      st.claims.ACR,
		AMR:      append([]string(nil), st.claims.AMR...),
		// RFC 8693 §4.1 — when an actor_token is presented, the new token carries
		// `act: {sub: <actor.sub>}`. Nil when no actor_token was supplied.
		Actor: st.actor,
		TTL:   client.AccessTokenTTL,
		// RFC 9396: preserve the subject_token's authorization_details across the
		// exchange so the resulting token carries the same fine-grained
		// authorization the user originally consented to.
		AuthorizationDetails: oauth.CloneRawJSON(st.claims.AuthorizationDetails),
		// RFC 9449 / RFC 8705 sender constraint: bind the exchanged token to the
		// presented DPoP key / mTLS cert thumbprint when one was supplied, matching
		// every other issuance grant. Empty leaves the token unbound (as before).
		ConfirmationJKT:     st.confJKT,
		ConfirmationX5TS256: st.confX5T,
	}
}

// tokExAuditSPIFFE records the internal audit trail for an accepted SPIFFE
// JWT-SVID. SVID rejections are deliberately NOT audited (they already collapsed
// to invalid_grant; per-cause events would re-open the hardened oracle).
func tokExAuditSPIFFE(d TokenExchangeDeps, ctx core.HandlerContext, client *core.Client, st *tokExState) {
	if st.spiffeID == nil || d.Auditor() == nil {
		return
	}
	spiffeID := st.spiffeID
	evt := &audit.Event{
		Type:     audit.EventSPIFFEJWTSVIDAccepted,
		Outcome:  audit.OutcomeSuccess,
		ActorID:  spiffeID.URI,
		ClientID: client.ID,
		Provider: core.AMRSpiffe,
		ActorIP:  audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, core.KeySPIFFETrustDomain, spiffeID.TrustDomain)
	if spiffeID.Namespace != "" {
		audit.SetMeta(evt, core.KeySPIFFENamespace, spiffeID.Namespace)
	}
	if spiffeID.ServiceAccount != "" {
		audit.SetMeta(evt, core.KeySPIFFEServiceAccount, spiffeID.ServiceAccount)
	}
	d.Auditor().Record(ctx.Request().Context(), evt)
}

// tokExIssueRefresh mints a refresh token alongside the access token when
// requested_token_type is refresh_token. This path is FAIL-OPEN: an issuance
// error leaves the caller with the already-minted access token.
func tokExIssueRefresh(d TokenExchangeDeps, ctx core.HandlerContext, client *core.Client, req TokenExchangeRequest, st *tokExState) {
	// RFC 8693 §2.1: when requested_token_type is refresh_token, mint a refresh
	// token alongside (the access token is always returned — requested_token_type
	// names what `issued_token_type` reports back, not what's emitted
	// exclusively). Provider/AMR/Resources/AuthDetails/SID propagate from the
	// subject_token's claims so a rotated chain inherits the same context.
	if req.RequestedTokenType != core.TokenTypeRefreshToken || d.RefreshTokenStore() == nil {
		return
	}
	provider := ""
	if len(st.claims.AMR) > 0 {
		provider = st.claims.AMR[0]
	}
	rt, rerr := d.IssueRefreshToken(
		ctx.Request().Context(),
		st.claims.Subject, client.ID, provider,
		st.scopes, st.claims.Extra, "", st.resources,
		oauth.CloneRawJSON(st.claims.AuthorizationDetails), // RFC 9396 — propagate the inbound binding
		st.claims.SID,
		// RFC 9068 §2.2 + AGENTS.md §3: propagate the inbound subject_token's
		// amr/acr/auth_time so a rotated chain keeps the original auth context
		// (mirrors the exchanged access token's Subject).
		oauth.RefreshAuthContext{AMR: st.claims.AMR, ACR: st.claims.ACR, AuthTime: st.claims.AuthTime},
		client.RefreshTokenTTL, req.DPoPJKT,
	)
	if rerr != nil {
		d.SrvLogger().Error("token exchange refresh issue failed", "strategy", st.strategy, "error", rerr)
		// Fail-open: caller still gets the access token. Spec allows this
		// since the access token alone is a complete response.
		return
	}
	st.resp[core.KeyRefreshToken] = rt
	st.resp[core.KeyIssuedTokenType] = core.TokenTypeRefreshToken
	d.RecordRefreshTokenIssued(ctx, client.ID, st.claims.Subject, false)
}

// The id_token output path (tokExIssueIDToken / tokExMintIDToken) lives in
// token_exchange_idtoken.go to keep this file within the size budget.
