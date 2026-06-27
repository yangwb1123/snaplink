package tokengrant

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
)

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
	actorClaims, _, aerr := d.ValidateAnyToken(ctx.Request().Context(), req.ActorToken)
	if aerr != nil || actorClaims == nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return true, false
	}
	if tokExActorJTIReplay(d, ctx, actorClaims) {
		return true, false
	}
	// RFC 8693 §4.1.1: when the subject_token already carries an `act` claim
	// (it was itself a delegated token), the new act prepends the current
	// actor and nests the previous chain beneath, preserving full provenance.
	st.actor = &core.ActorClaim{Subject: actorClaims.Subject, Actor: st.claims.Actor}
	return false, false
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
	expiry := actorClaims.ExpiresAt
	if expiry.IsZero() {
		expiry = time.Now().Add(security.DefaultJTIReplayWindow)
	}
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
	// Additionally bound the exchanged scope to the DOWNSTREAM client's
	// AllowedScopes (RFC 6749 §3.3) — intersection semantics: the result must be
	// subset of subject_token scopes (above) AND subset of the requesting
	// client's allowlist. Empty allowlist = unrestricted (byte-identical to
	// before).
	boundScopes, exScopeErr := oauth.GrantedScopes(scopes, client)
	if exScopeErr != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))
		return true
	}
	st.scopes = boundScopes

	strategy, ti, err := d.IssuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrNoTokenStrategy))
		return true
	}
	st.strategy = strategy
	st.ti = ti
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
	token, err := st.ti.Issue(ctx.Request().Context(), &core.Subject{
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
	}, st.scopes)
	if err != nil {
		d.SrvLogger().Error("token exchange issuance failed", "strategy", st.strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return true
	}
	st.token = token
	d.RecordTokenIssued(ctx, client.ID, st.strategy, st.claims.Subject)
	d.RecordSubjectClientAccess(ctx.Request().Context(), st.claims.Subject, client.ID)
	return false
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
		client.RefreshTokenTTL,
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
		Subject:     st.issuedSub,
		Audience:    client.ID,
		AuthTime:    st.claims.AuthTime,
		ACR:         st.claims.ACR,
		AMR:         append([]string(nil), st.claims.AMR...),
		Claims:      st.claims.Extra,
		SID:         st.claims.SID,
		AccessToken: st.token.AccessToken,
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
