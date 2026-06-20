package handler

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
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
	IssueRefreshToken(ctx context.Context, userID, clientID, provider string, scopes []string, attributes map[string]string, familyID string, resources []string, authDetails []byte, sid string, clientTTLOverride time.Duration) (string, error)
	MaybeEncryptIDToken(ctx context.Context, client *core.Client, signed string) (string, bool)
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
	if req.SubjectToken == "" || req.SubjectTokenType == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if req.SubjectTokenType != core.TokenTypeAccessToken &&
		req.SubjectTokenType != core.TokenTypeJWT &&
		req.SubjectTokenType != core.TokenTypeIDToken {
		// RFC 8693 §2.1 lists more token types; this server handles signed
		// access tokens + JWTs, plus id_token for the Native SSO 1.0 device-
		// secret exchange (handled in the actor branch below).
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if req.RequestedTokenType != "" &&
		req.RequestedTokenType != core.TokenTypeAccessToken &&
		req.RequestedTokenType != core.TokenTypeRefreshToken &&
		req.RequestedTokenType != core.TokenTypeIDToken {
		// Access + Refresh + ID token supported; SAML1/2 are future work.
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	// Refresh-token output requires a wired refresh store — without it there's no
	// way to honor the resulting rotation grant. Fail fast rather than silently
	// downgrade to access-only.
	if req.RequestedTokenType == core.TokenTypeRefreshToken && d.RefreshTokenStore() == nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrRefreshTokenNotConfigured))
		return
	}
	// RFC 8693 §2.2.1 id_token output requires a wired IDTokenIssuer. Without one
	// this AS instance cannot produce the requested representation — collapse to
	// invalid_request so no oracle reveals whether OIDC is configured. Resolved
	// against the per-client (tenant-aware) issuer so a tenant whose strategy is
	// non-OIDC also fails closed here rather than at issuance time.
	if req.RequestedTokenType == core.TokenTypeIDToken {
		if _, emit, idErr := d.IDTokenIssuerForClient(client); idErr != nil || !emit {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
			return
		}
	}

	claims, _, err := d.ValidateAnyToken(ctx.Request().Context(), req.SubjectToken)
	// SPIFFE JWT-SVID fallback (cluster C1). Tried ONLY when the local-issuer path
	// FAILED, the validator is wired, and the inbound type is the standard `jwt`
	// type SVIDs use. The validator requires the `sub` to be a spiffe:// URI in
	// the configured trust domain, so a foreign non-SVID JWT still fails and
	// collapses to the SAME invalid_grant below. On success the SVID is mapped
	// onto a synthetic claims set the existing issuance path reuses.
	var spiffeID *security.SPIFFEID
	if (err != nil || claims == nil) && d.SPIFFEValidator() != nil && req.SubjectTokenType == core.TokenTypeJWT {
		if id, verr := d.SPIFFEValidator().Validate(ctx.Request().Context(), req.SubjectToken, d.SPIFFEAudience()); verr == nil {
			spiffeID = id
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
		return
	}

	// RFC 9470 step-up: when the caller demands a minimum ACR via `acr_values`,
	// the inbound subject_token's ACR claim MUST match at least one value in the
	// demand set. Otherwise the AS would have to re-authenticate the user, which
	// token-exchange (server-to-server) can't do. Same wire shape as the
	// resource-server challenge so SPAs branch on it uniformly across grants.
	if req.ACRValues != "" {
		demanded := strings.Fields(req.ACRValues)
		if !oauth.ACRMatchesAny(claims.ACR, demanded) {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(security.ErrInsufficientUserAuthentication))
			return
		}
	}

	// RFC 8693 §2.1: actor_token and actor_token_type MUST both be present, or
	// both absent. Mismatch = invalid_request.
	if (req.ActorToken == "") != (req.ActorTokenType == "") {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	// OpenID Connect Native SSO 1.0 §3.2: a device_secret actor takes a
	// dedicated, self-contained path — the secret is not a JWT; it is validated
	// against the device-secret store + the id_token's ds_hash. Requires a wired
	// store (else the feature is off).
	if req.ActorToken != "" && req.ActorTokenType == core.TokenTypeDeviceSecret {
		if d.DeviceSecretStore() == nil {
			ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrDeviceSecretNotConfigured))
			return
		}
		d.HandleDeviceSecretExchange(ctx, claims, req.SubjectToken, req.ActorToken, client, req)
		return
	}
	var actor *core.ActorClaim
	if req.ActorToken != "" {
		if req.ActorTokenType != core.TokenTypeAccessToken && req.ActorTokenType != core.TokenTypeJWT {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
			return
		}
		actorClaims, _, aerr := d.ValidateAnyToken(ctx.Request().Context(), req.ActorToken)
		if aerr != nil || actorClaims == nil {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
			return
		}
		// Defense-in-depth: when a security.JTIReplayStore is wired AND the
		// actor_token carries a `jti`, refuse to honor the same delegation
		// assertion twice within its expiry window. Mirrors the same defense JAR
		// + DPoP + client_assertion already opt into; namespace prevents
		// collision with those jti spaces. Empty jti / no store / store error all
		// fall through (RFC 8693 doesn't mandate the check; collapse to
		// invalid_grant on confirmed reuse).
		if d.JTIReplayStore() != nil && actorClaims.JTI != "" {
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
					return
				}
			case !first:
				ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
				return
			}
		}
		// RFC 8693 §4.1.1: when the subject_token already carries an `act` claim
		// (it was itself a delegated token), the new act prepends the current
		// actor and nests the previous chain beneath, preserving full provenance.
		actor = &core.ActorClaim{Subject: actorClaims.Subject, Actor: claims.Actor}
	}

	// Merge `resource` + `audience` into the new token's aud claim. Both forms
	// are accepted (RFC 8693 + RFC 8707 overlap on intent); deduplicated in-order
	// so the first occurrence wins for deterministic output.
	resources := oauth.MergeTargets(req.Resource, req.Audience)
	if !client.AreResourcesAllowed(resources) {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidTarget))
		return
	}

	// Scope narrowing per RFC 8693 §2.1: when `scope` is supplied it MUST be a
	// subset of the subject_token's scopes; expansion is forbidden. Empty scope =
	// keep the subject's scopes.
	scopes := claims.Scopes
	if req.Scope != "" {
		requested := strings.Split(req.Scope, " ")
		if !oauth.IsScopeSubset(requested, claims.Scopes) {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))
			return
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
		return
	}
	scopes = boundScopes

	strategy, ti, err := d.IssuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrNoTokenStrategy))
		return
	}

	// OIDC §8 pairwise: the inbound subject_token's `sub` may be pairwise (issued
	// for the originating client's sector); resolve to the local sub, then
	// re-apply pairwise for the new (downstream) client's sector. The exchange
	// does not change the principal but the wire sub differs whenever the
	// downstream client lives in a different sector. Non-pairwise deployments are
	// a no-op pair.
	localSub, perr := d.ResolveLocalSubject(ctx.Request().Context(), claims.Subject)
	if perr != nil {
		d.SrvLogger().Error("pairwise resolve failed at token-exchange", "error", perr, "subject", claims.Subject)
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return
	}
	issuedSub := d.ApplyPairwiseSubject(ctx.Request().Context(), client, localSub)
	token, err := ti.Issue(ctx.Request().Context(), &core.Subject{
		ID:        issuedSub,
		Claims:    claims.Extra,
		Resources: resources,
		ClientID:  client.ID,
		// auth_time + amr propagate from the original subject_token — the
		// exchange doesn't represent a fresh end-user auth event; carrying the
		// originals lets downstream services see the actual factor strength.
		AuthTime: claims.AuthTime,
		ACR:      claims.ACR,
		AMR:      append([]string(nil), claims.AMR...),
		// RFC 8693 §4.1 — when an actor_token is presented, the new token carries
		// `act: {sub: <actor.sub>}`. Nil when no actor_token was supplied.
		Actor: actor,
		TTL:   client.AccessTokenTTL,
		// RFC 9396: preserve the subject_token's authorization_details across the
		// exchange so the resulting token carries the same fine-grained
		// authorization the user originally consented to.
		AuthorizationDetails: oauth.CloneRawJSON(claims.AuthorizationDetails),
	}, scopes)
	if err != nil {
		d.SrvLogger().Error("token exchange issuance failed", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	d.RecordTokenIssued(ctx, client.ID, strategy, claims.Subject)
	d.RecordSubjectClientAccess(ctx.Request().Context(), claims.Subject, client.ID)

	// Internal audit trail for an accepted SPIFFE JWT-SVID (the security-sensitive
	// inbound-external-identity path). Records WHICH mesh workload was admitted
	// and by which client. SVID REJECTIONS are deliberately NOT audited here —
	// they already collapsed to invalid_grant, and per-cause reject events would
	// re-open the oracle the wire is hardened against (§2).
	if spiffeID != nil && d.Auditor() != nil {
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

	resp := map[string]any{
		core.KeyAccessToken:     token.AccessToken,
		core.KeyIssuedTokenType: core.TokenTypeAccessToken,
		core.KeyTokenType:       token.TokenType,
		core.KeyExpiresIn:       token.ExpiresIn,
		core.KeyScope:           token.Scope,
		core.KeyTokenStrategy:   strategy,
	}
	// RFC 8693 §2.1: when requested_token_type is refresh_token, mint a refresh
	// token alongside (the access token is always returned — requested_token_type
	// names what `issued_token_type` reports back, not what's emitted
	// exclusively). Provider/AMR/Resources/AuthDetails/SID propagate from the
	// subject_token's claims so a rotated chain inherits the same context.
	if req.RequestedTokenType == core.TokenTypeRefreshToken && d.RefreshTokenStore() != nil {
		provider := ""
		if len(claims.AMR) > 0 {
			provider = claims.AMR[0]
		}
		rt, rerr := d.IssueRefreshToken(
			ctx.Request().Context(),
			claims.Subject, client.ID, provider,
			scopes, claims.Extra, "", resources,
			oauth.CloneRawJSON(claims.AuthorizationDetails), // RFC 9396 — propagate the inbound binding
			claims.SID,
			client.RefreshTokenTTL,
		)
		if rerr != nil {
			d.SrvLogger().Error("token exchange refresh issue failed", "strategy", strategy, "error", rerr)
			// Fail-open: caller still gets the access token. Spec allows this
			// since the access token alone is a complete response.
		} else {
			resp[core.KeyRefreshToken] = rt
			resp[core.KeyIssuedTokenType] = core.TokenTypeRefreshToken
			d.RecordRefreshTokenIssued(ctx, client.ID, claims.Subject, false)
		}
	}

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
	if req.RequestedTokenType == core.TokenTypeIDToken {
		if !slices.Contains(scopes, core.ScopeOpenID) {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
			return
		}
		idIssuer, _, idErr := d.IDTokenIssuerForClient(client)
		if idErr != nil || idIssuer == nil {
			d.SrvLogger().Error("token exchange id_token issuer resolution failed", "client", client.ID, "error", idErr)
			ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
			return
		}
		// auth_time / acr / amr / sid propagate from the inbound subject_token
		// exactly as the access token above. AccessToken is the one just minted
		// so the issuer stamps OIDC Core §3.1.3.6 at_hash. No nonce: there is no
		// authorization request in a token-exchange.
		idToken, iErr := idIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
			Subject:     issuedSub,
			Audience:    client.ID,
			AuthTime:    claims.AuthTime,
			ACR:         claims.ACR,
			AMR:         append([]string(nil), claims.AMR...),
			Claims:      claims.Extra,
			SID:         claims.SID,
			AccessToken: token.AccessToken,
		})
		if iErr != nil {
			d.SrvLogger().Error("token exchange id_token issue failed", "client", client.ID, "error", iErr)
			ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
			return
		}
		// Per-client id_token JWE (OIDC §10.2) when configured — a no-op
		// pass-through when the client has no encrypted-response metadata.
		enc, ok := d.MaybeEncryptIDToken(ctx.Request().Context(), client, idToken)
		if !ok {
			// Encryption requested but no encrypter wired — omitting a requested
			// id_token silently would be a confusing partial success, so collapse
			// to the internal error.
			ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
			return
		}
		resp[core.KeyIDToken] = enc
		resp[core.KeyIssuedTokenType] = core.TokenTypeIDToken
		d.RecordIDTokenIssued(ctx, client.ID, claims.Subject)
	}

	ctx.JSON(http.StatusOK, resp)
}
