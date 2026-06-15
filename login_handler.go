package sso

import (
	"net/http"
	"time"
	"slices"
	"strings"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/fapi"
	"github.com/snaplink/sso/geo"
	"github.com/snaplink/sso/oidc"
	"github.com/snaplink/sso/security"
	"github.com/snaplink/sso/spi"
	"github.com/snaplink/sso/oauth"
)
func (s *Server) handleLogin(ctx HandlerContext) {
	// Stamp the request start time onto the context for the
	// sso_login_duration_seconds histogram observation in
	// recordLoginSuccess / recordLoginFailure. The Login-specific
	// histogram is separate from sso_http_request_duration_seconds
	// because it carries the provider label — operators graphing
	// "is the OIDC federation upstream slow" need per-provider
	// slicing the bounded HTTP histogram doesn't provide.
	ctx.Set(ctxKeyLoginStart, time.Now())
	// RFC 6749 §5.1: token responses MUST stamp Cache-Control:
	// no-store + Pragma: no-cache. /auth/login bodies carry
	// access_token + refresh_token (and PKCE-flow code values
	// that an intermediary cache must not retain).
	tokenNoStoreHeaders(ctx)
	var req loginRequest
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, ErrInvalidRequest, err.Error()))
		return
	}

	// RFC 9126 §4: when request_uri is present, fetch the pushed
	// authorization parameters and merge them into the in-flight
	// request. The PAR record holds the AUTHORIZATION-SHAPED params
	// (response_type, redirect_uri, scope, etc.) — credentials still
	// arrive on this request, so PAR can't be used to bypass user
	// authentication. The merge gives PAR fields priority over
	// caller-supplied so a tampered redirect parameter can't override
	// what the client previously committed to.

	if s.resolveLoginRequest(ctx, &req) {
		return
	}

	// OIDC Core §3.1.2.1 prompt parameter — parse early so the
	// silent-renewal branch can override the providers-list probe
	// and the credential-validation pipeline alike. prompt=none
	// stays in the iframe contract (no UI, no credentials): the
	// only valid response is either a renewed token (if a session
	// is live) or login_required (§3.1.2.6).
	prompts := oidc.ParsePromptValues(req.Prompt)
	if oidc.PromptHasNone(prompts) {
		// Silent renewal needs the client resolved to verify
		// id_token_hint binding. Mirror the validation guards the
		// post-probe path runs so a misconfigured caller still
		// gets a coherent error.
		if req.ClientID == "" {
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMissingClientID))
			return
		}
		if s.clientStore == nil {
			ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrClientStoreNotConfigured))
			return
		}
		c, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, s.authzErrorBody(ctx, ErrInvalidClient))
			return
		}
		if !c.Active {
			ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrInactiveClient))
			return
		}
		if !clientTenantOK(ctx, c) {
			ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrTenantMismatch))
			return
		}
		// Data-residency write-gate BEFORE the silent-renewal mint. prompt=none
		// mints a fresh access (and id) token in handleSilentRenewal and returns
		// — without this gate it executes ABOVE the credential-path gate below,
		// so a foreign-region prompt=none request would bypass the primary write
		// control. The mint happens from THIS request's serving region, so the
		// gate reads the live region here (isWrite=true). Provider is attributed
		// "silent_renewal" to match the success audit RecordLoginSuccess emits.
		if s.residencyGateLogin(ctx, c.ID, "silent_renewal", c.TenantID) {
			return
		}
		// Scope authorization for the prompt=none silent-renewal mint —
		// the same RFC 6749 §3.3 gate as the interactive finishLogin path,
		// applied here because silent renewal mints a fresh access (and
		// id) token from THIS request's `scope` param without funneling
		// through finishLogin. Empty allowlist = unrestricted (unchanged).
		srGranted, srScopeErr := oauth.GrantedScopes(req.Scope, c)
		if srScopeErr != nil {
			s.recordLoginFailure(ctx, req.ClientID, "silent_renewal", ErrInvalidScope)
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidScope))
			return
		}
		req.Scope = srGranted
		if s.handleSilentRenewal(ctx, prompts, oidc.SilentRenewalRequest{
			ClientID:             req.ClientID,
			Scope:                req.Scope,
			State:                req.State,
			Nonce:                req.Nonce,
			Resource:             req.Resource,
			AuthorizationDetails: req.AuthorizationDetails,
			IDTokenHint:          req.IDTokenHint,
			MaxAge:               req.MaxAge,
		}, c) {
			return
		}
	}

	if req.Provider == "" {
		// Home-realm discovery (B2B, opt-in): if the login hint's email domain
		// maps to an enterprise connection, tell the client to authenticate via
		// that org's upstream IdP instead of offering the generic provider list.
		// No store / no hint / no match falls through to the normal list, so a
		// build without WithConnectionStore is byte-identical.
		if conn, ok := s.resolveHomeRealm(ctx, req.LoginHint); ok {
			ctx.JSON(http.StatusOK, map[string]any{
				keyHRConnectionRequired: true,
				keyHRConnectionID:       conn.ID,
				keyHRType:               string(conn.Type),
				keyHRTenantID:           conn.TenantID,
				keyHRDisplayName:        conn.DisplayName,
				KeyIss:                  s.resolveIssuer(ctx),
			})
			return
		}
		ctx.JSON(http.StatusOK, map[string]any{
			KeyProviders: s.providersForClient(ctx, req.ClientID),
			KeyIss:       s.resolveIssuer(ctx),
		})
		return
	}

	if req.ClientID == "" {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMissingClientID))
		return
	}
	if s.clientStore == nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrClientStoreNotConfigured))
		return
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidClient)
		ctx.JSON(http.StatusUnauthorized, s.authzErrorBody(ctx, ErrInvalidClient))
		return
	}
	if !client.Active {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInactiveClient)
		ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrInactiveClient))
		return
	}
	if !clientTenantOK(ctx, client) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrTenantMismatch)
		ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrTenantMismatch))
		return
	}
	// Data-residency gate — a SECOND tenant-binding gate after tenant_mismatch,
	// not a replacement. The credential path mints tokens downstream in
	// finishLogin, so it is dominated here by the shared residency write-gate:
	// when the region middleware stashed a serving region AND
	// WithTenantResidencyCheck is wired, a login whose serving region violates
	// the tenant's ResidencyPolicy is rejected before any credential work. The
	// SAME gate dominates the prompt=none silent-renewal branch above and the
	// /auth/mfa second leg (see residencyGateLogin / handleMFAComplete) so every
	// interactive-login mint path enforces residency identically. No resolver /
	// no check wired → the gate never fires → byte-identical to a pre-residency
	// build.
	if s.residencyGateLogin(ctx, req.ClientID, req.Provider, client.TenantID) {
		return
	}
	// RFC 9126 §2.1 — clients with RequirePAR=true MUST push their
	// authorization request via /par first. We check AFTER the PAR
	// merge above so a legitimate caller using request_uri still
	// works (the merge consumed the URI; req.RequestURI is the
	// pre-merge value). The merge succeeded ⇒ request_uri was
	// present ⇒ this client satisfies the PAR-only contract.
	// Empty req.RequestURI when RequirePAR=true ⇒ reject.
	if client.RequirePAR && req.RequestURI == "" {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRequest)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, ErrInvalidRequest, "client requires pushed authorization request"))
		return
	}
	// RFC 9101 §10.8 — high-security clients require a signed JAR
	// request object (inline `request` or fetched `request_uri`).
	// Direct /auth/login without either fails fast. PAR's pushed
	// JWT doesn't satisfy this gate by itself — PAR is about
	// transport, not about signing the request — but a JAR fetched
	// via request_uri does (the merge already populated req.Request
	// in that branch).
	if client.RequireSignedRequestObject && req.Request == "" {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRequest)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, ErrInvalidRequest, "client requires signed request object"))
		return
	}
	if !client.IsAuthenticatorAllowed(req.Provider) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrAuthenticatorNotAllowed)
		ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrAuthenticatorNotAllowed))
		return
	}

	// RFC 9101 JAR: when the `request` parameter is present, the
	// authorization request parameters live inside a signed JWT.
	// Verify it against the client's registered JWKS, then merge
	// JWT claims into req with JWT taking precedence on conflict
	// (matches PAR's merge semantics; FAPI 2.0's "ignore all
	// outside" mode is reserved for a future strict flag).
	//
	// RFC 9101 §6.4 encrypted variant: when the payload is JWE-shaped
	// (5 compact segments) and WithJARDecrypter is wired, decrypt
	// first; the plaintext is the same signed JAR JWT verifyJAR
	// validates below. Without a decrypter wired, JWE-shaped payloads
	// fail invalid_request_object (fail-closed; can't validate what
	// we can't decrypt).
	if req.Request != "" {
		jarRaw, unwrapErr := security.JWEUnwrap(ctx.Request().Context(), req.Request, s.jarDecrypter)
		if unwrapErr != nil {
			s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRequestObject)
			ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, ErrInvalidRequestObject, unwrapErr.Error()))
			return
		}
		jar, jarErr := verifyJAR(ctx.Request().Context(), jarRaw, client, s.resolveIssuer(ctx), s.jtiReplayStore, s.jtiReplayFailClosed)
		if jarErr != nil {
			s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRequestObject)
			ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, ErrInvalidRequestObject, jarErr.Error()))
			return
		}
		if jar.ResponseType != "" {
			req.ResponseType = jar.ResponseType
		}
		if jar.RedirectURI != "" {
			req.RedirectURI = jar.RedirectURI
		}
		if jar.Scope != "" {
			req.Scope = strings.Split(jar.Scope, " ")
		}
		if jar.State != "" {
			req.State = jar.State
		}
		if jar.Nonce != "" {
			req.Nonce = jar.Nonce
		}
		if jar.CodeChallenge != "" {
			req.CodeChallenge = jar.CodeChallenge
			req.CodeChallengeMethod = jar.CodeChallengeMethod
		}
		if len(jar.Resource) > 0 {
			req.Resource = jar.Resource
		}
		if len(jar.AuthorizationDetails) > 0 {
			req.AuthorizationDetails = oauth.CloneRawJSON(jar.AuthorizationDetails)
		}
		if jar.LoginHint != "" {
			req.LoginHint = jar.LoginHint
		}
		if jar.ResponseMode != "" {
			req.ResponseMode = jar.ResponseMode
		}
		if jar.ACRValues != "" {
			req.ACRValues = jar.ACRValues
		}
		if jar.UILocales != "" {
			req.UILocales = jar.UILocales
		}
		if len(jar.Claims) > 0 {
			req.Claims = oauth.CloneRawJSON(jar.Claims)
		}
	}

	// FAPI 2.0 Security Profile (§5.3.1) authorization-request baseline.
	// Signals are read AFTER the PAR + JAR merge so the rules see the
	// effective request. Inspection mode audits each violation and lets
	// the request proceed (the operator's per-RP compliance-gap signal);
	// enforce mode rejects on the first violation. This layer only
	// checks — each rule's capability (PAR / JAR / S256 PKCE) must be
	// independently wired and sent for a client to pass.
	if s.fapiValidator.Active() {
		if vs := s.fapiValidator.CheckAuthorization(fapi.AuthorizationContext{
			ClientID:            req.ClientID,
			ResponseType:        req.ResponseType,
			UsedPAR:             req.RequestURI != "",
			SignedRequest:       req.Request != "",
			CodeChallenge:       req.CodeChallenge,
			CodeChallengeMethod: req.CodeChallengeMethod,
		}); len(vs) > 0 {
			mode := s.fapiValidator.Mode().String()
			for _, v := range vs {
				audit.RecordFAPIViolation(s.auditor, ctx, v.ClientID, v.RuleID, v.Detail, mode)
				if s.metrics != nil {
					s.metrics.FAPIViolationsTotal.WithLabelValues(v.RuleID, mode).Inc()
				}
			}
			if s.fapiValidator.Enforcing() {
				s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRequest)
				ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, ErrInvalidRequest, "fapi: "+vs[0].RuleID+": "+vs[0].Detail))
				return
			}
		}
	}

	// RFC 8707 §2: each requested `resource` MUST be allowlisted on
	// the client. Empty allowlist disables enforcement (legacy compat).
	if !client.AreResourcesAllowed(req.Resource) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidTarget)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidTarget))
		return
	}
	// RFC 9396 §6: authorization_details, when present, MUST be a
	// JSON array of {type, ...} objects, and (if the client
	// declared an allowlist) every element's type MUST match.
	// Empty allowlist = parameter accepted but unconstrained
	// (legacy compat).
	// OIDC Core §5.5: when supplied, the `claims` parameter MUST be
	// a JSON object. We don't require any specific top-level keys
	// (the spec allows extension members); just enforce shape so a
	// caller passing an array / string / number fails fast.
	if len(req.Claims) > 0 {
		if err := oauth.ValidateClaimsParameter(req.Claims); err != nil {
			s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRequest)
			ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, ErrInvalidRequest, err.Error()))
			return
		}
	}
	if _, err := oauth.ValidateAuthorizationDetails(req.AuthorizationDetails, client.AllowedAuthorizationDetailsTypes); err != nil {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, oauth.ErrInvalidAuthorizationDetails)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, oauth.ErrInvalidAuthorizationDetails, err.Error()))
		return
	}

	auth, err := s.getAuthenticator(req.Provider)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrUnsupportedProvider))
		return
	}

	loginURL := auth.LoginURL(req.State)
	if loginURL != "" {
		ctx.Redirect(http.StatusFound, loginURL)
		return
	}

	// Per-account lockout gate: BEFORE invoking the credential
	// verifier, check whether the (client, identifier) pair is
	// currently locked. Skips the verifier entirely on a locked
	// account so a botnet can't drain the verifier's
	// constant-time hash budget while the lock is active.
	lockKey := security.LockoutKey(req.ClientID, req.Credential)
	if s.accountLockout != nil && lockKey != "" {
		if locked, until, _ := s.accountLockout.IsLocked(ctx.Request().Context(), lockKey); locked {
			s.recordAccountLocked(ctx, req.ClientID, req.Provider, lockKey, until)
			ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrAccountLocked))
			return
		}
	}

	result, err := auth.Authenticate(ctx.Request().Context(), &AuthRequest{
		Provider:        req.Provider,
		Credential:      req.Credential,
		ClientID:        req.ClientID,
		Scope:           req.Scope,
		State:           req.State,
		LoginHint:       req.LoginHint,
		ACRValues:       splitScope(req.ACRValues),
		UILocales:       splitScope(req.UILocales),
		RequestedClaims: oauth.CloneRawJSON(req.Claims),
	})
	if err != nil {
		s.logErrorCtx(ctx, "authentication failed", "provider", req.Provider, "error", err)
		// Failure attribution to per-account lockout BEFORE the
		// generic login_failure audit so the auditor records the
		// lockout state alongside the failure.
		if s.accountLockout != nil && lockKey != "" {
			if locked, until, _ := s.accountLockout.RegisterFailure(ctx.Request().Context(), lockKey); locked {
				s.recordAccountLocked(ctx, req.ClientID, req.Provider, lockKey, until)
				ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrAccountLocked))
				return
			}
		}
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidCredentials)
		ctx.JSON(http.StatusUnauthorized, s.authzErrorBody(ctx, ErrInvalidCredentials))
		return
	}

	// Successful credential validation clears any pending failure
	// counter for this (client, identifier) — a single legit
	// login resets the brute-force budget. Done BEFORE risk
	// evaluation so a risk-denied login doesn't unlock the
	// account (risk decisions might want the lock to stay
	// engaged for repeat-offender patterns).
	if s.accountLockout != nil && lockKey != "" {
		_ = s.accountLockout.RegisterSuccess(ctx.Request().Context(), lockKey)
	}

	// OIDC Core §3.1.2.6 / §5.5.1.1 ACR enforcement.
	// The RP can request specific ACR values through EITHER the acr_values
	// request parameter OR the claims parameter's id_token.acr entry; both
	// are honored with identical strictness, so a conformance suite that
	// uses the claims-parameter channel does not see its request silently
	// ignored. Checked immediately after credential validation so the gate
	// applies regardless of whether MFA or a risk decision follows. Empty
	// union = no constraint; a present list with no matching AchievedACR =
	// fail.
	acrList := splitScope(req.ACRValues)
	if len(req.Claims) > 0 {
		acrList = append(acrList, oauth.RequestedACRFromClaims(req.Claims)...)
	}
	if len(acrList) > 0 && !slices.Contains(acrList, result.AchievedACR) {
		// AchievedACR is empty or not in the requested set. Return the
		// spec-mandated error; do NOT reveal which ACR was achieved
		// (oracle-safe).
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrUnmetAuthReqs)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrUnmetAuthReqs))
		return
	}

	// Risk evaluation. Skipped entirely (zero overhead) when no scorer
	// configured. Scorer errors fail OPEN by contract — failing closed
	// on a misbehaving scorer locks every user out. Operators worried
	// about silent bypass should alert on "risk scorer failed".
	if s.riskScorer != nil {
		var geoInfo *geo.GeoInfo
		if g, ok := GeoFromHandlerContext(ctx); ok {
			geoInfo = g
		}
		assessment, riskErr := s.riskScorer.Score(ctx.Request().Context(), &spi.RiskRequest{
			SubjectID: result.UserID,
			ClientID:  req.ClientID,
			Provider:  req.Provider,
			RemoteIP:  audit.ClientIP(ctx.Request()),
			UserAgent: ctx.Request().UserAgent(),
			Geo:       geoInfo,
			Timestamp: time.Now(),
		})
		switch {
		case riskErr != nil:
			s.logErrorCtx(ctx, "risk scorer failed", "error", riskErr, "user", result.UserID, "client", req.ClientID)
		case assessment == nil:
			// Defensive: a scorer that returns (nil, nil) is misbehaving.
			s.logger.Error("risk scorer returned nil assessment", "user", result.UserID, "client", req.ClientID)
		default:
			if s.metrics != nil {
				s.metrics.RiskDecisionsTotal.WithLabelValues(string(assessment.Decision)).Inc()
			}
			if assessment.Decision == spi.DecisionDeny {
				s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrRiskDenied)
				ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrRiskDenied))
				return
			}
			if assessment.Decision == spi.DecisionRequireMFA && s.mfaProvider != nil && s.mfaChallengeStore != nil {
				// Step-up gate engaged: persist the in-flight state and
				// return mfa_required so the client follows up at
				// /auth/mfa. issueMFAChallenge writes the response;
				// resume happens in handleMFAComplete (handle_mfa.go).
				s.issueMFAChallenge(ctx, result, req, client)
				return
			}
			// spi.DecisionRequireMFA with NO provider wired falls through to
			// Allow — preserves the historical no-op behavior so callers
			// configuring a forward-looking scorer aren't broken when
			// they pre-date MFA orchestration. Operators who do ship MFA
			// add WithMFAProvider + WithMFAChallengeStore and this branch
			// never fires.
		}
	}

	s.finishLogin(ctx, result, req, client)
}

// finishLogin runs the post-credential-validation, post-risk-decision
// portion of /auth/login: optional userProvider upsert, OAuth 2.1
// strict checks, response_mode validation, the code-flow / direct-mint
// branches plus the refresh_token / id_token / permission-embed
// bookkeeping. Extracted so handleMFAComplete can re-enter the same
// flow after the step-up factor verifies — same response shape no
