package sso

import "github.com/snaplink/sso/oidc"

import "github.com/snaplink/sso/spi"

import "github.com/snaplink/sso/oauth"

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/snaplink/sso/security"
	"net/http"
	neturl "net/url"
	"slices"
	"strings"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/fapi"
	"github.com/snaplink/sso/geo"
	"github.com/snaplink/sso/tenant"
)

// errorBody / errorBodyWithDescription delegate to core/error_body.go.
// Keep the lowercase names so the 100+ call sites stay one-line.
func errorBody(code string) map[string]string { return core.ErrorBody(code) }

func errorBodyWithDescription(code, desc string) map[string]string {
	return core.ErrorBodyDesc(code, desc)
}

// bearerToken delegates to oauth.BearerToken — see that function for
// the RFC 6750 §2.1 missing-vs-bad-credential distinction.
func bearerToken(r *http.Request) string { return oauth.BearerToken(r) }

// clientTenantOK delegates to tenant.ClientOK.
func clientTenantOK(ctx HandlerContext, client *Client) bool {
	return tenant.ClientOK(ctx, client)
}

func (s *Server) handleHealth(ctx HandlerContext) {
	// BuildInfo surfaces version + VCS revision so operators can
	// confirm which commit a production replica is running without
	// shelling into the container. Cached after first call so this
	// stays cheap on the unauthenticated probe path.
	bi := ReadBuildInfo()
	resp := map[string]string{
		KeyStatus:  StatusOK,
		KeyIssuer:  s.issuer,
		KeyVersion: bi.Version,
	}
	if bi.VCSRevision != "" {
		resp[KeyVCSRevision] = bi.VCSRevision
	}
	if bi.VCSTime != "" {
		resp[KeyVCSTime] = bi.VCSTime
	}
	ctx.JSON(http.StatusOK, resp)
}

// loginRequest is the bound /auth/login request payload. Promoted from
// an anonymous local struct so the MFA-resume path (handle_mfa.go) can
// serialize + replay it.
type loginRequest struct {
	Provider             string            `json:"provider"`
	Credential           map[string]string `json:"credential"`
	ClientID             string            `json:"client_id"`
	Scope                []string          `json:"scope"`
	State                string            `json:"state"`
	ResponseType         string            `json:"response_type"`         // "code" → return auth code instead of token
	RedirectURI          string            `json:"redirect_uri"`          // required when response_type=code
	Nonce                string            `json:"nonce"`                 // OIDC nonce (passed through to oauth.AuthCode)
	CodeChallenge        string            `json:"code_challenge"`        // PKCE RFC 7636 §4.3
	CodeChallengeMethod  string            `json:"code_challenge_method"` // "S256" | "plain" (default plain per §4.3)
	Resource             []string          `json:"resource"`              // RFC 8707 resource indicators
	RequestURI           string            `json:"request_uri"`           // RFC 9126 PAR
	AuthorizationDetails json.RawMessage   `json:"authorization_details"` // RFC 9396
	Request              string            `json:"request"`               // RFC 9101 JAR
	Prompt               string            `json:"prompt"`                // OIDC Core §3.1.2.1: space-separated none|login|consent|select_account
	IDTokenHint          string            `json:"id_token_hint"`         // OIDC Core §3.1.2.1: identifies the subject for prompt=none
	MaxAge               *int64            `json:"max_age"`               // OIDC Core §3.1.2.1: max allowed auth age in seconds (pointer so 0 is distinguishable from absent)
	LoginHint            string            `json:"login_hint"`            // OIDC Core §3.1.2.1: subject identifier hint for the End-User
	ResponseMode         string            `json:"response_mode"`         // OIDC Core §3.1.2.1 + Form Post 1.0: query|fragment|form_post
	ACRValues            string            `json:"acr_values"`            // OIDC Core §3.1.2.1: space-separated preferred ACR values
	UILocales            string            `json:"ui_locales"`            // OIDC Core §3.1.2.1: space-separated BCP-47 language tags
	Claims               json.RawMessage   `json:"claims"`                // OIDC Core §5.5: requested claims JSON object
}

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
	if req.RequestURI != "" && security.IsJARFetchableURI(req.RequestURI) {
		// RFC 9101 §5.2.2 — JAR `request_uri` URL-fetch variant.
		// Fetch the signed JWT from the supplied URL, then fall
		// through into the existing JAR merge below by setting
		// req.Request to the fetched body. The fetched JWT still
		// goes through full signature + claim verification —
		// fetching only saves the RP an inline-JWT round trip.
		if s.jarFetcher == nil {
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequestURI))
			return
		}
		// Per-client allowlist is the SSRF defense. We must
		// resolve the client BEFORE the fetch — without the
		// allowlist check, an attacker who supplies an arbitrary
		// internal HTTPS URL could turn the AS into an SSRF
		// gadget. The form `client_id` is the lookup key
		// (the JWT's iss/client_id claim will be cross-checked
		// during verifyJAR below).
		if req.ClientID == "" || s.clientStore == nil {
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequestURI))
			return
		}
		c, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequestURI))
			return
		}
		if !security.IsRequestURIAllowed(req.RequestURI, c.AllowedRequestURIs) {
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequestURI))
			return
		}
		body, err := s.jarFetcher.Fetch(ctx.Request().Context(), req.RequestURI)
		if err != nil {
			s.logger.Error("jar fetch failed", "error", err, "client", req.ClientID, "uri", req.RequestURI)
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequestURI))
			return
		}
		// Hand off to the JAR merge below. Keep req.RequestURI
		// populated so the downstream `RequirePAR` gate sees the
		// client did push their request server-side (the two
		// shapes — PAR `urn:` and JAR URL — are equivalent from
		// the "request was authenticated up front" standpoint).
		req.Request = string(body)
	} else if req.RequestURI != "" {
		if s.parStore == nil {
			ctx.JSON(http.StatusNotImplemented, s.authzErrorBody(ctx, ErrPARNotConfigured))
			return
		}
		stored, err := s.parStore.Consume(ctx.Request().Context(), req.RequestURI)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequestURI))
			return
		}
		// Client identity from PAR is authoritative — clients
		// authenticated at /par; an attacker shouldn't be able to
		// flip client_id at the user-agent redirect step.
		if stored.ClientID != "" {
			req.ClientID = stored.ClientID
		}
		if stored.ResponseType != "" {
			req.ResponseType = stored.ResponseType
		}
		if stored.RedirectURI != "" {
			req.RedirectURI = stored.RedirectURI
		}
		if len(stored.Scope) > 0 {
			req.Scope = stored.Scope
		}
		if stored.State != "" {
			req.State = stored.State
		}
		if stored.Nonce != "" {
			req.Nonce = stored.Nonce
		}
		if stored.CodeChallenge != "" {
			req.CodeChallenge = stored.CodeChallenge
			req.CodeChallengeMethod = stored.CodeChallengeMethod
		}
		if len(stored.Resource) > 0 {
			req.Resource = stored.Resource
		}
		if len(stored.AuthorizationDetails) > 0 {
			// RFC 9396 + RFC 9126: PAR's value is committing the
			// authorization request authoritatively up-front, so the
			// pushed authorization_details wins over any caller-
			// supplied value at /auth/login (mirrors how PAR's
			// scope/resource/redirect_uri override the redirect-time
			// parameters).
			req.AuthorizationDetails = oauth.CloneRawJSON(stored.AuthorizationDetails)
		}
		if stored.LoginHint != "" {
			req.LoginHint = stored.LoginHint
		}
		if stored.ResponseMode != "" {
			req.ResponseMode = stored.ResponseMode
		}
		if stored.ACRValues != "" {
			req.ACRValues = stored.ACRValues
		}
		if stored.UILocales != "" {
			req.UILocales = stored.UILocales
		}
		if len(stored.Claims) > 0 {
			req.Claims = oauth.CloneRawJSON(stored.Claims)
		}
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
		jar, jarErr := verifyJAR(ctx.Request().Context(), jarRaw, client, s.resolveIssuer(ctx), s.jtiReplayStore)
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
		s.logger.Error("authentication failed", "provider", req.Provider, "error", err)
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
			s.logger.Error("risk scorer failed", "error", riskErr, "user", result.UserID, "client", req.ClientID)
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
// matter whether MFA gated the request or not.
func (s *Server) finishLogin(ctx HandlerContext, result *AuthResult, req loginRequest, client *Client) {
	if s.userProvider != nil {
		user := &User{
			ID:         result.UserID,
			ExternalID: result.ExternalID,
			Provider:   result.Provider,
			Attributes: result.Attributes,
		}
		if err := s.userProvider.CreateOrUpdate(ctx.Request().Context(), user); err != nil {
			s.logger.Error("failed to upsert user", "error", err)
			ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
			return
		}
	}

	// Non-blocking credential-health signal. Emitted once here so it
	// covers every downstream branch (code flow + direct mint) and both
	// the primary login and the MFA-resumed re-entry, which all funnel
	// through finishLogin. The signal NEVER blocks login and NEVER rides
	// on the wire — it lives only on the AuthResult and lands in the audit
	// log. nil = no signal (healthy credential or no checker wired).
	s.recordCredentialHealth(ctx, client.ID, result.UserID, result.CredentialHealth)

	// OAuth 2.1 strict mode: response_type=token (implicit) is
	// retired by OAuth 2.1; empty response_type (which defaulted
	// to direct-mint in OAuth 2.0) is treated the same way under
	// strict mode. Both reject with unsupported_response_type
	// — strict mode requires explicit response_type=code.
	if s.oauth21Strict && req.ResponseType != "code" {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrUnsupportedResponseType))
		return
	}

	// OIDC Form Post Response Mode 1.0 — validate response_mode
	// early so a bad value fails BEFORE any side-effects (auth code
	// issue, session create). Empty is always valid and falls
	// through to the response_type's default mode.
	if req.ResponseMode != "" && !s.isValidResponseMode(req.ResponseMode) {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequest))
		return
	}

	// OAuth 2.0 authorization_code branch: instead of minting a token
	// here, persist a short-lived code bound to (user, client, redirect_uri)
	// and return it so the relying party can exchange it via /token.
	if req.ResponseType == "code" {
		if s.authCodeStore == nil {
			ctx.JSON(http.StatusNotImplemented, s.authzErrorBody(ctx, ErrAuthCodeNotConfigured))
			return
		}
		if req.RedirectURI == "" || !client.IsRedirectURIValid(req.RedirectURI) {
			s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRedirectURI)
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRedirectURI))
			return
		}
		// OAuth 2.1 §4.1.3 — redirect_uri MUST use https. Localhost
		// (any port) remains permitted for development workflows.
		if s.oauth21Strict && !isSecureRedirectURI(req.RedirectURI) {
			s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRedirectURI)
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRedirectURI))
			return
		}
		// PKCE validation per RFC 7636 §4.3:
		// * If client policy requires PKCE, code_challenge MUST be set.
		// * OAuth 2.1 §4.1.1 makes PKCE mandatory; strict mode honors
		//   that even when the client has RequirePKCE=false set.
		// * If code_challenge IS set, length and method MUST be valid.
		// * Empty method defaults to "plain" per §4.3 (callers should
		//   prefer S256; "plain" stays for legacy interop).
		if req.CodeChallenge == "" {
			if client.RequirePKCE || s.oauth21Strict {
				s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrPKCERequired)
				ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrPKCERequired))
				return
			}
		} else {
			if l := len(req.CodeChallenge); l < PKCEVerifierMinLen || l > PKCEVerifierMaxLen {
				s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRequest)
				ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequest))
				return
			}
			if !isValidPKCEMethod(req.CodeChallengeMethod) {
				s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidPKCEMethod)
				ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidPKCEMethod))
				return
			}
			if req.CodeChallengeMethod == "" {
				req.CodeChallengeMethod = PKCEMethodPlain
			}
			// Per-client PKCE method allowlist (Client.AllowedPKCEMethods).
			// When set, every challenge method MUST appear in the list
			// — the canonical use case is forcing S256 on production
			// clients while leaving legacy clients on the default
			// (RFC-permissive) behavior.
			if !isPKCEMethodAllowedForClient(req.CodeChallengeMethod, client.AllowedPKCEMethods) {
				s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidPKCEMethod)
				ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidPKCEMethod))
				return
			}
		}
		code, err := s.issueAuthCode(ctx.Request().Context(), result, &req, client)
		if err != nil {
			s.logger.Error("failed to issue auth code", "error", err)
			ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
			return
		}
		s.recordLoginSuccess(ctx, client.ID, req.Provider, "code", result.UserID, "")

		// OIDC Form Post Response Mode 1.0: when the RP requested
		// form_post, render an HTML auto-POST page targeting
		// redirect_uri instead of the JSON body. Available only on
		// code flow (where there's a redirect_uri to POST to);
		// other response modes (query, fragment, empty) keep the
		// existing JSON response — the RP's own JS handles the
		// post-fetch redirect.
		if req.ResponseMode == ResponseModeFormPost {
			s.renderFormPostResponse(ctx, req.RedirectURI, code, req.State)
			return
		}

		// JARM — sign the authorization response into a JWT carried as
		// the single `response` parameter (query / fragment / form_post
		// per the sub-mode; the bare `jwt` alias resolves to query). A
		// JARM mode only reaches here when a signer is wired (gated in
		// isValidResponseMode). The signer is resolved per-tenant so a
		// tenant's authorization response is signed by the same key as
		// its access + id tokens. A signing failure — or a tenant whose
		// issuer can't sign JARM (jarmSignerForClient → ok=false) —
		// fails closed with invalid_request rather than leaking the bare
		// code under the shared key.
		if oidc.IsJARMResponseMode(req.ResponseMode) {
			signer, ok := s.jarmSignerForClient(client)
			if !ok || !oidc.RenderJARMResponse(ctx, signer, req.ResponseMode, req.RedirectURI, s.resolveIssuer(ctx), client.ID, code, req.State) {
				ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidRequest))
			}
			return
		}

		resp := map[string]any{
			KeyCode: code,
			KeyIss:  s.resolveIssuer(ctx),
		}
		if req.State != "" {
			resp[KeyState] = req.State
		}
		ctx.JSON(http.StatusOK, resp)
		return
	}
	if req.ResponseType != "" && req.ResponseType != "token" {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrUnsupportedResponseType))
		return
	}

	if s.sessionMgr == nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrSessionMgrNotConfigured))
		return
	}
	session, err := s.sessionMgr.Create(ctx.Request().Context(), result.UserID)
	if err != nil {
		s.logger.Error("failed to create session", "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}

	strategy, ti, err := s.issuerForClient(client)
	if err != nil {
		s.logger.Error("no token strategy for client", "client", client.ID, "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrNoTokenStrategy))
		return
	}
	issuedSub := s.applyPairwiseSubject(ctx.Request().Context(), client, result.UserID)
	token, err := ti.Issue(ctx.Request().Context(), &Subject{
		ID:                   issuedSub,
		Provider:             result.Provider,
		Claims:               result.Attributes,
		Resources:            append([]string(nil), req.Resource...),
		ClientID:             client.ID,
		AuthTime:             time.Now(),
		AMR:                  []string{result.Provider},
		AuthorizationDetails: oauth.CloneRawJSON(req.AuthorizationDetails),
		SID:                  session.ID,
		TTL:                  client.AccessTokenTTL,
	}, req.Scope)
	if err != nil {
		s.logger.Error("failed to issue token", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}

	s.recordLoginSuccess(ctx, client.ID, req.Provider, strategy, result.UserID, session.ID)
	s.recordSubjectClientAccess(ctx.Request().Context(), result.UserID, client.ID)

	// Geo enrichment: if the authenticator didn't supply
	// country/language hints, fall back to whatever the geo
	// middleware stashed on the request. Authenticators with a
	// stronger signal (SIM region, account default, explicit user
	// pref) override the geo guess by setting them themselves.
	// One Get to avoid two ctx.Get round trips.
	if result.CountryCode == "" || result.RecommendedLanguage == "" {
		if info, ok := GeoFromHandlerContext(ctx); ok {
			if result.CountryCode == "" {
				result.CountryCode = info.CountryCode
			}
			if result.RecommendedLanguage == "" {
				result.RecommendedLanguage = info.RecommendedLanguage
			}
		}
	}

	// When a oauth.RefreshTokenStore is wired, server-managed refresh tokens
	// override whatever the underlying TokenIssuer returned — that way
	// the OAuth refresh_token grant works uniformly regardless of which
	// issuer minted the access token. Fail-open: a refresh-token store
	// outage doesn't block the login (user gets an access_token they
	// can use until expiry), but it does surface as a server-side
	// logger.Error so operators see the degradation.
	refreshTokenOut := token.RefreshToken
	if s.refreshTokenStore != nil {
		rt, err := s.issueRefreshToken(ctx.Request().Context(),
			result.UserID, client.ID, result.Provider, req.Scope, result.Attributes, "", req.Resource,
			req.AuthorizationDetails, session.ID, client.RefreshTokenTTL)
		if err != nil {
			s.logger.Error("refresh token issue failed", "error", err, "client", client.ID, "user", result.UserID)
		} else {
			refreshTokenOut = rt
			s.recordRefreshTokenIssued(ctx, client.ID, result.UserID, false)
		}
	}

	resp := map[string]any{
		KeySessionID:     session.ID,
		KeyAccessToken:   token.AccessToken,
		KeyTokenType:     token.TokenType,
		KeyRefreshToken:  refreshTokenOut,
		KeyExpiresIn:     token.ExpiresIn,
		KeyScope:         token.Scope,
		KeyTokenStrategy: strategy,
		KeyIss:           s.resolveIssuer(ctx),
	}
	// OIDC ID Token: emit alongside the access token whenever the
	// caller requested "openid" scope AND an issuer is wired. Errors
	// fail open — a misconfigured ID-token issuer shouldn't block the
	// underlying authentication, the relying party just won't get
	// id_token in the response.
	if slices.Contains(req.Scope, ScopeOpenID) {
		idIssuer, emit, idErr := s.idTokenIssuerForClient(client)
		if idErr != nil {
			// Tenant mapping named an unregistered issuer — fail closed
			// (omit id_token) rather than sign with the shared key.
			s.logger.Error("id token issuer resolution failed; omitting id_token", "error", idErr, "client", client.ID, "user", result.UserID)
		} else if emit {
			idToken, err := idIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
				Subject:  issuedSub,
				Audience: client.ID,
				Nonce:    req.Nonce,
				AuthTime: time.Now(),
				AMR:      []string{result.Provider},
				Claims:   result.Attributes,
				SID:      session.ID,
			})
			if err != nil {
				s.logger.Error("id token issue failed", "error", err, "client", client.ID, "user", result.UserID)
			} else if enc, ok := s.maybeEncryptIDToken(ctx.Request().Context(), client, idToken); ok {
				resp[KeyIDToken] = enc
				s.recordIDTokenIssued(ctx, client.ID, result.UserID)
			}
		}
	}
	if result.CountryCode != "" {
		resp[KeyCountryCode] = result.CountryCode
	}
	if result.RecommendedLanguage != "" {
		resp[KeyRecommendedLang] = result.RecommendedLanguage
	}
	if s.embedPermissions {
		roles, perms, menus := s.resolvePermissionsForLogin(ctx.Request().Context(), result.UserID, client.ID)
		resp[KeyRoles] = roles
		resp[KeyPermissions] = perms
		resp[KeyMenus] = menus
	}
	ctx.JSON(http.StatusOK, resp)
}

// issueAuthCode generates an authorization code, persists it against the
// store, and returns the opaque code string. The TTL is taken from the
// Server's authCodeTTL with a fallback to DefaultAuthCodeTTL.
func (s *Server) issueAuthCode(
	ctx context.Context,
	result *AuthResult,
	req *loginRequest,
	client *Client,
) (string, error) {
	code, err := generateAuthCodeBytes()
	if err != nil {
		return "", fmt.Errorf("generate auth code: %w", err)
	}
	ttl := s.authCodeTTL
	if ttl <= 0 {
		ttl = DefaultAuthCodeTTL
	}
	entry := &oauth.AuthCode{
		UserID:               result.UserID,
		ClientID:             client.ID,
		RedirectURI:          req.RedirectURI,
		Scopes:               append([]string(nil), req.Scope...),
		Nonce:                req.Nonce,
		Provider:             result.Provider,
		Attributes:           result.Attributes,
		CodeChallenge:        req.CodeChallenge,
		CodeChallengeMethod:  req.CodeChallengeMethod,
		Resources:            append([]string(nil), req.Resource...),
		AuthorizationDetails: oauth.CloneRawJSON(req.AuthorizationDetails),
		ExpiresAt:            time.Now().Add(ttl),
	}
	if err := s.authCodeStore.Issue(ctx, code, entry); err != nil {
		return "", fmt.Errorf("store auth code: %w", err)
	}
	return code, nil
}

// isSecureRedirectURI reports whether the URI satisfies the OAuth 2.1
// §4.1.3 redirect_uri security profile: scheme=https required for
// public hosts; http://localhost (or http://127.0.0.1 / [::1]) on any
// port stays permitted so development workflows don't need a local
// TLS terminator. URIs that fail to parse return false (closed
// default), which collapses to invalid_redirect_uri on the caller.
func isSecureRedirectURI(uri string) bool {
	u, err := neturl.Parse(uri)
	if err != nil || u == nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}
	return false
}

// isValidPKCEMethod reports whether the named PKCE challenge method is
// one we support. Empty defaults to "plain" per RFC 7636 §4.3 (the
// caller stamps the default after this check); "S256" is the strongly
// recommended method for production.
func isValidPKCEMethod(method string) bool {
	return method == "" || method == PKCEMethodPlain || method == PKCEMethodS256
}

// isPKCEMethodAllowedForClient reports whether the (already-validated)
// PKCE challenge method is permitted under the client's per-client
// allowlist. Empty allowlist = unrestricted (legacy behavior, accept
// anything isValidPKCEMethod accepted). Empty method input means the
// default was applied — must be allowlisted too.
func isPKCEMethodAllowedForClient(method string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == method {
			return true
		}
	}
	return false
}

// verifyPKCE returns true when the supplied verifier derives to the
// stored challenge under the named method. Constant-time comparison
// closes off timing-oracle attacks on the challenge value.
//
// An empty challenge means no PKCE binding was set at issue; callers
// MUST NOT invoke this helper in that case (the exchange skips PKCE
// entirely when info.CodeChallenge is empty — backwards compatible
// with confidential clients).
func verifyPKCE(method, challenge, verifier string) bool {
	switch method {
	case PKCEMethodS256:
		sum := sha256.Sum256([]byte(verifier))
		derived := base64.RawURLEncoding.EncodeToString(sum[:])
		return subtle.ConstantTimeCompare([]byte(derived), []byte(challenge)) == 1
	case PKCEMethodPlain, "":
		return subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) == 1
	default:
		return false
	}
}

// generateAuthCodeBytes mints a cryptographically random base64url code.
// Local copy so handler.go doesn't depend on defaultimpl.
func generateAuthCodeBytes() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// issueRefreshToken generates a refresh token, persists it against the
// store, and returns the opaque token string. The TTL is taken from the
// Server's refreshTokenTTL with a fallback to DefaultRefreshTokenTTL.
//
// familyID controls the OAuth Security BCP §4.13 family-tracking
// chain: pass "" on the FIRST issue (login, authz_code, device) to
// mint a new family, or the existing FamilyID on rotation to keep
// every descendant of a single authorization event in one family.
// Stores that don't implement oauth.RefreshTokenFamilyTracker simply
// ignore the value — opt-in hardening.
//
// Callers MUST pre-check s.refreshTokenStore != nil — this helper
// dereferences it unconditionally so a misuse fails loudly during
// testing rather than silently no-op'ing in production.
func (s *Server) issueRefreshToken(
	ctx context.Context,
	userID, clientID, provider string,
	scopes []string,
	attributes map[string]string,
	familyID string,
	resources []string,
	authDetails json.RawMessage,
	sid string,
	clientTTLOverride time.Duration,
) (string, error) {
	token, err := generateAuthCodeBytes() // same 32-byte base64url generator
	if err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	// TTL resolution precedence: per-client override > server-wide
	// configuration > DefaultRefreshTokenTTL. The per-client override
	// lets operators give SPAs (public clients) short refresh tokens
	// while keeping long ones for service clients.
	ttl := clientTTLOverride
	if ttl <= 0 {
		ttl = s.refreshTokenTTL
	}
	if ttl <= 0 {
		ttl = DefaultRefreshTokenTTL
	}
	if familyID == "" {
		// First-issue path: mint a new family. Length matches the
		// token itself — 32 bytes / 256 bits — so collisions across
		// the fleet remain infeasible.
		fid, err := generateAuthCodeBytes()
		if err != nil {
			return "", fmt.Errorf("generate refresh family id: %w", err)
		}
		familyID = fid
	}
	now := time.Now()
	entry := &oauth.RefreshToken{
		UserID:               userID,
		ClientID:             clientID,
		Provider:             provider,
		Scopes:               append([]string(nil), scopes...),
		Attributes:           attributes,
		IssuedAt:             now,
		ExpiresAt:            now.Add(ttl),
		FamilyID:             familyID,
		Resources:            append([]string(nil), resources...),
		AuthorizationDetails: oauth.CloneRawJSON(authDetails),
		SID:                  sid,
	}
	if err := s.refreshTokenStore.Issue(ctx, token, entry); err != nil {
		return "", fmt.Errorf("store refresh token: %w", err)
	}
	return token, nil
}

// isScopeSubset reports whether every scope in want is also in have.
// Used by the refresh_token grant to enforce RFC 6749 §6's "MUST NOT
// expand scope" rule — a refresh request may downscope or keep the
// original grant but never widen it.
func isScopeSubset(want, have []string) bool {
	if len(want) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(have))
	for _, s := range have {
		set[s] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[w]; !ok {
			return false
		}
	}
	return true
}

// providersForClient returns the list of authenticator names this client may
// use. Used by GET /auth/login (provider discovery). If clientID is empty or
// not found, all registered providers are returned (backwards compatible).
func (s *Server) providersForClient(ctx HandlerContext, clientID string) []string {
	all := make([]string, 0, len(s.authenticators))
	for name := range s.authenticators {
		all = append(all, name)
	}
	if clientID == "" || s.clientStore == nil {
		return all
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil {
		return all
	}
	if len(client.AllowedAuthenticators) == 0 {
		return all
	}
	out := make([]string, 0, len(all))
	for _, name := range all {
		if client.IsAuthenticatorAllowed(name) {
			out = append(out, name)
		}
	}
	return out
}

func (s *Server) handleCallback(ctx HandlerContext) {
	code := ctx.Query("code")
	state := ctx.Query("state")
	provider := ctx.Query("provider")

	if code == "" || state == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidCallback))
		return
	}

	var auth Authenticator
	var err error
	if provider != "" {
		auth, err = s.getAuthenticator(provider)
	} else {
		for _, a := range s.authenticators {
			if _, err = a.Callback(context.Background(), &CallbackState{Code: code, State: state}); err == nil {
				auth = a
				break
			}
		}
	}

	if auth == nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrUnknownProvider))
		return
	}

	result, err := auth.Callback(context.Background(), &CallbackState{Code: code, State: state})
	if err != nil {
		s.logger.Error("callback failed", "provider", auth.Name(), "error", err)
		s.recordCallbackFailure(ctx, auth.Name(), ErrCallbackFailed)
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrCallbackFailed))
		return
	}

	user := &User{
		ID:         result.UserID,
		ExternalID: result.ExternalID,
		Provider:   result.Provider,
		Attributes: result.Attributes,
	}
	if s.userProvider != nil {
		s.userProvider.CreateOrUpdate(ctx.Request().Context(), user)
	}

	session, err := s.sessionMgr.Create(ctx.Request().Context(), result.UserID)
	if err != nil {
		s.logger.Error("failed to create session", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	ctx.JSON(http.StatusOK, map[string]string{
		KeySessionID: session.ID,
		KeyStatus:    StatusAuthenticated,
	})
}

func (s *Server) handleToken(ctx HandlerContext) {
	// RFC 6749 §5.1: token responses (successful AND error) MUST
	// include Cache-Control: no-store + Pragma: no-cache so
	// intermediaries (browsers, HTTP caches, edge proxies) never
	// retain credentials. Set BEFORE writing the response body so
	// the header is on the wire regardless of which code path
	// returns. Same requirement applies to /token/introspect and
	// /token/revoke via tokenNoStoreHeaders below.
	tokenNoStoreHeaders(ctx)
	if err := s.requireDeps(DepTokenIssuer, DepClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	var req struct {
		GrantType    string   `json:"grant_type"`
		Code         string   `json:"code"`
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		RefreshToken string   `json:"refresh_token"`
		Scope        string   `json:"scope"`
		RedirectURI  string   `json:"redirect_uri"`
		CodeVerifier string   `json:"code_verifier"` // PKCE RFC 7636 §4.5
		DeviceCode   string   `json:"device_code"`   // RFC 8628 §3.4 device grant
		AuthReqID    string   `json:"auth_req_id"`   // OIDC CIBA Core §10.1 grant
		Resource     []string `json:"resource"`      // RFC 8707 resource indicators

		// RFC 8693 token-exchange parameters.
		SubjectToken       string   `json:"subject_token"`
		SubjectTokenType   string   `json:"subject_token_type"`
		ActorToken         string   `json:"actor_token"`
		ActorTokenType     string   `json:"actor_token_type"`
		Audience           []string `json:"audience"`
		RequestedTokenType string   `json:"requested_token_type"`
		// RFC 9470 step-up: caller may demand the exchanged token
		// carries an ACR at least as strong as one in this list.
		// Used when the subject_token was minted from a weak factor
		// (e.g. password only) but the downstream resource requires
		// MFA — caller passes acr_values="urn:mace:incommon:iap:silver"
		// and the dispatcher rejects with insufficient_user_authentication
		// when the inbound ACR doesn't satisfy.
		ACRValues string `json:"acr_values"`

		// RFC 7521 + 7523 JWT bearer client authentication.
		ClientAssertion     string `json:"client_assertion"`
		ClientAssertionType string `json:"client_assertion_type"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	// HTTP Basic auth takes precedence over body fields per RFC 6749 §2.3.1.
	var basicAuthUsed bool
	if id, secret, ok := basicClientCreds(ctx.Request()); ok {
		req.ClientID = id
		req.ClientSecret = secret
		basicAuthUsed = true
	}

	// RFC 7521 §4.2 + RFC 7523 §2.2 — JWT bearer client authentication.
	// When `client_assertion_type` is the jwt-bearer URN AND
	// `client_assertion` is supplied, the JWT replaces client_secret
	// as the proof of client identity. The JWT MUST be signed by a
	// key in Client.JWKS; iss / sub MUST equal the client_id; aud
	// MUST include the AS issuer or the token endpoint URL; exp
	// MUST be in the future. Replay defense (jti tracking) reuses
	// the security.JTIReplayStore wiring JAR already opts into.
	if req.ClientAssertion != "" || req.ClientAssertionType != "" {
		if req.ClientAssertionType != ClientAssertionTypeJWTBearer {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
			return
		}
		assertedID, err := verifyJWTClientAssertion(
			ctx.Request().Context(),
			req.ClientAssertion,
			req.ClientID,
			s.clientStore,
			s.resolveIssuer(ctx),
			s.jtiReplayStore,
		)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
			return
		}
		req.ClientID = assertedID
	}

	client, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
		return
	}
	if !clientTenantOK(ctx, client) {
		ctx.JSON(http.StatusForbidden, errorBody(ErrTenantMismatch))
		return
	}
	// Skip the client_secret check when the caller authenticated
	// via JWT assertion — Client.JWKS verification stands in for
	// the secret. RFC 7521 §4.2 prohibits requiring BOTH proofs.
	if req.ClientAssertion == "" {
		if err := s.clientStore.ValidateSecret(ctx.Request().Context(), req.ClientID, req.ClientSecret); err != nil {
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClientSecret))
			return
		}
	}
	// RFC 8707 §2: each requested `resource` MUST be allowlisted on
	// the client. Empty allowlist disables enforcement (legacy compat).
	if !client.AreResourcesAllowed(req.Resource) {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidTarget))
		return
	}

	// RFC 9449 — DPoP. When the request carries a `DPoP` header,
	// validate the proof and stash the resulting JKT so the grant
	// branches below can bind the issued access token to the key.
	// Absence of the header keeps the legacy bearer-token path —
	// DPoP is opt-in per request, never required by this server.
	var dpopJKT string
	if proof := ctx.Request().Header.Get(HeaderDPoP); proof != "" {
		binding, err := verifyDPoPProof(
			ctx.Request().Context(),
			proof,
			ctx.Request().Method,
			requestURLForDPoP(ctx.Request()),
			s.jtiReplayStore,
			s.dpopNonceProvider,
		)
		if err != nil {
			// RFC 9449 §8 — nonce required: stamp a fresh nonce on
			// the response and respond with use_dpop_nonce instead
			// of invalid_dpop_proof so clients can retry. AS-side
			// uses HTTP 400 (vs 401 for RS-side).
			if errors.Is(err, ErrDPoPNonceRequired) {
				s.stampDPoPNonce(ctx)
				s.logger.Info("dpop nonce challenge", "method", ctx.Request().Method)
				ctx.JSON(http.StatusBadRequest, errorBody(ErrUseDPoPNonce))
				return
			}
			s.logger.Error("dpop proof failed", "error", err)
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidDPoPProof))
			return
		}
		dpopJKT = binding.JKT
	}

	// RFC 8705 §3 — mTLS certificate-bound access tokens. When a
	// client cert extractor is wired AND the inbound request
	// carries a client cert, stamp the cert's SHA-256 thumbprint
	// into the token's cnf.x5t#S256 claim. Mutually exclusive
	// with DPoP — first-set wins (caller MUST NOT supply both,
	// the configuration is per-token).
	var mtlsX5T string
	if s.clientCertExtractor != nil {
		if cert, ok := s.clientCertExtractor.ExtractClientCert(ctx.Request()); ok && cert != nil {
			mtlsX5T = certificateThumbprintS256(cert)
		}
	}

	// FAPI 2.0 Security Profile — issued access tokens MUST be
	// sender-constrained via DPoP or mTLS. Checked once here, before
	// the grant switch, so it applies uniformly to every grant that
	// mints an access token. Inspection mode audits and proceeds;
	// enforce mode rejects with invalid_request (a bearer-only token
	// request is the violation, not a credential failure — no oracle
	// concern). The rule id lands in the audit event; the wire stays
	// the standard error code.
	if s.fapiValidator.Active() {
		// Classify the client-authentication method used on this token
		// request so the FAPI client-auth rule can reject shared-secret
		// auth. private_key_jwt (assertion) and mTLS (client cert) are
		// the only FAPI-permitted methods; Basic / body secret map to
		// the prohibited shared-secret methods.
		clientAuthMethod := fapi.ClientAuthNone
		switch {
		case req.ClientAssertion != "":
			clientAuthMethod = fapi.ClientAuthPrivateKeyJWT
		case mtlsX5T != "":
			clientAuthMethod = fapi.ClientAuthTLS
		case basicAuthUsed:
			clientAuthMethod = fapi.ClientAuthSecretBasic
		case req.ClientSecret != "":
			clientAuthMethod = fapi.ClientAuthSecretPost
		}
		if vs := s.fapiValidator.CheckToken(fapi.TokenContext{
			ClientID:          req.ClientID,
			GrantType:         req.GrantType,
			SenderConstrained: dpopJKT != "" || mtlsX5T != "",
			ClientAuthMethod:  clientAuthMethod,
		}); len(vs) > 0 {
			mode := s.fapiValidator.Mode().String()
			for _, v := range vs {
				audit.RecordFAPIViolation(s.auditor, ctx, v.ClientID, v.RuleID, v.Detail, mode)
				if s.metrics != nil {
					s.metrics.FAPIViolationsTotal.WithLabelValues(v.RuleID, mode).Inc()
				}
			}
			if s.fapiValidator.Enforcing() {
				ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
				return
			}
		}
	}

	var scopes []string
	if req.Scope != "" {
		scopes = strings.Split(req.Scope, " ")
	}

	switch req.GrantType {
	case GrantAuthorizationCode:
		if s.authCodeStore == nil {
			ctx.JSON(http.StatusNotImplemented, errorBody(ErrAuthCodeNotConfigured))
			return
		}
		if req.Code == "" {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
			return
		}
		info, err := s.authCodeStore.Consume(ctx.Request().Context(), req.Code)
		if err != nil {
			// Unknown / expired / already-consumed all map to invalid_grant
			// per RFC 6749 §5.2 — clients can't distinguish, by design.
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
			return
		}
		// Bind the code to the client that's exchanging it.
		if info.ClientID != client.ID {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
			return
		}
		// Bind to the redirect_uri that was registered at issue time.
		if info.RedirectURI != "" && req.RedirectURI != info.RedirectURI {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRedirectURI))
			return
		}
		// PKCE verification per RFC 7636 §4.6: if a challenge was
		// captured at issue, the exchange MUST present a verifier
		// that derives to it under the original method. All failure
		// cases (missing verifier, malformed verifier, wrong verifier)
		// map to invalid_grant — RFC-mandated, and the oracle-leak
		// hardening matches the rest of the code exchange.
		if info.CodeChallenge != "" {
			if l := len(req.CodeVerifier); l < PKCEVerifierMinLen || l > PKCEVerifierMaxLen {
				ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
				return
			}
			if !verifyPKCE(info.CodeChallengeMethod, info.CodeChallenge, req.CodeVerifier) {
				ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
				return
			}
		}
		strategy, ti, err := s.issuerForClient(client)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrNoTokenStrategy))
			return
		}
		// Prefer the scopes captured at issue time; fall back to whatever
		// the caller supplied so older clients that don't echo the scope
		// param still get a sensible token.
		scopes := info.Scopes
		if len(scopes) == 0 {
			scopes = strings.Split(req.Scope, " ")
		}
		// Resources captured at authorization win over anything the
		// exchange caller supplies (RFC 8707 binds the audience at
		// authorization time, not at token redemption).
		resources := info.Resources
		if len(resources) == 0 {
			resources = req.Resource
		}
		issuedSub := s.applyPairwiseSubject(ctx.Request().Context(), client, info.UserID)
		token, err := ti.Issue(ctx.Request().Context(), &Subject{
			ID: issuedSub, Provider: info.Provider, Claims: info.Attributes,
			Resources:            resources,
			ClientID:             client.ID,
			AuthTime:             time.Now(),
			AMR:                  []string{info.Provider},
			AuthorizationDetails: oauth.CloneRawJSON(info.AuthorizationDetails),
			SID:                  info.SID,
			TTL:                  client.AccessTokenTTL,
			ConfirmationJKT:      dpopJKT,
			ConfirmationX5TS256:  mtlsX5T,
		}, scopes)
		if err != nil {
			s.logger.Error("token issuance failed", "strategy", strategy, "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
			return
		}
		s.recordTokenIssued(ctx, client.ID, strategy, info.UserID)
		s.recordSubjectClientAccess(ctx.Request().Context(), info.UserID, client.ID)
		resp := map[string]any{
			KeyAccessToken:   token.AccessToken,
			KeyTokenType:     dpopTokenTypeOr(token.TokenType, dpopJKT),
			KeyExpiresIn:     token.ExpiresIn,
			KeyScope:         token.Scope,
			KeyTokenStrategy: strategy,
		}
		if s.refreshTokenStore != nil {
			rt, err := s.issueRefreshToken(ctx.Request().Context(),
				info.UserID, client.ID, info.Provider, scopes, info.Attributes, "", info.Resources,
				info.AuthorizationDetails, info.SID, client.RefreshTokenTTL)
			if err != nil {
				s.logger.Error("refresh token issue failed", "error", err, "client", client.ID, "user", info.UserID)
			} else {
				resp[KeyRefreshToken] = rt
				s.recordRefreshTokenIssued(ctx, client.ID, info.UserID, false)
			}
		}
		// OIDC ID Token on the authorization_code path: same gate as
		// the direct-mint login flow, but the scope + nonce come from
		// what we captured at issue time, not from the exchange body.
		if slices.Contains(info.Scopes, ScopeOpenID) {
			idIssuer, emit, idErr := s.idTokenIssuerForClient(client)
			if idErr != nil {
				s.logger.Error("id token issuer resolution failed; omitting id_token", "error", idErr, "client", client.ID, "user", info.UserID)
			} else if emit {
				idToken, err := idIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
					Subject:  issuedSub,
					Audience: client.ID,
					Nonce:    info.Nonce,
					AuthTime: time.Now(),
					AMR:      []string{info.Provider},
					Claims:   info.Attributes,
				})
				if err != nil {
					s.logger.Error("id token issue failed", "error", err, "client", client.ID, "user", info.UserID)
				} else if enc, ok := s.maybeEncryptIDToken(ctx.Request().Context(), client, idToken); ok {
					resp[KeyIDToken] = enc
					s.recordIDTokenIssued(ctx, client.ID, info.UserID)
				}
			}
		}
		ctx.JSON(http.StatusOK, resp)
	case GrantRefreshToken:
		if s.refreshTokenStore == nil {
			ctx.JSON(http.StatusNotImplemented, errorBody(ErrRefreshTokenNotConfigured))
			return
		}
		if req.RefreshToken == "" {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
			return
		}
		info, err := s.refreshTokenStore.Consume(ctx.Request().Context(), req.RefreshToken)
		if err != nil {
			// OAuth Security BCP §4.13: a previously-consumed token
			// presented again is a reuse signal. Kill the whole family
			// (every sibling and descendant) before returning the wire
			// error — an attacker who already rotated after stealing
			// the leaf loses access to the active descendant too.
			if errors.Is(err, oauth.ErrRefreshTokenReused) && info != nil && info.FamilyID != "" {
				killed := 0
				if tracker, ok := s.refreshTokenStore.(oauth.RefreshTokenFamilyTracker); ok {
					n, derr := tracker.DeleteFamily(ctx.Request().Context(), info.FamilyID)
					if derr != nil {
						s.logger.Error("family revocation on reuse failed",
							"error", derr, "family", info.FamilyID)
					} else {
						killed = n
						s.logger.Error("refresh token reuse detected — family revoked",
							"family", info.FamilyID, "killed", killed,
							"client", client.ID)
					}
				}
				s.recordRefreshTokenReuse(ctx, client.ID, info.FamilyID, killed)
			}
			// Unknown / expired / already-consumed all map to invalid_grant
			// per RFC 6749 §5.2 — clients can't distinguish, by design.
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
			return
		}
		// Bind the token to the client that's exchanging it (RFC 6749 §6).
		if info.ClientID != client.ID {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
			return
		}
		// Scope rules per RFC 6749 §6: omitted scope = keep original;
		// supplied scope MUST be a subset of the original (narrowing
		// allowed, expansion forbidden).
		grantScopes := info.Scopes
		if req.Scope != "" {
			requested := strings.Split(req.Scope, " ")
			if !isScopeSubset(requested, info.Scopes) {
				ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidScope))
				return
			}
			grantScopes = requested
		}
		strategy, ti, err := s.issuerForClient(client)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrNoTokenStrategy))
			return
		}
		issuedSub := s.applyPairwiseSubject(ctx.Request().Context(), client, info.UserID)
		token, err := ti.Issue(ctx.Request().Context(), &Subject{
			ID: issuedSub, Provider: info.Provider, Claims: info.Attributes,
			Resources: info.Resources,
			ClientID:  client.ID,
			// Refresh rotations don't reset auth_time per RFC 9068
			// — the underlying authentication event is the original
			// login, not the refresh exchange. AMR likewise stays
			// the original method.
			AMR: []string{info.Provider},
			// RFC 9396: the authorization_details grant captured
			// at the original authorization survives the rotation
			// — refreshed tokens MUST carry the same fine-grained
			// authorization the user already consented to.
			AuthorizationDetails: oauth.CloneRawJSON(info.AuthorizationDetails),
			// SID is locked to the original authorization's
			// session — rotation never opens a new session.
			SID:                 info.SID,
			TTL:                 client.AccessTokenTTL,
			ConfirmationJKT:     dpopJKT,
			ConfirmationX5TS256: mtlsX5T,
		}, grantScopes)
		if err != nil {
			s.logger.Error("token issuance failed", "strategy", strategy, "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
			return
		}
		// Rotation: issue a NEW refresh token (the old one was deleted by
		// Consume above). Pass info.FamilyID so the new leaf joins the
		// same family — stores that track families can detect any
		// future reuse anywhere in the chain. A presented-twice old
		// token now fails as invalid_grant (and kills the family).
		newRefresh, err := s.issueRefreshToken(ctx.Request().Context(),
			info.UserID, client.ID, info.Provider, grantScopes, info.Attributes, info.FamilyID, info.Resources,
			info.AuthorizationDetails, info.SID, client.RefreshTokenTTL)
		if err != nil {
			s.logger.Error("refresh token rotation failed", "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
			return
		}
		s.recordTokenIssued(ctx, client.ID, strategy, info.UserID)
		s.recordRefreshTokenIssued(ctx, client.ID, info.UserID, true)
		s.recordSubjectClientAccess(ctx.Request().Context(), info.UserID, client.ID)
		ctx.JSON(http.StatusOK, map[string]any{
			KeyAccessToken:   token.AccessToken,
			KeyTokenType:     token.TokenType,
			KeyRefreshToken:  newRefresh,
			KeyExpiresIn:     token.ExpiresIn,
			KeyScope:         token.Scope,
			KeyTokenStrategy: strategy,
		})
	case GrantDeviceCode:
		s.handleDeviceTokenGrant(ctx, client, req.DeviceCode)
	case GrantCIBA:
		s.handleCIBATokenGrant(ctx, client, req.AuthReqID, dpopJKT, mtlsX5T)
	case GrantTokenExchange:
		s.handleTokenExchangeGrant(ctx, client, tokenExchangeRequest{
			SubjectToken:       req.SubjectToken,
			SubjectTokenType:   req.SubjectTokenType,
			ActorToken:         req.ActorToken,
			ActorTokenType:     req.ActorTokenType,
			Resource:           req.Resource,
			Audience:           req.Audience,
			Scope:              req.Scope,
			RequestedTokenType: req.RequestedTokenType,
			ACRValues:          req.ACRValues,
		})
	case GrantClientCredentials:
		strategy, ti, err := s.issuerForClient(client)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrNoTokenStrategy))
			return
		}
		// client_credentials: subject IS the client, so ClientID =
		// Sub. No end-user auth event, hence no AuthTime/AMR.
		token, err := ti.Issue(ctx.Request().Context(), &Subject{
			ID: client.ID, Resources: req.Resource, ClientID: client.ID,
			TTL:                 client.AccessTokenTTL,
			ConfirmationJKT:     dpopJKT,
			ConfirmationX5TS256: mtlsX5T,
		}, scopes)
		if err != nil {
			s.logger.Error("token issuance failed", "strategy", strategy, "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
			return
		}
		s.recordTokenIssued(ctx, client.ID, strategy, client.ID)
		ctx.JSON(http.StatusOK, map[string]any{
			KeyAccessToken:   token.AccessToken,
			KeyTokenType:     dpopTokenTypeOr(token.TokenType, dpopJKT),
			KeyExpiresIn:     token.ExpiresIn,
			KeyScope:         token.Scope,
			KeyTokenStrategy: strategy,
		})
	default:
		ctx.JSON(http.StatusBadRequest, map[string]any{
			KeyError:           ErrUnsupportedGrantType,
			KeySupportedGrants: SupportedGrants,
		})
	}
}

func (s *Server) handleUserInfo(ctx HandlerContext) {
	// /userinfo carries the subject's profile (sub, name, email,
	// custom claims). Per RFC 6749 §5.1 cache-prevention pattern
	// applied to /token, the response must never be retained by
	// intermediaries — a stale cached body would leak across
	// users if served from a different bearer.
	tokenNoStoreHeaders(ctx)
	if err := s.requireDeps(DepTokenIssuer, DepUserProvider); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	tokenString := bearerToken(ctx.Request())
	if tokenString == "" {
		// RFC 6750 §3: a 401 from a protected resource MUST carry
		// a WWW-Authenticate challenge naming the scheme + realm.
		// The "no credentials" case omits error parameters per §3.1
		// (the request didn't try to authenticate).
		setBearerChallenge(ctx, s.resolveIssuer(ctx), "", "")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrMissingToken))
		return
	}

	claims, _, err := s.validateAnyToken(ctx.Request().Context(), tokenString)
	if err != nil {
		// RFC 6750 §3.1: token-validation failures carry
		// error="invalid_token" in the challenge so the RP can
		// distinguish "I need to refresh" from "I forgot to send".
		setBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "The access token is invalid or expired")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return
	}

	// RFC 9449 §7 — when the access token carries a `cnf.jkt`
	// binding, the request MUST also carry a fresh DPoP proof
	// whose JWK thumbprint matches. Legacy bearer tokens (no
	// cnf.jkt) skip this gate. A failure here is indistinguishable
	// from "invalid bearer" on the wire (single error code) so
	// attackers can't tell DPoP-bound from unbound tokens via
	// response probing.
	if err := s.verifyDPoPBearer(ctx, claims); err != nil {
		// RFC 9449 §8 — RS-side nonce challenge: 401 + DPoP-Nonce header.
		// Distinct from the AS-side challenge (400 at /token) so a
		// resource server sees the standard 401-with-WWW-Authenticate
		// pattern it already implements for bearer failures.
		if errors.Is(err, ErrDPoPNonceRequired) {
			s.stampDPoPNonce(ctx)
			setBearerChallenge(ctx, s.resolveIssuer(ctx), ErrUseDPoPNonce, "Fresh DPoP nonce required")
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrUseDPoPNonce))
			return
		}
		s.logger.Error("dpop bearer verification failed", "error", err, "subject", claims.Subject)
		setBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "DPoP proof missing or thumbprint mismatch")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return
	}
	// RFC 8705 §3 — symmetric mTLS resource verification. When
	// the token carries cnf.x5t#S256, the inbound TLS connection's
	// client cert MUST have the matching thumbprint. Same wire-
	// shape collapse to invalid_token.
	if err := s.verifyMTLSBearer(ctx, claims); err != nil {
		s.logger.Error("mtls bearer verification failed", "error", err, "subject", claims.Subject)
		setBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "Client certificate missing or thumbprint mismatch")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return
	}

	// OIDC §8 pairwise: the inbound claims.Subject may be the per-
	// sector opaque identifier rather than a local UserProvider key.
	// Resolve to the local sub before the GetByID — but keep
	// claims.Subject untouched for the projected response so the RP
	// sees the same sub it was given at issuance.
	lookupSub, perr := s.resolveLocalSubject(ctx.Request().Context(), claims.Subject)
	if perr != nil {
		s.logger.Error("pairwise resolve failed at /userinfo", "error", perr, "subject", claims.Subject)
		setBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "Subject mapping unavailable")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return
	}
	user, err := s.userProvider.GetByID(ctx.Request().Context(), lookupSub)
	if err != nil {
		ctx.JSON(http.StatusNotFound, errorBody(ErrUserNotFound))
		return
	}

	// OIDC profile: when the token carries "openid" scope, project the
	// user into the OIDC-standard claim shape (sub always, then claims
	// gated by scope per OIDC Core §5.4). The full User struct (with
	// non-standard fields like provider, created_at) is returned only
	// for non-OIDC tokens — pre-OIDC integrations keep working unchanged.
	if slices.Contains(claims.Scopes, ScopeOpenID) {
		body := projectUserInfoForOIDC(user, claims.Scopes)
		// OIDC §8 pairwise: the projected `sub` is u.ID (local), but
		// the RP knows the user by the pairwise sub from its token.
		// Restore the inbound sub so the response matches the RP's
		// view (RPs MUST verify `sub` here matches the id_token sub
		// per §5.3.2; mismatch would fail that check).
		if claims.Subject != "" && claims.Subject != user.ID {
			body["sub"] = claims.Subject
		}
		// RFC 9068 §2.2 claims passthrough on the OIDC profile: when
		// the access token carries auth_time / acr / amr (because it
		// was minted via /auth/login with a fresh user-auth event),
		// expose them on /userinfo so downstream policy can branch
		// on factor strength without re-validating the access token.
		// Empty values are omitted so legacy tokens still produce
		// the minimal {sub} response.
		if !claims.AuthTime.IsZero() {
			body["auth_time"] = claims.AuthTime.Unix()
		}
		if claims.ACR != "" {
			body["acr"] = claims.ACR
		}
		if len(claims.AMR) > 0 {
			body["amr"] = claims.AMR
		}
		// OIDC Core §5.3.2 — when the requesting client has
		// `userinfo_signed_response_alg` set AND the wired
		// oidc.IDTokenIssuer implements oidc.UserinfoSigner, return a
		// signed JWT (Content-Type: application/jwt) instead
		// of plain JSON. Today only EdDSA is supported.
		if s.maybeSignUserInfo(ctx, claims.ClientID, body) {
			return
		}
		ctx.JSON(http.StatusOK, body)
		return
	}

	ctx.JSON(http.StatusOK, user)
}

// projectUserInfoForOIDC returns the OIDC-standard claim set for a user
// gated by the token's scopes. OIDC Core §5.4 mapping:
//
//	openid  → sub (always)
//	email   → email, email_verified
//	profile → name, given_name, family_name, picture, preferred_username
//	address → address (object)
//	phone   → phone_number, phone_number_verified
//
// Non-standard fields on the User (provider, external_id, created_at,
// updated_at) are omitted — OIDC RPs don't expect them and including
// them would make the response shape ambiguous with the legacy
// non-OIDC response.
//
// Per-claim values come from User's first-class fields (Email, Name)
// or from Attributes when the field name matches the claim name.
// Operators control which claims are exposed via what they populate
// in the User and Attributes — there's no per-server claim allowlist
// to maintain.
func projectUserInfoForOIDC(u *User, scopes []string) map[string]any {
	out := map[string]any{"sub": u.ID}
	hasScope := func(name string) bool {
		return slices.Contains(scopes, name)
	}
	// Attributes win when both an attribute AND a first-class field
	// carry the same claim — the authenticator is the live source of
	// truth (User.Email + User.Name are caches that aren't always
	// repopulated by the login upsert path).
	emailFrom := func() string {
		if v, ok := u.Attributes["email"]; ok && v != "" {
			return v
		}
		return u.Email
	}
	nameFrom := func() string {
		if v, ok := u.Attributes["name"]; ok && v != "" {
			return v
		}
		return u.Name
	}
	if hasScope("email") {
		if v := emailFrom(); v != "" {
			out["email"] = v
		}
		if v, ok := u.Attributes["email_verified"]; ok {
			out["email_verified"] = v == "true"
		}
	}
	if hasScope("profile") {
		if v := nameFrom(); v != "" {
			out["name"] = v
		}
		for _, k := range []string{"given_name", "family_name", "picture", "preferred_username", "nickname", "locale", "zoneinfo"} {
			if v, ok := u.Attributes[k]; ok && v != "" {
				out[k] = v
			}
		}
	}
	if hasScope("address") {
		if v, ok := u.Attributes["address"]; ok && v != "" {
			out["address"] = v
		}
	}
	if hasScope("phone") {
		if v, ok := u.Attributes["phone_number"]; ok && v != "" {
			out["phone_number"] = v
		}
		if v, ok := u.Attributes["phone_number_verified"]; ok {
			out["phone_number_verified"] = v == "true"
		}
	}
	return out
}

func (s *Server) handleLogout(ctx HandlerContext) {
	var req struct {
		SessionID string `json:"session_id"`
	}
	// Body is optional — bearer-only logouts are allowed.
	_ = ctx.Bind(&req)

	bearer := bearerToken(ctx.Request())

	if req.SessionID == "" && bearer == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrSessionIDOrBearerRequired))
		return
	}

	// Capture (subject, client) for back-channel logout BEFORE
	// revoking the bearer — the post-revoke Validate call would
	// fail. We do this in a best-effort way: a malformed or
	// already-expired bearer just yields no back-channel
	// notification, never an error.
	var bcSubject, bcClientID, bcSID string
	if bearer != "" {
		if claims, _, err := s.validateAnyToken(ctx.Request().Context(), bearer); err == nil && claims != nil {
			bcSubject = claims.Subject
			bcSID = claims.SID
			if claims.ClientID != "" {
				bcClientID = claims.ClientID
			} else if len(claims.Audience) > 0 {
				bcClientID = claims.Audience[0]
			}
		}
	}

	revoked := []string{}
	if req.SessionID != "" && s.sessionMgr != nil {
		if err := s.sessionMgr.Destroy(ctx.Request().Context(), req.SessionID); err != nil {
			s.logger.Error("logout: destroy session failed", "error", err)
		} else {
			revoked = append(revoked, RevokedSession)
		}
	}
	if bearer != "" && len(s.tokenIssuers) > 0 {
		issuersHit, failedIssuers := s.revokeAcrossIssuers(ctx.Request().Context(), bearer)
		for range issuersHit {
			revoked = append(revoked, RevokedToken)
		}
		s.auditPartialRevokeFailure(ctx, issuersHit, failedIssuers)
	}

	// OIDC Back-Channel Logout 1.0: notify the client in the
	// bearer's aud / client_id that this user just logged out so
	// the RP can tear down its local session. No-op when the
	// subsystem isn't wired or the client has no
	// backchannel_logout_uri declared.
	if bcSubject != "" && bcClientID != "" && s.clientStore != nil {
		if c, err := s.clientStore.Get(ctx.Request().Context(), bcClientID); err == nil && c != nil {
			// Multi-RP fan-out when the security.SubjectClientIndex is wired;
			// degrades to single-RP notification of the bearer's
			// client when it isn't.
			s.fanOutBackchannelLogout(ctx, c, bcSubject, bcSID)
		}
	}

	s.recordLogout(ctx, req.SessionID, revoked)

	ctx.JSON(http.StatusOK, map[string]any{
		KeyStatus:  StatusLoggedOut,
		KeyRevoked: revoked,
	})
}

func (s *Server) handleSendCode(ctx HandlerContext) {
	var req struct {
		Provider string `json:"provider"`
		Target   string `json:"target"`
	}
	if err := ctx.Bind(&req); err != nil || req.Provider == "" || req.Target == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrProviderAndTargetRequired))
		return
	}

	auth, err := s.getAuthenticator(req.Provider)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrUnsupportedProvider))
		return
	}

	sender, ok := auth.(spi.CodeSender)
	if !ok {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrProviderDoesNotSendCodes))
		return
	}

	if err := sender.SendCode(ctx.Request().Context(), req.Target); err != nil {
		s.logger.Error("send code failed", "provider", req.Provider, "error", err)
		s.recordCodeSent(ctx, req.Provider, req.Target, false)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrSendFailed))
		return
	}

	s.recordCodeSent(ctx, req.Provider, req.Target, true)

	ctx.JSON(http.StatusOK, map[string]string{KeyStatus: StatusSent})
}

func (s *Server) handleGetClient(ctx HandlerContext) {
	if s.clientStore == nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrClientStoreNotConfigured))
		return
	}

	clientID := ctx.Param("id")
	if clientID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrMissingClientID))
		return
	}

	client, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, errorBody(ErrClientNotFound))
		return
	}

	ctx.JSON(http.StatusOK, client)
}
