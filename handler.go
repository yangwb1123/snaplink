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
	"github.com/snaplink/sso/region"
	"github.com/snaplink/sso/tenant"
)

// errorBody delegates to core/error_body.go. Keep the lowercase name so the
// 100+ call sites stay one-line.
func errorBody(code string) map[string]string { return core.ErrorBody(code) }

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
	ConsentChallengeID   string            `json:"consent_challenge_id"`  // server-issued challenge from a prior consent_required response
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
			s.logErrorCtx(ctx, "jar fetch failed", "error", err, "client", req.ClientID, "uri", req.RequestURI)
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
	// on the wire or into any token — AuthResult.CredentialHealth is
	// json:"-", so generic serialization (tokens, the MFA challenge store)
	// strips it; the MFA step-up path re-threads it explicitly via
	// mfaResumeState.CredentialHealth so this audit still fires after
	// resume. It lands only in the audit log. nil = no signal (healthy
	// credential or no checker wired).
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

	// Scope authorization (RFC 6749 §3.3) — the access-control gate on
	// what the issued token may carry. Run here, AFTER authentication and
	// the tenant/residency gates, so it can never be a pre-auth probe and
	// covers BOTH the authorization_code branch (the granted set is baked
	// into the stored code) and the direct-mint branch below. Mirrors the
	// tenant_mismatch / residency gates: record the failure + emit the
	// authz error body carrying the RFC 9207 iss. req.Scope is replaced
	// with the GRANTED set (validated, or defaulted to the client's
	// AllowedScopes when the request named no scope) so every downstream
	// consumer — auth code, direct mint, refresh, id_token gate — sees
	// the authorized scope. Empty allowlist = unrestricted = req.Scope
	// passes through unchanged (byte-identical for clients without one).
	granted, scopeErr := oauth.GrantedScopes(req.Scope, client)
	if scopeErr != nil {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidScope)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrInvalidScope))
		return
	}
	req.Scope = granted

	// Consent gate (opt-in via WithConsentStore, nil = no-op).
	// Runs AFTER scope authorization so req.Scope is the granted set that
	// will actually appear in the issued token — the grant we check and
	// record is authoritative for exactly those scopes.
	if s.consentStore != nil {
		if s.handleConsentGate(ctx, result.UserID, client, req.Scope, req.Prompt, req.ConsentChallengeID) {
			return
		}
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
		AMR:                  amrForResult(result),
		ACR:                  result.AchievedACR,
		AuthorizationDetails: oauth.CloneRawJSON(req.AuthorizationDetails),
		SID:                  session.ID,
		TTL:                  client.AccessTokenTTL,
		RequestedClaims:      oauth.CloneRawJSON(req.Claims),
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
	// Native SSO 1.0: when the client was granted the device_sso scope and a
	// device-secret store is wired, mint a device_secret BEFORE the id_token so
	// its ds_hash can ride the id_token. Fail-open: issuance failure logs and
	// omits the secret (the access_token is already minted).
	var deviceSecretValue string
	if slices.Contains(req.Scope, ScopeDeviceSSO) && s.deviceSecretStore != nil {
		if ds, dsErr := s.issueDeviceSecret(ctx.Request().Context(), result.UserID, session.ID, client.ID); dsErr != nil {
			s.logger.Error("device secret issue failed", "error", dsErr, "client", client.ID, "user", result.UserID)
		} else {
			deviceSecretValue = ds
		}
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
			// OIDC Core §5.5 — the id_token carries the resolved user
			// attribute set. The claims-parameter id_token.acr request is
			// enforced upstream (folded into ACR enforcement after credential
			// validation), so it is not re-projected here; requested claims
			// that the AS cannot source from Attributes are a no-op (we can't
			// invent values).
			idToken, err := idIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
				Subject:      issuedSub,
				Audience:     client.ID,
				Nonce:        req.Nonce,
				AuthTime:     time.Now(),
				AMR:          amrForResult(result),
				ACR:          result.AchievedACR,
				Claims:       result.Attributes,
				SID:          session.ID,
				AccessToken:  token.AccessToken,
				DeviceSecret: deviceSecretValue,
			})
			if err != nil {
				s.logger.Error("id token issue failed", "error", err, "client", client.ID, "user", result.UserID)
			} else if enc, ok := s.maybeEncryptIDToken(ctx.Request().Context(), client, idToken); ok {
				resp[KeyIDToken] = enc
				s.recordIDTokenIssued(ctx, client.ID, result.UserID)
			}
		}
	}
	if deviceSecretValue != "" {
		resp[KeyDeviceSecret] = deviceSecretValue
	}
	if result.CountryCode != "" {
		resp[KeyCountryCode] = result.CountryCode
	}
	if result.RecommendedLanguage != "" {
		resp[KeyRecommendedLang] = result.RecommendedLanguage
	}
	// serving_region surfaces WHICH regional deployment served this login —
	// a UX/governance hint for the SPA, not a security signal. Only present
	// when the region middleware resolved a non-empty region (no resolver
	// wired → absent → response shape byte-identical to a pre-region build).
	if servingRegion, ok := region.FromHandlerContext(ctx); ok && servingRegion != "" {
		resp[KeyServingRegion] = string(servingRegion)
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
		AuthTime:             time.Now(),
		AuthMethods:          result.AuthMethods,
		ACR:                  result.AchievedACR,
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
		// Miss is surfaced via the auth == nil check below, so the lookup
		// error itself is not needed here.
		auth, _ = s.getAuthenticator(provider)
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
		if err := s.userProvider.CreateOrUpdate(ctx.Request().Context(), user); err != nil {
			s.logger.Error("failed to upsert user", "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
			return
		}
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
			s.jtiReplayFailClosed,
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
			// RFC 6749 §5.2: all client-authentication failures return
			// invalid_client. Collapsing wrong-secret into the same code as
			// unknown-client (above) is also oracle-safe — a distinct
			// invalid_client_secret would let an attacker enumerate valid
			// client_ids by the error code alone.
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
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
			s.jtiReplayFailClosed,
			s.dpopNonceProvider,
			s.resolvedDPoPProofMaxAge(),
			s.resolvedDPoPProofClockSkew(),
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
		// auth_time reflects the real /auth/login moment captured on the
		// AuthCode, not this redemption, so an RP's max_age / freshness
		// check isn't fooled by a delayed code exchange (OIDC Core §2). A
		// zero value (older code, or a store that doesn't persist it) falls
		// back to now.
		authTime := info.AuthTime
		if authTime.IsZero() {
			authTime = time.Now()
		}
		token, err := ti.Issue(ctx.Request().Context(), &Subject{
			ID: issuedSub, Provider: info.Provider, Claims: info.Attributes,
			Resources:            resources,
			ClientID:             client.ID,
			AuthTime:             authTime,
			AMR:                  amrOrProvider(info.AuthMethods, info.Provider),
			ACR:                  info.ACR,
			AuthorizationDetails: oauth.CloneRawJSON(info.AuthorizationDetails),
			SID:                  info.SID,
			TTL:                  client.AccessTokenTTL,
			ConfirmationJKT:      dpopJKT,
			ConfirmationX5TS256:  mtlsX5T,
		}, scopes)
		if err != nil {
			s.logErrorCtx(ctx, "token issuance failed", "strategy", strategy, "error", err)
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
		// Native SSO 1.0: device_secret on the authorization_code grant (the
		// primary native-app flow). Minted before the id_token so ds_hash rides
		// it. device_sso is captured in info.Scopes at authorization time.
		var deviceSecretValue string
		if slices.Contains(info.Scopes, ScopeDeviceSSO) && s.deviceSecretStore != nil {
			if ds, dsErr := s.issueDeviceSecret(ctx.Request().Context(), info.UserID, info.SID, client.ID); dsErr != nil {
				s.logger.Error("device secret issue failed", "error", dsErr, "client", client.ID, "user", info.UserID)
			} else {
				deviceSecretValue = ds
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
					Subject:      issuedSub,
					Audience:     client.ID,
					Nonce:        info.Nonce,
					AuthTime:     authTime,
					AMR:          amrOrProvider(info.AuthMethods, info.Provider),
					ACR:          info.ACR,
					Claims:       info.Attributes,
					AccessToken:  token.AccessToken,
					DeviceSecret: deviceSecretValue,
				})
				if err != nil {
					s.logger.Error("id token issue failed", "error", err, "client", client.ID, "user", info.UserID)
				} else if enc, ok := s.maybeEncryptIDToken(ctx.Request().Context(), client, idToken); ok {
					resp[KeyIDToken] = enc
					s.recordIDTokenIssued(ctx, client.ID, info.UserID)
				}
			}
		}
		if deviceSecretValue != "" {
			resp[KeyDeviceSecret] = deviceSecretValue
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
			// Refresh double-submit grace: if THIS token was rotated within the
			// grace window, replay the SAME successor it already produced —
			// idempotent, so a legitimate concurrent double-submit doesn't trip
			// the family-reuse kill below (a logout storm). A genuine post-window
			// replay finds no entry and falls through (BCP §4.13 unweakened).
			if s.refreshGrace != nil {
				if cached, ok := s.refreshGrace.lookup(req.RefreshToken, time.Now()); ok {
					ctx.JSON(http.StatusOK, cached)
					return
				}
			}
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
						s.logErrorCtx(ctx, "family revocation on reuse failed",
							"error", derr, "family", info.FamilyID)
					} else {
						killed = n
						s.logErrorCtx(ctx, "refresh token reuse detected — family revoked",
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
		// Per-family rotation-VELOCITY cap (OPTIONAL hardening, opt-in via a
		// store implementing oauth.RefreshTokenRotationLimiter). Runs AFTER
		// the single-use Consume above (so it counts a genuine rotation) and
		// BEFORE any token is minted. An attacker who steals a refresh token
		// and rotates once — while the victim keeps rotating the original
		// chain — drives the family's rotation rate above any single client's
		// cadence; this turns that into a kill signal even though no leaf was
		// ever double-presented (which is all the reuse tracker can see).
		//
		// On windowExceeded the family is compromised: kill it via the SAME
		// DeleteFamily path family-reuse uses, then reject with the SAME
		// invalid_grant wire shape (no distinct code, no Retry-After, no
		// rate/velocity/family hint — the detail lives only in the audit
		// event + metric). FAIL-OPEN on a limiter store error: log + proceed
		// (the cap is a defense layer, not a correctness gate — the opposite
		// of the family-reuse fail-closed above). info.FamilyID == "" (family
		// tracking opted out) makes RecordRotation a no-op.
		if limiter, ok := s.refreshTokenStore.(oauth.RefreshTokenRotationLimiter); ok && info.FamilyID != "" {
			count, exceeded, lerr := limiter.RecordRotation(ctx.Request().Context(), info.FamilyID)
			if lerr != nil {
				// Availability class (§2): a store error must not block a
				// legitimate refresh, and must NOT kill the family.
				s.logErrorCtx(ctx, "refresh rotation velocity check failed — proceeding (fail-open)",
					"error", lerr, "family", info.FamilyID, "client", client.ID)
			} else if exceeded {
				killed := 0
				if tracker, ok := s.refreshTokenStore.(oauth.RefreshTokenFamilyTracker); ok {
					n, derr := tracker.DeleteFamily(ctx.Request().Context(), info.FamilyID)
					if derr != nil {
						s.logErrorCtx(ctx, "family revocation on rotation-velocity breach failed",
							"error", derr, "family", info.FamilyID)
					} else {
						killed = n
						s.logErrorCtx(ctx, "refresh rotation velocity exceeded — family revoked",
							"family", info.FamilyID, "count", count, "killed", killed,
							"client", client.ID)
					}
				}
				if s.metrics != nil {
					s.metrics.RefreshRotationVelocityExceededTotal.Inc()
				}
				s.recordRefreshRotationVelocity(ctx, client.ID, info.FamilyID, count, killed)
				// Same wire shape as a reuse / bad refresh — oracle-leak
				// collapse (§2).
				ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
				return
			}
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
			s.logErrorCtx(ctx, "token issuance failed", "strategy", strategy, "error", err)
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
			s.logErrorCtx(ctx, "refresh token rotation failed", "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
			return
		}
		s.recordTokenIssued(ctx, client.ID, strategy, info.UserID)
		s.recordRefreshTokenIssued(ctx, client.ID, info.UserID, true)
		s.recordSubjectClientAccess(ctx.Request().Context(), info.UserID, client.ID)
		resp := map[string]any{
			KeyAccessToken:   token.AccessToken,
			KeyTokenType:     token.TokenType,
			KeyRefreshToken:  newRefresh,
			KeyExpiresIn:     token.ExpiresIn,
			KeyScope:         token.Scope,
			KeyTokenStrategy: strategy,
		}
		// Refresh double-submit grace: cache this successor keyed by the
		// just-consumed token so a benign concurrent re-presentation of the
		// SAME token replays it instead of tripping family-reuse (refresh_grace.go).
		if s.refreshGrace != nil {
			s.refreshGrace.remember(req.RefreshToken, resp, time.Now())
		}
		ctx.JSON(http.StatusOK, resp)
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
		// Scope authorization (RFC 6749 §3.3). The client is already
		// authenticated above (HTTP Basic > body creds), so this gate is
		// not a pre-auth probe. Reject an out-of-allowlist scope with a
		// 400 invalid_scope (/token shape, not the authz body); default
		// an empty request to the client's AllowedScopes so the token
		// carries its entitled scope. Empty allowlist = unrestricted
		// (byte-identical to the old pass-through).
		grantCCScopes, ccScopeErr := oauth.GrantedScopes(scopes, client)
		if ccScopeErr != nil {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidScope))
			return
		}
		// client_credentials: subject IS the client, so ClientID =
		// Sub. No end-user auth event, hence no AuthTime/AMR.
		token, err := ti.Issue(ctx.Request().Context(), &Subject{
			ID: client.ID, Resources: req.Resource, ClientID: client.ID,
			TTL:                 client.AccessTokenTTL,
			ConfirmationJKT:     dpopJKT,
			ConfirmationX5TS256: mtlsX5T,
		}, grantCCScopes)
		if err != nil {
			s.logErrorCtx(ctx, "token issuance failed", "strategy", strategy, "error", err)
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
		s.setResourceBearerChallenge(ctx, s.resolveIssuer(ctx), "", "")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrMissingToken))
		return
	}

	claims, _, err := s.validateAnyToken(ctx.Request().Context(), tokenString)
	if err != nil {
		// RFC 6750 §3.1: token-validation failures carry
		// error="invalid_token" in the challenge so the RP can
		// distinguish "I need to refresh" from "I forgot to send".
		s.setResourceBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "The access token is invalid or expired")
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
			s.setResourceBearerChallenge(ctx, s.resolveIssuer(ctx), ErrUseDPoPNonce, "Fresh DPoP nonce required")
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrUseDPoPNonce))
			return
		}
		s.logErrorCtx(ctx, "dpop bearer verification failed", "error", err, "subject", claims.Subject)
		s.setResourceBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "DPoP proof missing or thumbprint mismatch")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return
	}
	// RFC 8705 §3 — symmetric mTLS resource verification. When
	// the token carries cnf.x5t#S256, the inbound TLS connection's
	// client cert MUST have the matching thumbprint. Same wire-
	// shape collapse to invalid_token.
	if err := s.verifyMTLSBearer(ctx, claims); err != nil {
		s.logErrorCtx(ctx, "mtls bearer verification failed", "error", err, "subject", claims.Subject)
		s.setResourceBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "Client certificate missing or thumbprint mismatch")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return
	}

	// Data-residency READ-gate (the access-side counterpart to the login
	// write-gate). The bearer is now fully validated AND any DPoP/mTLS
	// sender-constraint enforced, so this runs ONLY for a holder of a valid
	// token (no unauthenticated oracle). When the token's tenant constrains
	// its serving regions and THIS region isn't allowed, deny with a 403
	// carrying the residency wire code — NOT a 401 invalid_token: the token
	// IS valid, this is a policy denial, a distinct condition that must not
	// corrupt the invalid_token bearer path. tokenNoStoreHeaders already
	// stamped at entry, so the 403 carries no-store too. Zero-cost +
	// byte-identical when residency is disabled (residencyDeniedForAccess
	// returns before any tenant lookup).
	if code, denied := s.residencyDeniedForAccess(ctx, claims); denied {
		ctx.JSON(http.StatusForbidden, errorBody(code))
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
		s.setResourceBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "Subject mapping unavailable")
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
		body := projectUserInfoForOIDC(user, claims.Scopes, claims.RequestedClaims)
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

// handleMeshExtAuthz is the Envoy/Istio ext_authz HTTP-mode authorization
// endpoint (cluster C1 mesh data-plane). A mesh sidecar calls it per
// request: a 200 ALLOWs (and the sidecar injects the X-Auth-* response
// headers stamped here into the upstream request), any other status
// DENIES. It is essentially a /userinfo variant that returns IDENTITY
// HEADERS instead of a body — so it reuses the EXACT bearer-validation
// path /userinfo uses (validateAnyToken + the DPoP/mTLS sender-constraint
// checks), with no new validation logic. The "validate at the sidecar,
// inject identity to the upstream" mesh pattern.
//
// TRUST MODEL: every X-Auth-* header is DERIVED from the validated token;
// the endpoint NEVER trusts an inbound X-Auth-*. The upstream trusts the
// injected headers ONLY because the sidecar ran this check, so the mesh
// MUST strip client-supplied X-Auth-* at ingress (same edge-strip model
// as X-Forwarded-* / mtls.backend: header — AGENTS.md §2). The endpoint
// is mesh-internal: only the trusted sidecar should be able to reach it.
func (s *Server) handleMeshExtAuthz(ctx HandlerContext) {
	// Credential-validating endpoint: the (header-only) response must
	// never be retained by an intermediary — a cached cross-request
	// ALLOW would let a different bearer's identity be injected upstream.
	tokenNoStoreHeaders(ctx)
	if err := s.requireDeps(DepTokenIssuer); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	// Thin HTTP wrapper over the dep-free MeshAuthorize seam (mesh_authz.go).
	// The decision (bearer validation + DPoP/mTLS sender-constraint +
	// residency + identity derivation) lives in MeshAuthorize so a future
	// Phase-B go-control-plane gRPC Authorization service reuses the EXACT
	// same logic without duplicating it (and without go-control-plane in the
	// core go.mod). Build the request abstraction from the *http.Request —
	// requestURLForDPoP(r) supplies the same X-Forwarded-aware htu the inline
	// path used, the cloned Header carries the bearer + DPoP proof +
	// X-Forwarded-* + header-mode mTLS cert, and r.TLS feeds TLS-backend
	// mTLS — so MeshAuthorize reads exactly what the inline handler did. The
	// HTTP response is then rendered byte-identically by
	// writeMeshAuthzResponse.
	r := ctx.Request()
	res := s.MeshAuthorize(r.Context(), MeshAuthorizeRequest{
		Method: r.Method,
		URL:    requestURLForDPoP(r),
		Header: r.Header,
		TLS:    r.TLS,
	})
	s.writeMeshAuthzResponse(ctx, res)
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
func projectUserInfoForOIDC(u *User, scopes []string, requestedClaims json.RawMessage) map[string]any {
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
	// OIDC Core §5.5: project userinfo-section requested claims that
	// scope alone did not already include. Fail-open on parse errors.
	if len(requestedClaims) > 0 {
		if _, userinfoReq, parseErr := oauth.ParseRequestedClaims(requestedClaims); parseErr == nil {
			for claimName := range userinfoReq {
				if _, alreadySet := out[claimName]; alreadySet {
					continue
				}
				if v, ok := u.Attributes[claimName]; ok && v != "" {
					out[claimName] = v
				}
			}
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

// consentChallengeTTL is the lifetime of a server-issued consent challenge.
// The SPA must present the challenge ID within this window.
const consentChallengeTTL = 5 * time.Minute

// handleConsentGate checks whether the user has consented to the requested
// scopes for the given client. Returns true when the gate fired (caller
// MUST return immediately) or false when the request may proceed.
//
// Gate logic:
//  1. prompt=consent forces re-prompt even when a valid grant exists.
//  2. No existing grant -> consent_required (first-time flow).
//  3. Existing grant that doesn't cover all requested scopes -> consent_required.
//  4. Otherwise -> record/refresh the grant (updates granted_at) and continue.
//
// When consent_required is returned, a server-issued consentChallengeID is
// included. The SPA must present this ID back in the next /auth/login call
// (consent_challenge_id field). The gate validates and atomically consumes the
// challenge — the challenge is bound to (userID, clientID, exact scopes) and
// expires after consentChallengeTTL, so a client cannot fabricate an approval
// or reuse a challenge for a different scope set.
func (s *Server) handleConsentGate(ctx HandlerContext, userID string, client *Client, scopes []string, prompt string, consentChallengeID string) (halted bool) {
	requestCtx := ctx.Request().Context()
	clientID := client.ID

	// Per-client trust escape hatch: an operator-marked first-party client
	// bypasses the consent flow entirely (no prompt, no grant recorded). This
	// is operator policy, never DCR-settable — see Client.SkipConsent.
	if client.SkipConsent {
		return false
	}

	grant, err := s.consentStore.GetConsent(requestCtx, userID, clientID)

	promptConsent := hasPromptValue(prompt, PromptConsent)
	needsConsent := false

	switch {
	case errors.Is(err, ErrNoConsentGrant):
		// First-time authorization — user has never granted for this client.
		needsConsent = true
	case err != nil:
		// Store outage: fail-open to preserve availability (matches the
		// audit / risk-scorer / geo fail-open contract). Log and continue.
		s.logger.Error("consent store get failed; skipping gate", "user", userID, "client", clientID, "error", err)
	case promptConsent:
		// RP requested explicit re-consent (e.g. for UI branding or re-auth).
		needsConsent = true
	case !scopesSubsumed(grant.Scopes, scopes):
		// Existing grant does not cover all the requested scopes — new scopes
		// were added to the authorization request since the user last consented.
		needsConsent = true
	case client.ConsentRefreshInterval > 0 && time.Since(grant.GrantedAt) > client.ConsentRefreshInterval:
		// Periodic re-consent: the grant still covers the scopes but is older
		// than this client's refresh cadence (high-risk clients re-confirm
		// authorization on a schedule). GrantedAt is refreshed on every
		// approval, so the clock restarts each time the user re-consents.
		needsConsent = true
	}

	if needsConsent {
		// Require a server-issued challenge that was previously returned in a
		// consent_required response. A bare boolean would let any caller bypass
		// the consent screen by fabricating the approval signal.
		if consentChallengeID == "" || !s.consumeConsentChallenge(consentChallengeID, userID, clientID, scopes) {
			// A presented-but-invalid challenge is a failed approval attempt
			// (expired / fabricated / replayed / wrong scopes) — record it for
			// forensics. A first-time prompt (empty challenge) is not a denial.
			if consentChallengeID != "" {
				s.recordConsentEvent(ctx, audit.EventConsentDenied, audit.OutcomeFailure, userID, clientID, scopes)
			}
			challengeID := s.issueConsentChallenge(userID, clientID, scopes)
			resp := map[string]any{
				KeyError:              ErrConsentRequired,
				KeyConsentChallengeID: challengeID,
				KeyIss:                s.resolveIssuer(ctx),
			}
			// Presentational enrichment so the consent UI can render a meaningful
			// screen (the app's display name + per-scope descriptions) instead of
			// raw IDs. Additive — older clients ignore the extra fields.
			if client.Name != "" {
				resp[KeyClientName] = client.Name
			}
			resp[KeyScopes] = s.describeScopes(scopes)
			ctx.JSON(http.StatusOK, resp)
			return true
		}
		// Challenge validated and consumed: record the grant and continue.
		_ = s.consentStore.RecordConsent(requestCtx, ConsentGrant{
			UserID:    userID,
			ClientID:  clientID,
			Scopes:    scopes,
			GrantedAt: time.Now(),
		})
		s.recordConsentEvent(ctx, audit.EventConsentGranted, audit.OutcomeSuccess, userID, clientID, scopes)
		return false
	}

	// Grant exists and is sufficient (or store outage fell through): persist
	// an up-to-date record so the granted_at timestamp stays fresh and any
	// newly-in-scope scopes are saved. Fail-open on write errors — the
	// absence of a stored grant is not a correctness issue here since we
	// already confirmed the existing grant is sufficient.
	_ = s.consentStore.RecordConsent(requestCtx, ConsentGrant{
		UserID:    userID,
		ClientID:  clientID,
		Scopes:    scopes,
		GrantedAt: time.Now(),
	})
	return false
}

// recordConsentEvent emits a user-initiated consent-lifecycle audit event
// (granted / revoked / denied). No-op when no auditor is wired. The acting
// subject is the resource owner (userID) — distinct from the admin-plane
// EventAdminConsentRevoked which is keyed on the operator. Scopes are joined
// into a single bounded metadata value (audit metadata is unbounded by design;
// only metrics labels carry the cardinality constraint).
func (s *Server) recordConsentEvent(ctx HandlerContext, evtType audit.EventType, outcome audit.Outcome, userID, clientID string, scopes []string) {
	if s.auditor == nil {
		return
	}
	evt := &audit.Event{
		Type:    evtType,
		Outcome: outcome,
		ActorID: userID,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, KeyClientID, clientID)
	if len(scopes) > 0 {
		audit.SetMeta(evt, "scopes", strings.Join(scopes, " "))
	}
	s.auditor.Record(ctx.Request().Context(), evt)
}

// describeScopes pairs each requested scope with its operator-defined human
// description (WithScopeDescriptions) for the consent_required response. A scope
// with no registered description carries an empty one — the consent UI falls
// back to the scope name (or its own built-in label).
func (s *Server) describeScopes(scopes []string) []map[string]string {
	out := make([]map[string]string, 0, len(scopes))
	for _, sc := range scopes {
		out = append(out, map[string]string{"scope": sc, "description": s.scopeDescriptions[sc]})
	}
	return out
}

// issueConsentChallenge generates and stores a single-use consent challenge
// bound to (userID, clientID, scopes). Returns the opaque challenge ID to
// include in the consent_required response.
func (s *Server) issueConsentChallenge(userID, clientID string, scopes []string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := base64.RawURLEncoding.EncodeToString(b)

	s.consentChallengeMu.Lock()
	defer s.consentChallengeMu.Unlock()
	if s.consentChallenges == nil {
		s.consentChallenges = make(map[string]*pendingConsentChallenge)
	}
	s.consentChallenges[id] = &pendingConsentChallenge{
		UserID:    userID,
		ClientID:  clientID,
		Scopes:    slices.Clone(scopes),
		ExpiresAt: time.Now().Add(consentChallengeTTL),
	}
	return id
}

// consumeConsentChallenge validates and atomically removes the challenge with
// the given ID. Returns true only if the challenge exists, matches
// (userID, clientID, exact scopes), and has not expired.
func (s *Server) consumeConsentChallenge(id, userID, clientID string, scopes []string) bool {
	s.consentChallengeMu.Lock()
	defer s.consentChallengeMu.Unlock()
	if s.consentChallenges == nil {
		return false
	}

	// Prune expired entries on every lookup to bound memory growth.
	now := time.Now()
	for k, v := range s.consentChallenges {
		if now.After(v.ExpiresAt) {
			delete(s.consentChallenges, k)
		}
	}

	ch, ok := s.consentChallenges[id]
	if !ok || now.After(ch.ExpiresAt) {
		return false
	}
	if ch.UserID != userID || ch.ClientID != clientID || !consentScopesMatch(ch.Scopes, scopes) {
		return false
	}
	// Single-use: consume immediately.
	delete(s.consentChallenges, id)
	return true
}

// consentScopesMatch reports whether a and b contain exactly the same scopes
// regardless of order. Used to bind challenge validation to the exact scope set
// the challenge was issued for.
func consentScopesMatch(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := slices.Clone(a)
	bs := slices.Clone(b)
	slices.Sort(as)
	slices.Sort(bs)
	return slices.Equal(as, bs)
}

// hasPromptValue reports whether the space-separated OIDC prompt parameter
// contains the named value (e.g. "consent"). Case-sensitive per spec.
func hasPromptValue(prompt, val string) bool {
	for _, p := range strings.Fields(prompt) {
		if p == val {
			return true
		}
	}
	return false
}

// scopesSubsumed reports whether every scope in requested is present in
// granted. An empty requested set is trivially subsumed (nothing to check).
func scopesSubsumed(granted, requested []string) bool {
	if len(requested) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(granted))
	for _, s := range granted {
		set[s] = struct{}{}
	}
	for _, r := range requested {
		if _, ok := set[r]; !ok {
			return false
		}
	}
	return true
}
