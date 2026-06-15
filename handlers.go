package sso


import (
	"errors"
	"net/http"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/oidc"
)
// tracer is shared by audit-event helpers for parsing inbound W3C
// traceparent headers into TraceID/SpanID for stamping on Event
// records. Stateless — safe at package scope.
var tracer = audit.NewTracer()

// active state + standard metadata claims for a presented access or
// refresh token. Inactive tokens return {active: false} only, with no
// extra metadata — §2.2 mandates this to limit oracle leakage.
//
// Auth: the introspecting client authenticates with client_id +
// client_secret (Basic auth or form body). Per §2.1 any registered
// active client may introspect — production deployments that want
// stronger isolation should layer an authorization middleware that
// checks a custom "introspect" scope or role on the client.
// handleIntrospect delegates to oauth.HandleIntrospect — see that
// file for the RFC 7662 + 7521/7523 client-auth precedence + §2.2
// {active:false} oracle-leak hardening.
func (s *Server) handleIntrospect(ctx HandlerContext) { oauth.HandleIntrospect(s, ctx) }

// authenticateClientCreds verifies the client_id + secret pair via
// the wired ClientStore + tenant gate. Used by handleRevoke + future
// handle_par migration. Returns nil on success.
func (s *Server) authenticateClientCreds(ctx HandlerContext, id, secret string) error {
	if id == "" || secret == "" {
		return errors.New("missing client credentials")
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), id)
	if err != nil {
		return err
	}
	if !client.Active {
		return errors.New("inactive client")
	}
	if !clientTenantOK(ctx, client) {
		return errors.New("tenant mismatch")
	}
	return s.clientStore.ValidateSecret(ctx.Request().Context(), id, secret)
}

// basicClientCreds delegates to oauth.BasicClientCreds — see that
// function for the RFC 6749 §2.3.1 precedence rationale.
func basicClientCreds(r *http.Request) (id, secret string, ok bool) {
	return oauth.BasicClientCreds(r)
}

// handlePAR implements RFC 9126 Pushed Authorization Requests.
// Confidential clients POST their authorization request parameters
// here BEFORE redirecting the user agent, getting back an opaque
// request_uri they then pass to /auth/login. This pre-registration
// pattern:
//
//   - Authenticates the client BEFORE the user-agent redirect (the
//     traditional authorization flow has the AS see the client
//     only AFTER the redirect, when there's nothing to do about a
//     bad request beyond rendering an error).
//   - Removes long auth-request URLs (PKCE + scopes + state +
//     resource + nonce add up fast) that browsers, log files, and
//     proxies all handle poorly.
//   - Prevents request-tampering: nothing in the redirect URL
//     beyond client_id + request_uri can be modified without
//     invalidating the lookup.
//
// Auth: HTTP Basic OR client_id+client_secret form body per
// RFC 6749 §2.3.1 (Basic wins when both present — same precedence
// rule as /token).
//
// Spec sentinel mapping:
//   - missing client credentials              → 401 invalid_client
//   - PAR store not wired                     → 501 par_not_configured
//   - invalid redirect_uri allowlist          → 400 invalid_redirect_uri
//   - resource not in allowlist (RFC 8707)    → 400 invalid_target
//
// Response per RFC 9126 §2.2:
//
//	{
//	  "request_uri": "urn:ietf:params:oauth:request_uri:<token>",
//	  "expires_in":  90
//	}
//
// handlePAR delegates to oauth.HandlePAR — see that file for the
// RFC 9126 pre-redirect client authentication + validation flow.
func (s *Server) handlePAR(ctx HandlerContext) { oauth.HandlePAR(s, ctx) }

// handleRevoke delegates to oauth.HandleRevoke — see that file for
// the §2.2 always-200 oracle-leak hardening + hint-driven
// best-effort dual-tier revocation.
func (s *Server) handleRevoke(ctx HandlerContext) { oauth.HandleRevoke(s, ctx) }

// handleRevokeAll implements the "logout everywhere" endpoint. The
// user presents a bearer token; the server reads sub + aud from its
// claims, then kills every refresh token bound to that
// (subject, client) pair via the optional oauth.RefreshTokenSubjectIndex
// extension. The presented access token is also revoked via the
// normal per-issuer path so it stops working immediately.
//
// Useful for a "sign out of all devices" button — one round trip
// instead of per-device per-token revocation.
//
// Requires the oauth.RefreshTokenStore to implement
// oauth.RefreshTokenSubjectIndex; without it, the response is 501.
//
// Authentication: bearer token only (not client credentials). The
// user is the actor — they're authorizing the revocation of their
// own tokens.
// handleRevokeAll delegates to oauth.HandleRevokeAll — see that
// file for the bearer-token-authenticated "logout everywhere"
// semantics via the RefreshTokenSubjectIndex extension.
func (s *Server) handleRevokeAll(ctx HandlerContext) { oauth.HandleRevokeAll(s, ctx) }

// handleEndSession implements OpenID Connect RP-Initiated Logout 1.0.
// Unlike POST /logout (a session-scoped bearer-authenticated kill
// switch), this is a GET endpoint a relying party can redirect the
// user agent to so the SSO server logs the user out and then sends
// them back to the RP's post-logout page.
//
// Query parameters (per the spec §2):
//
//   - id_token_hint            REQUIRED to identify the user — a
//     previously-issued id_token. The server
//     validates the signature and uses the
//     token's aud claim to look up the client.
//   - post_logout_redirect_uri Optional; MUST be in the client's
//     PostLogoutRedirectURIs allowlist.
//   - state                    Optional; echoed back on the redirect.
//   - client_id                Optional fallback when id_token_hint
//     is absent — used only for
//     redirect-uri allowlist lookup, NOT
//     for session termination.
//
// Behavior:
//
//   - Always best-effort revokes the access token derived from the
//     id_token_hint (so a stolen id_token_hint can't be used to
//     just bounce the user without invalidating their session).
//   - When post_logout_redirect_uri is in the allowlist, returns
//     302 with Location pointing at the redirect_uri (+ state when
//     supplied).
//   - When the redirect_uri is missing or rejected, returns 204 —
//     the session is dead, but we don't open a redirect-vector for
//     callers without a registered URL.
//
// Security:
//
//   - id_token_hint signature MUST verify against the server's
//     wired token issuers (we treat ID tokens and access tokens
//     as signed by the same key pair).
//   - post_logout_redirect_uri MUST exact-match (no path tolerance,
//     no scheme-only match) — phishing defense per §3.
//
// handleEndSession delegates to oidc.HandleEndSession — see that
// file for the OIDC RP-Initiated Logout 1.0 flow, including FCL
// iframe gather/render + BCL fan-out + phishing-safe redirect
// allowlist semantics.
func (s *Server) handleEndSession(ctx HandlerContext) { oidc.HandleEndSession(s, ctx) }

// handleRegister delegates to oauth.HandleRegister (RFC 7591 DCR).
func (s *Server) handleRegister(ctx HandlerContext) { oauth.HandleRegister(s, ctx) }

// handleRegistrationGet delegates to oauth.HandleRegistrationGet (RFC 7592 §2.1).
func (s *Server) handleRegistrationGet(ctx HandlerContext) { oauth.HandleRegistrationGet(s, ctx) }

// handleRegistrationPut delegates to oauth.HandleRegistrationPut (RFC 7592 §2.2).
func (s *Server) handleRegistrationPut(ctx HandlerContext) { oauth.HandleRegistrationPut(s, ctx) }

// handleRegistrationDelete delegates to oauth.HandleRegistrationDelete (RFC 7592 §2.3).
func (s *Server) handleRegistrationDelete(ctx HandlerContext) { oauth.HandleRegistrationDelete(s, ctx) }

// mfaResumeState is the JSON-encoded blob persisted alongside the
// spi.MFAChallenge. Opaque to spi.MFAChallengeStore backends; the SSO server
// marshals + unmarshals so the post-step-up handler can replay the
// same finishLogin flow the no-MFA path takes.
//
// CredentialHealth is carried out-of-band from Result on purpose:
// AuthResult.CredentialHealth is json:"-" (kept off all generic
// serialization, including this blob), so the embedded Result would drop
// the signal on the round trip. This is the ONE intentional persistence
// generateDeviceCodeBytes delegates to oauth.GenerateDeviceCode.
func normalizeUserCode(s string) string { return oauth.NormalizeUserCode(s) }

// splitScope delegates to oauth.SplitScope.
func splitScope(s string) []string { return oauth.SplitScope(s) }

// Query parameter accepted by the /permissions/me, /menus/me, /roles/me
// endpoints to scope the lookup to a particular APP.
const QueryClientID = "client_id"

// authenticatedSubject resolves the bearer token to a user ID + client ID.
// client_id resolution: explicit query param > token audience > "".
func (s *Server) authenticatedSubject(ctx HandlerContext) (userID, clientID string, ok bool) {
	tokenString := bearerToken(ctx.Request())
	if tokenString == "" {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrMissingToken))
		return "", "", false
	}
	claims, _, err := s.validateAnyToken(ctx.Request().Context(), tokenString)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return "", "", false
	}
	clientID = ctx.Query(QueryClientID)
	if clientID == "" && len(claims.Audience) > 0 {
		clientID = claims.Audience[0]
	}
	return claims.Subject, clientID, true
}

// Netpolicy endpoint handlers moved to netpolicy/handlers.go. Methods
// below stay as thin delegators so the existing route binding via
// method values keeps working.

func (s *Server) handleListNetPolicies(ctx HandlerContext)    { netpolicy.HandleList(s, ctx) }
func (s *Server) handleGetNetPolicy(ctx HandlerContext)       { netpolicy.HandleGet(s, ctx) }
func (s *Server) handleApplyNetPolicy(ctx HandlerContext)     { netpolicy.HandleApply(s, ctx) }
func (s *Server) handleDeleteNetPolicy(ctx HandlerContext)    { netpolicy.HandleDelete(s, ctx) }
func (s *Server) handleClassifyNetPolicy(ctx HandlerContext)  { netpolicy.HandleClassify(s, ctx) }
func (s *Server) handleResolveMeNetPolicy(ctx HandlerContext) { netpolicy.HandleResolveMe(s, ctx) }

// ClassifyRequest is exposed for embedders that want to classify a request
// in their own middleware. Returns nil when no classifier is wired or no
// policy matches.
func (s *Server) ClassifyRequest(r *http.Request) *netpolicy.Policy {
	if s.netClassifier == nil || r == nil {
		return nil
	}
	return s.netClassifier.Classify(r.RemoteAddr, r.Host)
}

// audit.EventFromRequest pre-fills an Event with caller-side
// metadata (IP, user-agent, request ID, trace context, plus geo
// when the geo middleware is wired). Handlers fill the rest.
// TracingMiddleware populates the headers this function reads;
// without that middleware installed, RequestID/TraceID/SpanID
// stay empty. GeoMiddleware similarly populates the geo metadata
// keys; without it, no geo.* metadata appears.

// audit.EnrichTenant lifts tenant routing results onto
// Event.Metadata under the tenant.* prefix. No-op when the
// tenant middleware didn't run (no store wired, unknown host,
// suspended tenant). Tenant goes onto every audit event so
// SIEM filters like "show me failed logins for tenant X" become
// a single Metadata key check.

// audit.EnrichGeo lifts geo lookup results from HandlerContext onto
// Event.Metadata under the geo.* prefix. No-op when the geo
// middleware didn't run (no Lookup, ErrNotFound, nil Provider).
// Only non-empty fields are projected so audit consumers can do a
// presence check rather than a value check.

// audit.SetMeta writes key=val into e.Metadata, lazily allocating the map
// and skipping empty values. Use this instead of `e.Metadata = map[...]{...}`
// — direct assignment would clobber whatever audit.EventFromRequest
// already populated (geo enrichment, future fields).

// ctxKeyLoginStart is the HandlerContext.Set/Get key holding the
// time.Time stamped at /auth/login entry. Used by recordLogin* to
// observe the per-provider login duration histogram.
const ctxKeyLoginStart = "_sso_login_start"

// observeLoginDuration computes elapsed since the stamp + observes
// the histogram. Safe no-op when metrics aren't wired or the stamp
// is absent (defensive — tests may bypass handleLogin).
