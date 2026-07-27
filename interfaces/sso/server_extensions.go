package sso

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/internal/handler"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/cluster"
	"github.com/yangwb1123/snaplink/platform/lifecycle/webhook"
	"github.com/yangwb1123/snaplink/protocols/caep"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
)

// Generic event/webhook handlers delegate to the lifecycle package while
// retaining method values used by the existing route bindings.
func (s *Server) handleWebhookListSubscriptions(ctx HandlerContext) {
	webhook.HandleListSubscriptions(s, ctx)
}

func (s *Server) handleWebhookCreateSubscription(ctx HandlerContext) {
	webhook.HandleCreateSubscription(s, ctx)
}

func (s *Server) handleWebhookDeleteSubscription(ctx HandlerContext) {
	webhook.HandleDeleteSubscription(s, ctx)
}

func (s *Server) handleWebhookListDeadLetters(ctx HandlerContext) {
	webhook.HandleListDeadLetters(s, ctx)
}

func (s *Server) handleWebhookReplayDeadLetter(ctx HandlerContext) {
	webhook.HandleReplayDeadLetter(s, ctx)
}

// Route re-exports keep the public SSO composition surface independent of the
// shared wire-constant package.
const (
	PathAdminWebhookSubscriptions    = core.PathAdminWebhookSubscriptions
	PathAdminWebhookSubscriptionByID = core.PathAdminWebhookSubscriptionByID
	PathAdminWebhookDeadLetters      = core.PathAdminWebhookDeadLetters
	PathAdminWebhookDeadLetterReplay = core.PathAdminWebhookDeadLetterReplay
)

// mountWebhookAdminAPI registers subscription management and dead-letter
// inspection/replay only when WithWebhookEngine supplied an engine. Keeping
// the routes absent when unwired makes that admin surface byte-identical to a
// build without the optional lifecycle feature.
func (s *Server) mountWebhookAdminAPI(api Router) {
	if s.webhookEngine == nil {
		return
	}
	api.GET(PathAdminWebhookSubscriptions, s.handleWebhookListSubscriptions)
	api.POST(PathAdminWebhookSubscriptions, s.handleWebhookCreateSubscription)
	api.DELETE(PathAdminWebhookSubscriptionByID, s.handleWebhookDeleteSubscription)
	api.GET(PathAdminWebhookDeadLetters, s.handleWebhookListDeadLetters)
	api.POST(PathAdminWebhookDeadLetterReplay, s.handleWebhookReplayDeadLetter)
}

// temporarily fails.
// matching the JWT issuers' already-configurable skew.

func tokenNoStoreHeaders(ctx HandlerContext) { middleware.TokenNoStoreHeaders(ctx) }

// setBearerChallenge stamps an RFC 6750 §3 WWW-Authenticate header
// on a 401 response. Protected resources that accept Bearer tokens
// MUST include this challenge so RPs know which scheme to use and
// can branch on `error=invalid_token` to trigger a refresh vs.
// `error=insufficient_scope` (reserved for /userinfo scope gates
// added later).
//
// realm: the protection space — defaulted to "sso" when the
// issuer can't be resolved. errorCode / errorDescription: omitted
// for the "no credentials presented" case (RFC §3.1: error
// parameters are only included when the request had a token that
// failed validation). Description values are quoted-string escaped
// per RFC 7235 §2.2 so untrusted upstream values can't break out
// and inject additional auth-params.
// setResourceBearerChallenge stamps the RFC 6750 challenge and, when RFC 9728
// Protected Resource Metadata is enabled, appends the §5.1 resource_metadata
// parameter pointing at the PRM document — so a client (e.g. an MCP / AI-agent
// client) hitting a 401 on a protected resource can discover this resource's
// authorization server. Used ONLY on protected-RESOURCE endpoints (/userinfo,
// /me*), not the AS credential endpoints (those use invalid_client, not a
// bearer-resource challenge).
func (s *Server) setResourceBearerChallenge(ctx HandlerContext, realm, errorCode, errorDescription string) {
	setBearerChallenge(ctx, realm, errorCode, errorDescription)
	if s.protectedResourceMetadata == nil {
		return
	}
	h := ctx.ResponseWriter().Header()
	existing := h.Get("WWW-Authenticate")
	url := requestBaseURL(ctx.Request()) + PathProtectedResourceMetadata
	h.Set("WWW-Authenticate", existing+", resource_metadata="+security.QuoteAuthParam(url))
}

func setBearerChallenge(ctx HandlerContext, realm, errorCode, errorDescription string) {
	if realm == "" {
		realm = "sso"
	}
	parts := []string{`Bearer realm=` + security.QuoteAuthParam(realm)}
	if errorCode != "" {
		parts = append(parts, `error=`+security.QuoteAuthParam(errorCode))
	}
	if errorDescription != "" {
		parts = append(parts, `error_description=`+security.QuoteAuthParam(errorDescription))
	}
	ctx.ResponseWriter().Header().Set("WWW-Authenticate", strings.Join(parts, ", "))
}

// auditPartialRevokeFailure emits an `EventPartialRevokeFailure` event
// when at least one TokenIssuer failed to revoke a token while at
// least one succeeded — the "logout everywhere" promise has been
// partially violated and operators MUST follow up manually before the
// failed-issuer's tokens reach natural expiry.
//
// Both lists are recorded so SIEM filters can compute the success
// ratio over time and alert when failed/(revoked+failed) crosses a
// threshold. When failed is empty (full success or "no issuer owned
// this token"), this is a no-op — emitting an event in those cases
// would be noise. Safe to call with a nil Recorder; uses audit.SetMeta so
// geo + tenant middleware enrichment isn't clobbered.
func (s *Server) auditPartialRevokeFailure(ctx HandlerContext, revoked, failed []string) {
	s.auditPartialRevokeFailureCtx(ctx.Request().Context(), revoked, failed)
}

// auditPartialRevokeFailureCtx is auditPartialRevokeFailure's context.Context
// variant, for callers with no HandlerContext to hang off — namely RevokeToken
// (accessors_feature_gates.go), the admin.Deps method the break-glass impersonation
// cascade uses to deny a bearer across every issuer. Without this, an issuer
// that owns the bearer but fails to revoke it would silently leave the
// partial-revoke-failure promise unaudited for THAT ONE call site, even though
// every other revocation path (/token/revoke, /token/revoke-all, /logout, OIDC
// end_session) already surfaces it. Same no-op-when-clean contract as the
// HandlerContext variant.
func (s *Server) auditPartialRevokeFailureCtx(ctx context.Context, revoked, failed []string) {
	if s.auditor == nil || len(failed) == 0 {
		return
	}
	e := &audit.Event{
		Type:      audit.EventPartialRevokeFailure,
		Outcome:   audit.OutcomeFailure,
		Timestamp: time.Now(),
	}
	audit.SetMeta(e, "revoked", strings.Join(revoked, ","))
	audit.SetMeta(e, "failed", strings.Join(failed, ","))
	s.auditor.Record(ctx, e)
}

// maxSETBodyBytes bounds how much of an inbound SET body the receiver
// reads. A compact-JWS SET is small (header + a few claims + signature);
// 64 KiB is generous for an RSA-4096 signature + a richer subject id yet
// caps a hostile/oversized body before it allocates. The body limit
// middleware (when wired) also caps it; this is a defensive inner bound for
// the byte-stream read regardless of middleware.
const maxSETBodyBytes = 64 << 10

// handleSSFReceive is the opt-in OpenID Shared Signals (CAEP/SSF) push
// delivery RECEIVER endpoint (RFC 8935) — the inbound half of Shared
// Signals, the inverse of the CAEP transmitter. A CONFIGURED trusted
// upstream transmitter POSTs a signed Security Event Token (a compact JWS,
// Content-Type application/secevent+jwt) in the body; the receiver
// validates it FAIL-CLOSED (trusted-iss allowlist + signature against that
// transmitter's JWKS via the alg-confusion-safe security.VerifyCompactJWS +
// aud-binding + exp/iat + jti-replay) and, for a PRECISELY-mapped local
// subject on a revocation event, revokes that subject's local access.
//
// Response contract (RFC 8935):
//   - 202 Accepted on a VALID SET — including a valid SET that maps to no
//     local subject or carries only unknown events (the transmitter did its
//     job; the receiver simply had nothing to do). No body.
//   - 400 with an oracle-safe SSF error body ({err, description}) on a
//     MALFORMED / UNSIGNED / UNTRUSTED-iss / WRONG-aud / EXPIRED / REPLAYED
//     SET. The `err` is a COARSE SSF-standard code (invalid_request /
//     invalid_key); it does NOT reveal which precise gate failed.
//   - 500 only on a transient internal failure AFTER full validation (a
//     resolver/revoke-store outage) — the validated revocation intent is
//     real, so the transmitter should retry rather than the receiver
//     silently dropping it.
//
// handleSSFConfig serves the SSF transmitter configuration endpoint.
func (s *Server) handleSSFConfig(ctx HandlerContext) {
	caep.HandleSSFConfiguration(s, ctx)
}
func (s *Server) handleCreateStream(ctx HandlerContext) { caep.HandleCreateStream(s, ctx) }
func (s *Server) handleGetStream(ctx HandlerContext)    { caep.HandleGetStream(s, ctx) }
func (s *Server) handleUpdateStream(ctx HandlerContext) { caep.HandleUpdateStream(s, ctx) }
func (s *Server) handleListStreams(ctx HandlerContext)  { caep.HandleListStreams(s, ctx) }
func (s *Server) handleDeleteStream(ctx HandlerContext) { caep.HandleDeleteStream(s, ctx) }

// This is a credential-bearing endpoint (the SET is a signed bearer
// artefact), so tokenNoStoreHeaders stamps no-store on every response.
func (s *Server) handleSSFReceive(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	if s.caepReceiver == nil {
		// Defensive: the route is only mounted when the receiver is wired,
		// but guard so a future refactor can't reach a nil receiver.
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrServerMisconfigured))
		return
	}

	// Read the compact-JWS SET from the body (bounded). The SET is the body
	// per the SSF push-delivery profile; we don't require an exact
	// Content-Type match (transmitters vary), but cap the size.
	body, err := io.ReadAll(io.LimitReader(ctx.Request().Body, maxSETBodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxSETBodyBytes {
		writeSSFError(ctx, caep.ErrReceiverInvalidRequest)
		return
	}

	res, rerr := s.caepReceiver.Receive(ctx.Request().Context(), strings.TrimSpace(string(body)))
	if rerr != nil {
		// A transient internal failure AFTER full validation (the SET was
		// authentic + addressed here, but the revoke/resolve store faltered).
		// 500 so the transmitter retries — we must not ack a revocation we
		// didn't perform. No oracle: the body is a generic internal error.
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
		return
	}
	if !res.Acked {
		writeSSFError(ctx, res.RejectCode)
		return
	}
	// Valid + acked (acted or no-op). RFC 8935: 202 with no body.
	ctx.JSON(http.StatusAccepted, struct{}{})
}

// writeSSFError renders an RFC 8935 §2.4 SSF error response: a 400 with a
// minimal {err, description} body. The `err` is the COARSE SSF-standard
// code from the receiver (invalid_request | invalid_key) — it never leaks
// which precise validation gate failed (signature vs aud vs replay vs
// expiry all collapse to invalid_key), so a probing transmitter learns
// only the standard category. The description is a fixed, non-revealing
// string (no per-failure detail).
func writeSSFError(ctx HandlerContext, code string) {
	if code == "" {
		code = caep.ErrReceiverInvalidKey
	}
	desc := "the security event token could not be authenticated"
	if code == caep.ErrReceiverInvalidRequest {
		desc = "the request body is not a valid security event token"
	}
	ctx.JSON(http.StatusBadRequest, map[string]string{
		"err":         code,
		"description": desc,
	})
}

// InvalidateClientCache evicts the cached client entity for clientID from
// the opt-in per-login ClientStore cache (WithClientStoreCache). Wire this
// into every client-mutation path — admin ClientAdminService
// Create/Update/Delete/RotateSecret and the RFC 7591/7592 DCR
// register/update/delete handlers — so a metadata edit (redirect_uri /
// scopes / active flag / secret) takes effect on the next Get, not after
// the TTL expires.
//
// When an invalidation bus is wired ([WithInvalidationBus]), this also
// publishes the change so every other replica evicts its local cache too —
// closing the cross-replica window where a just-edited client is still
// served stale elsewhere until that node's TTL elapses. Publish failures
// are logged, not propagated: the local eviction already succeeded and
// peers fall back to their TTL, matching the suspension cache's fail-open
// design.
//
// Safe to call when no cache is configured (no-op). Note this affects only
// the METADATA cache — ValidateSecret bypasses the cache entirely (§2), so
// a credential decision is never stale to begin with.

// === CIBA adapter methods (migrated from ciba_handler.go) ===

// handleBackchannelAuth delegates to oauth.HandleBackchannelAuth —
// see that file for the OIDC CIBA Core 1.0 poll-mode flow.
func (s *Server) handleBackchannelAuth(ctx HandlerContext) { oauth.HandleBackchannelAuth(s, ctx) }

// ResolveCIBAHint maps a CIBA request's hints to a known user's subject
// id. Poll mode: at least one hint must resolve. login_hint is matched
// against UserProvider.GetByID (the canonical identifier); id_token_hint
// is validated and its sub trusted; login_hint_token is treated as an
// opaque GetByID lookup. Returns ("", nil) when nothing resolves — the
// handler collapses that to unknown_user_id (anti-enumeration). The
// provider name is recorded for the AMR claim ("ciba" — out-of-band
// confirmation).
func (s *Server) ResolveCIBAHint(ctx context.Context, loginHint, idTokenHint, loginHintToken string) (string, string, error) {
	// id_token_hint: validate the token and trust its subject. The
	// validator rejects expired / wrong-alg / bad-signature tokens.
	if idTokenHint != "" {
		if claims, err := s.ValidateToken(ctx, idTokenHint); err == nil && claims != nil && claims.Subject != "" {
			return claims.Subject, CIBAAMR, nil
		}
	}
	if s.userProvider == nil {
		return "", "", nil
	}
	for _, hint := range []string{loginHint, loginHintToken} {
		if hint == "" {
			continue
		}
		if u, err := s.userProvider.GetByID(ctx, hint); err == nil && u != nil {
			return u.ID, CIBAAMR, nil
		}
	}
	return "", "", nil
}

// CIBAAMR is the AMR / provider value recorded for a token minted via the CIBA
// grant. Defined in core so the extracted CIBA grant handler can reference it.
const CIBAAMR = core.CIBAAMR

// DeliverCIBAChallenge pushes the auth_req_id out of band via the wired
// CIBA transport. binding_message is forwarded under the metadata key
// so the device app can render it for the user to correlate.
func (s *Server) DeliverCIBAChallenge(ctx context.Context, authReqID, subjectID, bindingMessage string) error {
	if s.cibaTransport == nil {
		return oauth.ErrCIBARequestInvalid
	}
	var meta map[string]string
	if bindingMessage != "" {
		meta = map[string]string{"binding_message": bindingMessage}
	}
	return s.cibaTransport.Send(ctx, authReqID, subjectID, meta)
}

// RecordCIBAAuthRequest emits the ciba_auth_request audit event.
func (s *Server) RecordCIBAAuthRequest(ctx HandlerContext, clientID, subjectID, authReqID string) {
	audit.RecordCIBAAuthRequest(s.auditor, ctx, clientID, subjectID, authReqID)
}

// recordCIBADecision emits a ciba_approved / ciba_denied audit event.
func (s *Server) recordCIBADecision(ctx HandlerContext, clientID, subjectID string, approved bool) {
	audit.RecordCIBADecision(s.auditor, ctx, clientID, subjectID, approved)
}

// publishTokenRevocation broadcasts a token revocation to other replicas.
func (s *Server) publishTokenRevocation(ctx context.Context, token string, exp int64) {
	handler.PublishTokenRevocation(s.BuildHandlerDeps(), ctx, token, exp)
}

// notifyTokenRevoked fans a successful cross-issuer revoke out to BOTH
// out-of-band channels this single choke point (RevokeAcrossIssuers) feeds:
// the cross-replica cluster Bus (publishTokenRevocation, so peer replicas
// drop the token from their in-process deny-set) and the audit pipeline's
// token_revoked event (recordTokenRevoked, so any operator-registered
// platform/lifecycle/webhook subscription — or CEF/OCSF export, or the SOC2
// control-area report — actually observes the revocation; see
// audit.RecordTokenRevoked's doc for why that second leg was previously a
// dead letter). Both legs are best-effort/fail-open: the revocation itself
// already succeeded locally before either fires.
func (s *Server) notifyTokenRevoked(ctx context.Context, token string, revokedIssuers []string) {
	s.publishTokenRevocation(ctx, token, jwtExpUnsafe(token))
	s.recordTokenRevoked(ctx, token, revokedIssuers)
}

// recordTokenRevoked emits the token_revoked audit event. clientID/subject
// are best-effort, UNVERIFIED claims (handler.JWTClaimsUnsafe) — annotation
// only, mirroring jwtExpUnsafe's existing advisory contract.
func (s *Server) recordTokenRevoked(ctx context.Context, token string, revokedIssuers []string) {
	clientID, subject := handler.JWTClaimsUnsafe(token)
	audit.RecordTokenRevoked(s.auditor, ctx, clientID, subject, revokedIssuers)
}

// applyTokenRevocation applies a token revocation received from another replica.
func (s *Server) applyTokenRevocation(ctx context.Context, evt cluster.Event) {
	handler.ApplyTokenRevocation(s.BuildHandlerDeps(), ctx, evt)
}

// jwtExpUnsafe extracts the exp claim from a JWT without validation.
func jwtExpUnsafe(token string) int64 {
	return handler.JWTExpUnsafe(token)
}

// revocationSeeder is the same seam boot uses to seed the issuers'
// in-process revocation deny-sets from the durable RevocationStore
// (cmd/sso-server/serverbuildsign.seedRevocations). Re-used on
// invalidation-bus recovery so a KindTokenRevoked event lost during the
// outage is re-applied from the store instead of being lost forever.
type revocationSeeder interface {
	SeedRevocations(context.Context) error
}

// resubscribeAndReseed opens a fresh bus subscription and then converges the
// state this replica may have missed while degraded. Ordering is load-bearing:
// subscribe FIRST (re-seeding before the new stream exists would open a fresh
// loss window between re-seed and subscribe), re-seed SECOND, and only then
// does the caller clear degraded — readiness must not go green while local
// state is still stale. Events buffered on the new stream during the re-seed
// are applied right after; invalidations are idempotent so the overlap is safe.
//
// The subscription rides its own child context so an abandoned stream (re-seed
// failed, the backoff loop will open another) releases its bus registration /
// watch instead of accumulating one per retry for the life of the process.
func (s *Server) resubscribeAndReseed(ctx context.Context, attempt int) (<-chan cluster.Event, context.CancelFunc, bool) {
	subCtx, cancel := context.WithCancel(ctx)
	next, err := s.invalidationBus.Subscribe(subCtx)
	if err != nil {
		cancel()
		if ctx.Err() == nil {
			s.logger.Error("invalidation bus resubscribe failed, will retry", "attempt", attempt, "error", err)
		}
		return nil, nil, false
	}
	if err := s.reseedInvalidationState(ctx); err != nil {
		// Fail-safe: a partial re-seed must NOT clear degraded — /readyz stays
		// red and the loop retries the whole subscribe+re-seed cycle after
		// backoff. Audited per attempt (rate-bounded by the backoff cadence)
		// because "bus is back but the durable re-read failed" is a distinct,
		// actionable fault the one-per-transition degraded event can't convey.
		cancel()
		s.logger.Error("invalidation bus resubscribed but re-seed failed; staying degraded", "attempt", attempt, "error", err)
		s.recordInvalidationBusEvent(eventInvalidationBusDegraded, audit.OutcomeFailure, invalidationBusReseedFailedReason)
		return nil, nil, false
	}
	return next, cancel, true
}

// reseedInvalidationState re-applies everything a lost invalidation Event
// could have carried. TTL-backed caches are flushed (their next read
// re-fetches from the authoritative store), and the revocation deny-sets are
// re-seeded from the durable store — the one target with NO TTL safety net: a
// missed KindTokenRevoked would otherwise honor a revoked token until its own
// exp. KindSigningKeyRotation is deliberately absent — peer-key convergence is
// owned by the signing-key aggregation loop's own subscribeAndSeed self-heal.
func (s *Server) reseedInvalidationState(ctx context.Context) error {
	s.flushInvalidationCaches()
	return s.reseedRevocationDenySets(ctx)
}

// reseedRevocationDenySets re-runs the boot-time SeedRevocations pass on every
// registered issuer that exposes the seam. Seeding is additive + idempotent
// (revocation_set.go), so re-running it over a live issuer is safe; a nil
// RevocationStore inside the issuer is a no-op exactly as at boot. Every
// issuer is attempted even after a failure so one broken store doesn't stop
// the others from converging; any error keeps the replica degraded.
func (s *Server) reseedRevocationDenySets(ctx context.Context) error {
	var errs []error
	for name, ti := range s.tokenIssuers {
		seeder, ok := ti.(revocationSeeder)
		if !ok {
			continue
		}
		if err := seeder.SeedRevocations(ctx); err != nil {
			errs = append(errs, fmt.Errorf("issuer %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}
