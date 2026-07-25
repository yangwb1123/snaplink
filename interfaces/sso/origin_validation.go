package sso

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
)

// The Key* re-exports below moved here from aliases.go to keep that
// generated file within the per-file line budget; this file otherwise has
// no relation to the wire-payload key constants.
const KeyAccessToken = core.KeyAccessToken
const KeyACR = core.KeyACR
const KeyActive = core.KeyActive
const KeyAMR = core.KeyAMR
const KeyAud = core.KeyAud
const KeyAuthTime = core.KeyAuthTime
const KeyClientID = core.KeyClientID
const KeyTenantID = core.KeyTenantID
const KeyClientName = core.KeyClientName
const KeyScopes = core.KeyScopes
const KeyCode = core.KeyCode
const KeyCountryCode = core.KeyCountryCode
const KeyError = core.KeyError
const KeyErrorDescription = core.KeyErrorDescription
const KeyExp = core.KeyExp
const KeyExpiresIn = core.KeyExpiresIn
const KeyIat = core.KeyIat
const KeyIDToken = core.KeyIDToken
const KeyIss = core.KeyIss
const KeyIssuedTokenType = core.KeyIssuedTokenType
const KeyIssuer = core.KeyIssuer
const KeyJTI = core.KeyJTI
const KeyConsentChallengeID = core.KeyConsentChallengeID
const KeyMFAChallengeID = core.KeyMFAChallengeID
const KeyMFAMethod = core.KeyMFAMethod
const KeyMFAMethodData = core.KeyMFAMethodData
const KeyMFAMethods = core.KeyMFAMethods
const KeyNbf = core.KeyNbf
const KeyProviders = core.KeyProviders
const KeyClientContext = core.KeyClientContext
const KeyRecommendedLang = core.KeyRecommendedLang
const KeyRedirectURI = core.KeyRedirectURI
const KeyRefreshToken = core.KeyRefreshToken
const KeyRevoked = core.KeyRevoked
const KeyScope = core.KeyScope
const KeyServingRegion = core.KeyServingRegion
const KeySessionID = core.KeySessionID
const KeyState = core.KeyState
const KeyDevice = core.KeyDevice
const KeyLoginPageURI = core.KeyLoginPageURI
const KeyPreviousLogin = core.KeyPreviousLogin
const KeyBranding = core.KeyBranding
const KeyActiveDevices = core.KeyActiveDevices
const KeyDeviceLimitWarn = core.KeyDeviceLimitWarn
const KeySessionLimitWarn = core.KeySessionLimitWarn
const KeyStatus = core.KeyStatus
const KeyStrategy = core.KeyStrategy
const KeySub = core.KeySub
const KeySupportedGrants = core.KeySupportedGrants
const KeyTokenHint = core.KeyTokenHint
const KeyTokenStrategy = core.KeyTokenStrategy
const KeyTokenType = core.KeyTokenType
const KeyVCSRevision = core.KeyVCSRevision
const KeyVCSTime = core.KeyVCSTime
const KeyVersion = core.KeyVersion

// isOriginAllowed checks if the given origin is allowed by the CORS policy.
// Returns true if:
//   - No CORS policy is configured (allow all for backwards compatibility)
//   - The origin is in the AllowedOrigins list
//   - Wildcard "*" is configured
//
// Returns false if:
//   - CORS policy exists but origin is not in AllowedOrigins and no wildcard
//
// This is used for defense-in-depth CSRF protection on sensitive endpoints
// like /auth/login where we want to validate the Origin header even before
// the CORS middleware runs.
func (s *Server) isOriginAllowed(origin string) bool {
	// No CORS policy = no origin restrictions (backwards compatible)
	if s.corsPolicy == nil {
		return true
	}

	// Check each allowed origin
	for _, allowed := range s.corsPolicy.AllowedOrigins {
		// Wildcard allows any origin
		if allowed == "*" {
			return true
		}
		// Exact match
		if allowed == origin {
			return true
		}
	}

	return false
}

// --- CIBA ping delivery -----------------------------------------------
//
// Lives here (not a dedicated file) because interfaces/sso is at its frozen
// file-count ceiling (directory_fanout_test.go) — this is otherwise
// unrelated to origin/CORS validation above; it backs CIBA's ping/push
// notification-delivery mode.

// ErrCIBANotEnabled is returned by ResolveBackchannelAuthRequest when no
// CIBA store is wired (WithCIBA not configured). It is an SDK-level
// sentinel, not a wire error code.
var ErrCIBANotEnabled = errors.New("sso: CIBA is not enabled")

// cibaPingDeliveryTimeout bounds the detached ping goroutine spawned on
// resolution. The request that triggered the approval has already returned,
// so the goroutine runs on context.Background() with NO inherited deadline —
// without this bound a hanging/never-returning custom notifier would leak the
// goroutine forever. Deliberately set LONGER than the reference
// httpCIBAPingNotifier's own 5s HTTP client timeout so the transport's timeout
// fires first on the common path (yielding a clean error, not a context
// cancellation), while a custom notifier that ignores ctx still gets bounded.
const cibaPingDeliveryTimeout = 10 * time.Second

// ResolveBackchannelAuthRequest transitions a pending CIBA request to
// approved or denied and, in ping or push delivery mode, notifies the
// client. Operators call this from their device-confirmation callback
// instead of poking CIBAStore.SetStatus directly, so delivery fires
// automatically on resolution.
//
// The status transition is authoritative (a /token poll — still available
// as a fallback even in push mode — mints or refuses tokens off it).
// Delivery is best-effort and fire-and-forget: dispatchCIBANotification
// (accessors_feature_gates.go) picks push over ping when both are wired
// and the resolution is an approval (push is a strict upgrade — it mints
// and delivers the actual token, see deliverCIBAPush); a denied resolution
// has no token to push, so ping (if wired) still fires for it. A failed
// delivery is logged, never returned, since the client can still poll.
//
// Returns ErrCIBANotEnabled if CIBA isn't wired, or the store's error for
// an unknown/expired (oauth.ErrCIBARequestNotFound) or already-resolved
// (oauth.ErrCIBARequestResolved) request.
func (s *Server) ResolveBackchannelAuthRequest(ctx context.Context, authReqID string, approved bool) error {
	if s.cibaStore == nil {
		return ErrCIBANotEnabled
	}
	// Read before transition so a racing /token poll that consumes +
	// deletes the entry can't strip the notification token from under us.
	req, err := s.cibaStore.Get(ctx, authReqID)
	if err != nil {
		return err
	}
	status := oauth.CIBADenied
	if approved {
		status = oauth.CIBAApproved
	}
	if err := s.cibaStore.SetStatus(ctx, authReqID, status); err != nil {
		return err
	}
	if req.ClientNotificationToken != "" {
		s.dispatchCIBANotification(authReqID, req.ClientID, req.ClientNotificationToken, approved)
	}
	return nil
}

// deliverCIBAPing supervises a single detached CIBA ping delivery. It is the
// body of the goroutine spawned by ResolveBackchannelAuthRequest, extracted so
// the timeout + recover + metric/audit wrapper is unit-testable in isolation.
//
// Hardening over the original bare `go n.Notify(context.Background(), ...)`:
//   - Bounded context: a hanging/never-returning notifier can no longer leak
//     this goroutine indefinitely (cibaPingDeliveryTimeout).
//   - recover(): a panicking custom notifier is contained here — it logs +
//     audits + counts an error instead of taking down the goroutine (and
//     potentially the process) with no trace.
//   - Observability: every outcome increments sso_ciba_ping_total{outcome};
//     failures (error return OR recovered panic) also emit a ciba_ping_failed
//     audit event so operators can see WHICH client's ping failed.
//
// The ping is best-effort by contract (the client can still poll), so a failure
// is logged + recorded, never surfaced — there is no caller to return to.
func (s *Server) deliverCIBAPing(clientID, authReqID, token string) {
	// recover() so a panic in a third-party notifier can't crash the goroutine
	// silently (or escalate to a process-wide crash on an unrecovered panic in
	// a bare goroutine). On recovery, treat it as a delivery failure.
	defer func() {
		if r := recover(); r != nil {
			reason := fmt.Sprintf("panic: %v", r)
			s.logger.Error("ciba ping notification panicked", "auth_req_id", authReqID, "client_id", clientID, "panic", r)
			s.recordCIBAPingFailure(clientID, authReqID, reason)
		}
	}()

	// context.Background() is the correct PARENT here (the request that
	// triggered the approval has returned, so there is no live request ctx to
	// inherit — inheriting one would cancel the ping immediately). We ADD a
	// deadline so a notifier that blocks past the bound is unblocked and the
	// goroutine returns.
	ctx, cancel := context.WithTimeout(context.Background(), cibaPingDeliveryTimeout)
	defer cancel()

	if err := s.cibaPingNotifier.Notify(ctx, clientID, authReqID, token); err != nil {
		s.logger.Error("ciba ping notification failed", "auth_req_id", authReqID, "client_id", clientID, "error", err)
		s.recordCIBAPingFailure(clientID, authReqID, err.Error())
		return
	}
	if s.metrics != nil {
		s.metrics.CIBAPingTotal.WithLabelValues("success").Inc()
	}
}

// recordCIBAPingFailure is the shared error tail for deliverCIBAPing: bump the
// error metric + emit the ciba_ping_failed audit event. Detached goroutine, so
// it audits over context.Background() via the background-context recorder helper
// (mirrors the signing-key aggregation degraded/recovered events).
func (s *Server) recordCIBAPingFailure(clientID, authReqID, reason string) {
	if s.metrics != nil {
		s.metrics.CIBAPingTotal.WithLabelValues("error").Inc()
	}
	audit.RecordCIBAPingFailed(s.auditor, context.Background(), clientID, authReqID, reason)
}
