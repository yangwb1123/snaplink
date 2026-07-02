package sso

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/snaplink/sso/domains/anomaly"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/protocols/oidc"
)

func (s *Server) getAuthenticator(name string) (Authenticator, error) {
	a, ok := s.authenticators[name]
	if !ok {
		return nil, fmt.Errorf("authenticator %q not registered", name)
	}
	return a, nil
}

// issuerForClient returns the TokenIssuer that should mint tokens for the
// given client. Resolution order: per-tenant issuer (WithTenantTokenIssuer)
// → client.TokenStrategy → server default → (if exactly one issuer is
// registered) that one.
//
// A per-tenant mapping takes precedence over the client/server strategy so
// that crypto isolation is not silently defeatable by a client setting its
// own TokenStrategy. When a tenant mapping names an issuer that was never
// registered via WithTokenIssuer we fail closed (error) rather than fall
// back to a shared default key — a misconfiguration must not leak one
// tenant's clients onto another key.
func (s *Server) issuerForClient(c *Client) (string, TokenIssuer, error) {
	name := ""
	if c != nil && c.TenantID != "" {
		if tn, ok := s.tenantTokenStrategies[c.TenantID]; ok {
			name = tn
		}
	}
	if name == "" {
		if c != nil && c.TokenStrategy != "" {
			name = c.TokenStrategy
		} else if s.defaultTokenStrategy != "" {
			name = s.defaultTokenStrategy
		} else if len(s.tokenIssuers) == 1 {
			for n := range s.tokenIssuers {
				name = n
			}
		}
	}
	if name == "" {
		return "", nil, fmt.Errorf("no token strategy resolvable for client")
	}
	ti, ok := s.tokenIssuers[name]
	if !ok {
		return name, nil, fmt.Errorf("token strategy %q not registered", name)
	}
	return name, ti, nil
}

// idTokenIssuerForClient selects the oidc.IDTokenIssuer that should mint
// the ID token for the given client, mirroring issuerForClient so a
// tenant's id_tokens are signed by the SAME key as its access tokens —
// closing the crypto-isolation gap where id_token previously always used
// the one shared s.idTokenIssuer.
//
// A per-tenant mapping (WithTenantTokenIssuer) deliberately governs ALL of
// that tenant's token types at once: there is no separate id_token tenant
// map, because isolating access tokens but not id_tokens for the same
// tenant would silently re-open this very gap. The registered TokenIssuer
// object is reused — the default Ed25519/ECDSA/RSA issuers each satisfy
// oidc.IDTokenIssuer, so one signing key + one JWKS entry already covers
// access + id (+ JARM + userinfo).
//
// Returns (issuer, emit, err):
//   - No tenant mapping → (s.idTokenIssuer, s.idTokenIssuer != nil, nil):
//     unchanged shared behavior, pure backward-compat.
//   - Tenant mapping naming an UNREGISTERED issuer → (nil, false, error):
//     fail closed exactly like issuerForClient — a misconfiguration must
//     not leak the tenant onto a shared key. The caller logs + omits.
//   - Tenant mapping whose registered issuer does NOT implement
//     oidc.IDTokenIssuer (e.g. an opaque/session strategy) → (nil, false,
//     nil): emit=false, the caller OMITS id_token. Falling back to the
//     shared s.idTokenIssuer here would sign this tenant's id_token with
//     another key — the opposite of isolation — so we fail closed by
//     omission (the access-token branch is unaffected; only id_token is
//     withheld, exactly as if no issuer were wired).
func (s *Server) idTokenIssuerForClient(c *Client) (oidc.IDTokenIssuer, bool, error) {
	if c == nil || c.TenantID == "" {
		return s.idTokenIssuer, s.idTokenIssuer != nil, nil
	}
	name, ok := s.tenantTokenStrategies[c.TenantID]
	if !ok {
		// Tenant without a mapping behaves like a non-tenant client.
		return s.idTokenIssuer, s.idTokenIssuer != nil, nil
	}
	ti, ok := s.tokenIssuers[name]
	if !ok {
		return nil, false, fmt.Errorf("token strategy %q not registered", name)
	}
	idIssuer, ok := ti.(oidc.IDTokenIssuer)
	if !ok {
		// The tenant's signing strategy can't mint id_tokens (e.g. opaque
		// session tokens). Omit rather than sign with the shared key.
		s.logger.Error("tenant token strategy does not support id_token issuance; omitting id_token",
			"tenant", c.TenantID, "strategy", name, "client", c.ID)
		return nil, false, nil
	}
	return idIssuer, true, nil
}

// jarmSignerForClient selects the oidc.JARMSigner for the given client's
// authorization response, mirroring idTokenIssuerForClient so a tenant's
// JARM responses are signed by the SAME key as its access + id tokens.
// JARM is opt-in (WithJARM); when no signer is wired this returns (nil,
// false) and the caller never reaches a JARM response mode (gated in
// isValidResponseMode).
//
// Same discipline as idTokenIssuerForClient:
//   - No tenant mapping → the shared s.jarmSigner (unchanged behavior).
//   - Tenant issuer unregistered → (nil, false): fail closed. The JARM
//     render path already fails closed (invalid_request) when signing
//     can't proceed, so an omitted signer surfaces as that same error
//     rather than leaking the bare code.
//   - Tenant issuer registered but not a JARMSigner → (nil, false): omit
//     (fail closed) rather than sign with another tenant's / the shared
//     key.
func (s *Server) jarmSignerForClient(c *Client) (oidc.JARMSigner, bool) {
	if c == nil || c.TenantID == "" {
		return s.jarmSigner, s.jarmSigner != nil
	}
	name, ok := s.tenantTokenStrategies[c.TenantID]
	if !ok {
		return s.jarmSigner, s.jarmSigner != nil
	}
	ti, ok := s.tokenIssuers[name]
	if !ok {
		s.logger.Error("tenant token strategy not registered; failing JARM closed",
			"tenant", c.TenantID, "strategy", name, "client", c.ID)
		return nil, false
	}
	js, ok := ti.(oidc.JARMSigner)
	if !ok {
		s.logger.Error("tenant token strategy does not support JARM signing; failing closed",
			"tenant", c.TenantID, "strategy", name, "client", c.ID)
		return nil, false
	}
	return js, true
}

// applyIntrospectionSigningMetadata advertises RFC 9701 §7
// introspection_signing_alg_values_supported — ONLY when a dedicated
// introspection signer is wired (WithIntrospectionSigning); omitted
// entirely otherwise, so an unmodified deployment's discovery doc is
// byte-identical to a build without this feature. Lives alongside the
// other signer-selection helpers (jarmSignerForClient above) rather than
// in its own file: interfaces/sso is already at its frozen
// directory_fanout_test.go file-count ceiling (AGENTS.md §0.1), and
// server_discovery_config.go — the more obvious home — is itself near the
// 500-line file budget.
func (s *Server) applyIntrospectionSigningMetadata(cfg *oidc.ProviderMetadata, ctx context.Context) {
	if s.introspectionSigner == nil {
		return
	}
	cfg.IntrospectionSigningAlgValuesSupported = s.introspectionSigningAlgValues(ctx)
}

// introspectionSigningAlgValues derives the alg(s) the wired introspection
// signer actually produces. Prefers the published JWKS (authoritative —
// covers a signer mid-rotation with two live algs, though the shipped
// issuers never mix algs on one instance) and falls back to the signer's
// own Alg() method (the same fallback shape userinfoSignerProducesAlg
// uses) for a signer that opts out of JWKS discovery entirely (e.g. a
// KMS-backed IntrospectionSigner with no local public key to publish).
func (s *Server) introspectionSigningAlgValues(ctx context.Context) []string {
	if jp := s.IntrospectionSigningKeys(); jp != nil {
		if keys, err := jp.JWKS(ctx); err == nil {
			seen := map[string]struct{}{}
			for _, k := range keys {
				if k.Alg != "" {
					seen[k.Alg] = struct{}{}
				}
			}
			if len(seen) > 0 {
				out := make([]string, 0, len(seen))
				for a := range seen {
					out = append(out, a)
				}
				sort.Strings(out)
				return out
			}
		}
	}
	if ar, ok := s.introspectionSigner.(interface{ Alg() string }); ok {
		if alg := ar.Alg(); alg != "" {
			return []string{alg}
		}
	}
	return nil
}

// ValidateToken is the public face of validateAnyToken — returns just the
// claims for callers (e.g. the admin middleware) that don't care which
// issuer accepted the token.

// === Audit helper methods (migrated from audit_helpers.go) ===

// boundLoginProvider maps an arbitrary provider string to a BOUNDED Prometheus
// label: a registered authenticator name passes through, anything else collapses
// to "unknown". The /auth/login provider is request input and is recorded on the
// PRE-validation failure path (e.g. unknown client_id) before getAuthenticator
// ever runs, so without this an unauthenticated caller sending a unique random
// provider per request would mint unbounded permanent series (cardinality DoS) on
// sso_login_attempts_total + sso_login_duration_seconds. Same class as the
// HTTP-method label fix; the raw provider still flows to audit/anomaly (forensics
// need the real value — those are not bounded-cardinality metric labels).
func (s *Server) boundLoginProvider(provider string) string {
	if _, ok := s.authenticators[provider]; ok {
		return provider
	}
	return "unknown"
}

func (s *Server) observeLoginDuration(ctx HandlerContext, provider, outcome string) {
	if s.metrics == nil {
		return
	}
	v := ctx.Get(ctxKeyLoginStart)
	start, ok := v.(time.Time)
	if !ok {
		return
	}
	s.metrics.LoginDuration.WithLabelValues(s.boundLoginProvider(provider), outcome).Observe(time.Since(start).Seconds())
}

// recordLoginFailure emits a login-failure audit event AND bumps the
// failure counter on the metrics registry (nil-safe). Reason is one of
// the Err* constants describing why authentication was refused.
func (s *Server) recordLoginFailure(ctx HandlerContext, clientID, provider, reason string) {
	if s.metrics != nil {
		s.metrics.LoginAttemptsTotal.WithLabelValues(s.boundLoginProvider(provider), "failure").Inc()
	}
	s.recordTenantLoginAttempt(ctx, clientID, "failure")
	s.observeLoginDuration(ctx, provider, "failure")
	s.dispatchLoginAnomaly(ctx, "", clientID, provider, "failure", reason)
	if s.auditor == nil {
		return
	}
	audit.RecordLoginFailure(s.auditor, ctx, clientID, provider, reason)
}

// dispatchLoginAnomaly hands a anomaly.LoginEvent to the AnomalyRunner.
// Nil-safe — no runner = no-op zero overhead. SubjectID is
// optional on failure paths (the credential validator may not
// have resolved a user); detectors needing it skip the subject-
// scoped checks.
func (s *Server) dispatchLoginAnomaly(ctx HandlerContext, subjectID, clientID, provider, outcome, failureReason string) {
	if s.anomalyRunner == nil {
		return
	}
	r := ctx.Request()
	event := &anomaly.LoginEvent{
		SubjectID:     subjectID,
		ClientID:      clientID,
		Provider:      provider,
		Outcome:       outcome,
		FailureReason: failureReason,
		RemoteIP:      audit.ClientIP(r),
		UserAgent:     r.Header.Get("User-Agent"),
		Timestamp:     time.Now(),
	}
	if info, ok := GeoFromHandlerContext(ctx); ok {
		event.Geo = info
	}
	if tp := r.Header.Get(HeaderTraceparent); tp != "" {
		if tc, err := tracer.ParseTraceparent(tp); err == nil {
			event.TraceID = tc.TraceID
		}
	}
	s.anomalyRunner.Dispatch(r.Context(), event)
}

// recordLoginSuccess emits a login event after a fully successful login flow
// AND bumps the success counter + tokens_issued counter on the metrics
// registry (nil-safe).
func (s *Server) recordLoginSuccess(ctx HandlerContext, clientID, provider, strategy, userID, sessionID string) {
	if s.metrics != nil {
		s.metrics.LoginAttemptsTotal.WithLabelValues(s.boundLoginProvider(provider), "success").Inc()
		s.metrics.TokensIssuedTotal.WithLabelValues(strategy).Inc()
	}
	s.recordTenantLoginAttempt(ctx, clientID, "success")
	s.recordTenantTokenIssued(ctx, clientID, strategy)
	s.observeLoginDuration(ctx, provider, "success")
	s.dispatchLoginAnomaly(ctx, userID, clientID, provider, "success", "")
	if s.auditor == nil {
		return
	}
	audit.RecordLoginSuccess(s.auditor, ctx, clientID, provider, strategy, userID, sessionID)
}

// recordCredentialHealth emits a non-blocking credential-health signal
// after a successful login (password_weak / password_compromised). It is
// purely informational — the login already succeeded and was not blocked.
// nil health short-circuits with zero overhead (no checker wired, or a
// healthy credential). Counts the signal toward the bounded
// credential-health metric before auditing.
func (s *Server) recordCredentialHealth(ctx HandlerContext, clientID, userID string, health *CredentialHealth) {
	if health == nil {
		return
	}
	if s.metrics != nil {
		signal := metrics.SignalWeak
		if health.Compromised {
			signal = metrics.SignalCompromised
		}
		s.metrics.CredentialHealthSignalsTotal.WithLabelValues(signal).Inc()
	}
	audit.RecordCredentialHealth(s.auditor, ctx, clientID, userID, health)
}

// recordLogout emits a logout event with what was actually revoked.
func (s *Server) recordLogout(ctx HandlerContext, sessionID string, revoked []string) {
	audit.RecordLogout(s.auditor, ctx, sessionID, revoked)
}

// recordLogoutNotifySuccess emits a `logout_notified` audit
// event for a successful back-channel logout fanout. ClientID is
// the RP that was notified; ActorID is the user whose logout
// triggered the notification.
func (s *Server) recordLogoutNotifySuccess(ctx HandlerContext, clientID, subject, uri string) {
	audit.RecordLogoutNotifySuccess(s.auditor, ctx, clientID, subject, uri)
}

// recordLogoutNotifyFailure emits a `logout_notified` audit
// event with Outcome=failure when the back-channel POST failed
// or the RP returned a non-2xx status. The error string lands
// in Reason so SIEMs can alert on patterns ("rp-X always 503").
func (s *Server) recordLogoutNotifyFailure(ctx HandlerContext, clientID, subject, reason string) {
	audit.RecordLogoutNotifyFailure(s.auditor, ctx, clientID, subject, reason)
}

// recordAccountLocked emits an account_locked audit event. Fires
// both when a NEW lockout engages (after the failure crossed the
// threshold) and when a subsequent attempt arrives while the
// lock is still active — operators want both signals to
// distinguish "lock just engaged" from "attacker keeps trying
// against a locked account". The lockoutKey lands in ActorID so
// SIEMs can pivot on it.
func (s *Server) recordAccountLocked(ctx HandlerContext, clientID, provider, lockKey string, until time.Time) {
	audit.RecordAccountLocked(s.auditor, ctx, clientID, provider, lockKey, until)
}

// recordCodeSent emits a code_sent event for two-step flows (phone/email).
// target is intentionally not stored in full to limit PII spread; only its
// type lives in Provider, the value goes into a short metadata key.
func (s *Server) recordCodeSent(ctx HandlerContext, provider, target string, ok bool) {
	audit.RecordCodeSent(s.auditor, ctx, provider, target, ok)
}

// recordTokenIssued emits a token_issued event (used for grant flows).
func (s *Server) recordTokenIssued(ctx HandlerContext, clientID, strategy, subjectID string) {
	s.recordTenantTokenIssued(ctx, clientID, strategy)
	audit.RecordTokenIssued(s.auditor, ctx, clientID, strategy, subjectID)
}

// recordRefreshTokenIssued emits a refresh_token_issued event. Set
// rotation=true on the rotation path so SIEMs can separate first-
// issue (login / authz_code) from rotation (refresh_token grant).
func (s *Server) recordRefreshTokenIssued(ctx HandlerContext, clientID, subjectID string, rotation bool) {
	audit.RecordRefreshTokenIssued(s.auditor, ctx, clientID, subjectID, rotation)
}

// recordIDTokenIssued emits an id_token_issued event whenever an
// OIDC id_token is appended to the response.
func (s *Server) recordIDTokenIssued(ctx HandlerContext, clientID, subjectID string) {
	audit.RecordIDTokenIssued(s.auditor, ctx, clientID, subjectID)
}

// recordDeviceCodeIssued emits a device_code_issued event at the
// start of an RFC 8628 device authorization grant.
func (s *Server) recordDeviceCodeIssued(ctx HandlerContext, clientID string) {
	audit.RecordDeviceCodeIssued(s.auditor, ctx, clientID)
}

// recordDeviceCodeApproved / Denied emit at the consent step.
// userID is the user who hit /device/verify; deviceClientID is the
// client_id that originally requested the device authorization.
func (s *Server) recordDeviceCodeDecision(ctx HandlerContext, userID, deviceClientID string, approved bool) {
	audit.RecordDeviceCodeDecision(s.auditor, ctx, userID, deviceClientID, approved)
}

// recordRefreshTokenReuse emits a refresh_token_reuse_detected event.
// Fired from the rotation grant when the store signals
// oauth.ErrRefreshTokenReused — a security signal worth routing to alerting.
func (s *Server) recordRefreshTokenReuse(ctx HandlerContext, clientID, familyID string, killed int) {
	audit.RecordRefreshTokenReuse(s.auditor, ctx, clientID, familyID, killed)
}

// recordRefreshRotationVelocity emits a refresh_rotation_velocity_exceeded
// event after the per-family rotation-velocity cap trips and the family is
// killed. The wire response stays the generic invalid_grant — this audit
// event (plus sso_refresh_rotation_velocity_exceeded_total) is the only
// place the velocity detail surfaces.
func (s *Server) recordRefreshRotationVelocity(ctx HandlerContext, clientID, familyID string, count, killed int) {
	audit.RecordRefreshRotationVelocityExceeded(s.auditor, ctx, clientID, familyID, count, killed)
}

// recordCallbackFailure emits a callback_failure event.
func (s *Server) recordCallbackFailure(ctx HandlerContext, provider, reason string) {
	audit.RecordCallbackFailure(s.auditor, ctx, provider, reason)
}
