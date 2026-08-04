package oauth

import (
	"strings"

	"github.com/yangwb1123/snaplink/domains/metering"
	"github.com/yangwb1123/snaplink/platform/geo"
	"github.com/yangwb1123/snaplink/shared/core"
)

// recordIntrospectionUsage Offers a token-usage telemetry event for an
// ACTIVE access-token introspection. Off the request hot path: Offer never
// blocks, and a nil recorder (telemetry disabled) is a safe no-op. The
// client-id fallback mirrors populateAccessIntrospectionBody's so the
// aggregated bucket and the response body agree on which client "owns" the
// token. ctx carries the request's geo stash; without one the Event's
// GeoCountry stays "" — byte-identical to a build without the extractor.
func recordIntrospectionUsage(d IntrospectDeps, ctx core.HandlerContext, claims *core.TokenClaims) {
	clientID := claims.ClientID
	if clientID == "" && len(claims.Audience) > 0 {
		clientID = claims.Audience[0]
	}
	d.TokenUsageRecorder().Offer(metering.Event{
		Thumbprint: metering.Thumbprint(claims.JTI),
		Kind:       metering.KindAccess,
		Endpoint:   metering.EndpointIntrospect,
		ClientID:   clientID,
		SubjectID:  claims.Subject,
		GeoCountry: geo.CountryCodeFromContext(ctx),
	})
}

// populateIntrospectionSID stamps the sid (session id) claim onto the
// introspection body when the token carries a session binding.
func populateIntrospectionSID(body map[string]any, claims *core.TokenClaims) {
	if claims.SID != "" {
		body[core.KeySID] = claims.SID
	}
}

// populateIntrospectionConfirmation stamps the RFC 7662 §2.2 sender-constraint
// confirmation onto the introspection body (mTLS X.509 SHA-256 or DPoP JKT).
func populateIntrospectionConfirmation(body map[string]any, claims *core.TokenClaims) {
	if claims.ConfirmationX5TS256 != "" {
		body[core.KeyCnf] = map[string]any{core.KeyCnfX5TS256: claims.ConfirmationX5TS256}
	} else if claims.ConfirmationJKT != "" {
		body[core.KeyCnf] = map[string]any{core.KeyCnfJKT: claims.ConfirmationJKT}
	}
}

// populateIntrospectionServingRegion echoes the token's mint region (RFC
// 7662 extension, same discipline as client_id/jti/sid). Provenance of the
// token, NOT the calling RS's region — deliberately ungated, like the rest
// of introspection.
func populateIntrospectionServingRegion(body map[string]any, claims *core.TokenClaims) {
	if claims.ServingRegion != "" {
		body[core.KeyServingRegion] = claims.ServingRegion
	}
}

// populateAccessIntrospectionBody copies the optional RFC 7662 / RFC 9068
// claims onto an already-active access-token body. Purely additive: it
// carries NO early-return / auth-gate semantics — the ValidateAnyToken auth
// gate stays in introspectAccess.
func populateAccessIntrospectionBody(body map[string]any, claims *core.TokenClaims) {
	if !claims.ExpiresAt.IsZero() {
		body[core.KeyExp] = claims.ExpiresAt.Unix()
	}
	if !claims.IssuedAt.IsZero() {
		body[core.KeyIat] = claims.IssuedAt.Unix()
	}
	if !claims.NotBefore.IsZero() {
		body[core.KeyNbf] = claims.NotBefore.Unix()
	}
	if len(claims.Audience) > 0 {
		body[core.KeyAud] = claims.Audience
	}
	// RFC 9068 §2.2 supplies a first-class `client_id` claim. Prefer
	// it; fall back to the first audience entry for older tokens or
	// non-RFC-9068 issuers (per RFC 7662 §2.2 the field is optional).
	switch {
	case claims.ClientID != "":
		body[core.KeyClientID] = claims.ClientID
	case len(claims.Audience) > 0:
		body[core.KeyClientID] = claims.Audience[0]
	}
	if len(claims.Scopes) > 0 {
		body[core.KeyScope] = strings.Join(claims.Scopes, " ")
	}
	// RFC 9068 §2.2 jti — useful for replay tracking on the
	// introspecting resource server. Same goes for auth_time / acr / amr /
	// sid which let downstream policy reason about authentication + session.
	if claims.JTI != "" {
		body[core.KeyJTI] = claims.JTI
	}
	if !claims.AuthTime.IsZero() {
		body[core.KeyAuthTime] = claims.AuthTime.Unix()
	}
	if claims.ACR != "" {
		body[core.KeyACR] = claims.ACR
	}
	if len(claims.AMR) > 0 {
		body[core.KeyAMR] = claims.AMR
	}
	// SID (session id) lets the introspection consumer correlate this
	// token with the SSO session that authenticated it.
	populateIntrospectionSID(body, claims)
	// RFC 7662 §2.2: echo the sender-constraint confirmation.
	populateIntrospectionConfirmation(body, claims)
	// Mint-region provenance: the region that ISSUED the token (not the
	// calling RS's) — the RS gate reads it for region-constrained
	// deployments.
	populateIntrospectionServingRegion(body, claims)
}

// introspectSessionActive checks whether the session identified by claims.SID
// is still active. Oracle-safe: all failures (store error, not-found,
// expired, revoked) collapse to inactive so the caller returns
// {active:false} with no detail leak -- the same fail-closed contract
// MeshAuthorize's meshCheckSession (interfaces/sso/mesh_authz.go) applies to
// the identical signal. This matters in practice, not just in principle:
// every built-in SessionManager.Get (memory/redis/sqlite/postgres) already
// collapses missing, revoked, AND expired into core.ErrSessionNotFound --
// none of them return a populated Session with Revoked/expired fields set --
// so a fail-OPEN "err != nil -> active" would make the destroy/revoke path
// (the primary reason this check exists) a silent no-op. A nil
// SessionManager (unwired) skips the check entirely, same as a token with no
// sid.
func introspectSessionActive(d IntrospectDeps, ctx core.HandlerContext, claims *core.TokenClaims) bool {
	sm := d.SessionManager()
	if sm == nil {
		return true // unwired = skip check, same as no SID
	}
	sess, err := sm.Get(ctx.Request().Context(), claims.SID)
	if err != nil || sess == nil || sess.IsExpired() || sess.Revoked {
		return false
	}
	return true
}
