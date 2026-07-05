package tokengrant

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/internal/handler"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
)

// RefreshGrantDeps is what HandleRefreshGrant needs. *sso.Server satisfies it
// via accessors_token_grant.go with a compile-time guard there. The refresh
// grant issues no id_token (so it needs no oidc), but it lives here with the
// rest of the token-grant family for cohesion (and it shares RefreshGraceCache,
// which already lives in this package).
type RefreshGrantDeps interface {
	RefreshTokenStore() oauth.RefreshTokenStore
	RefreshGrace() RefreshGraceStore
	SessionManager() core.SessionManager
	IssuerForClient(c *core.Client) (string, core.TokenIssuer, error)
	ApplyPairwiseSubject(ctx context.Context, client *core.Client, localSub string) string
	IssueRefreshToken(ctx context.Context, userID, clientID, provider string, scopes []string, attributes map[string]string, familyID string, resources []string, authDetails []byte, sid string, authCtx oauth.RefreshAuthContext, clientTTLOverride time.Duration, confirmationJKT string) (string, error)
	DPoPTokenTypeOr(defaultType, jkt string) string
	RecordTokenIssued(ctx core.HandlerContext, clientID, strategy, subjectID string)
	RecordRefreshTokenIssued(ctx core.HandlerContext, clientID, subjectID string, rotation bool)
	RecordSubjectClientAccess(ctx context.Context, subject, clientID string)
	RecordRefreshTokenReuse(ctx core.HandlerContext, clientID, familyID string, killed int)
	RecordRefreshRotationVelocity(ctx core.HandlerContext, clientID, familyID string, count, killed int)
	IncRefreshRotationVelocityExceeded()
	LogErrorCtx(ctx core.HandlerContext, msg string, kv ...any)
	// EnforceRefreshDepthPolicy runs the wired token-policy engine's
	// max_refresh_depth dimension against the family's current rotation depth.
	// It writes the ORACLE-SAFE generic invalid_grant (the specific reason lands
	// only in the metric + server log) and returns true when the cap is hit so
	// the caller returns immediately. Byte-identical no-op (returns false) when
	// no token-policy store is wired — the default-off contract.
	EnforceRefreshDepthPolicy(ctx core.HandlerContext, clientID, subject string, scopes []string, depth int) bool
	// RefreshAbsoluteMaxLifetime returns the configured hard ceiling on a
	// refresh-token family's total age since original issuance (0 = disabled,
	// the default-off contract — see refreshEnforceAbsoluteMaxLifetime).
	RefreshAbsoluteMaxLifetime() time.Duration
}

// HandleRefreshGrant processes the RFC 6749 §6 refresh_token grant. Behavior is
// byte-identical to the prior root handler.
//
// Refresh-family security (AGENTS.md §3, OAuth Security BCP §4.13): the token is
// single-use (Consume deletes it). A previously-consumed token presented again
// is a reuse signal — the WHOLE family (every sibling + descendant) is killed via
// DeleteFamily before returning, FAIL-CLOSED. A benign concurrent double-submit
// within the grace window replays the same successor (idempotent) instead of
// tripping the kill. The optional rotation-velocity cap kills the family on a
// breach but FAILS-OPEN on a limiter-store error. Unknown / expired / consumed /
// reused / velocity-exceeded / scope-expansion ALL collapse to 400 invalid_grant
// (oracle-leak collapse) — only a scope that is not a subset returns the distinct
// invalid_scope (not a credential oracle).
//
// RFC 9068: a rotation does NOT reset auth_time and preserves the original AMR —
// the underlying authentication event is the original login, not this exchange.
func HandleRefreshGrant(d RefreshGrantDeps, ctx core.HandlerContext, client *core.Client, refreshToken, scope, dpopJKT, mtlsX5T string) {
	store := d.RefreshTokenStore()
	if store == nil {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrRefreshTokenNotConfigured))
		return
	}
	if refreshToken == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	info, err := store.Consume(ctx.Request().Context(), refreshToken)
	if err != nil {
		if refreshHandleConsumeError(d, ctx, client, store, refreshToken, info, err) {
			return
		}
		// Unknown / expired / already-consumed all map to invalid_grant
		// per RFC 6749 §5.2 — clients can't distinguish, by design.
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return
	}
	if refreshBindGuard(ctx, client, info, dpopJKT) {
		return
	}
	if refreshEnforceAbsoluteMaxLifetime(d, ctx, info) {
		return
	}
	// Session liveness check (§2): when the refresh token carries a SID
	// and a SessionManager is wired, verify the parent session is still
	// alive. Session gone / expired / revoked → 400 invalid_grant. A
	// store error is treated as "session not found" (fail-closed) — see
	// the refreshCheckSessionLiveness contract.
	if refreshCheckSessionLiveness(d, ctx, info) {
		return
	}
	grantScopes, ok := refreshResolveScopes(ctx, info, scope)
	if !ok {
		return
	}
	// Token-policy max_refresh_depth (opt-in, no-op unwired): deny once the
	// family's rotation depth (info.Generation) reaches the cap — same
	// invalid_grant collapse as every other refresh failure (oracle-leak).
	if d.EnforceRefreshDepthPolicy(ctx, client.ID, info.UserID, grantScopes, info.Generation) {
		return
	}
	if refreshVelocityGate(d, ctx, client, store, info.FamilyID) {
		return
	}
	refreshIssueAndRotate(d, ctx, client, info, refreshToken, grantScopes, dpopJKT, mtlsX5T)
}

// refreshBindGuard enforces RFC 6749 §6 client binding and RFC 9449 §5 DPoP
// key binding on the consumed token: the exchanging client MUST match the one
// the token was issued to, and a DPoP-bound token MUST be presented with the
// SAME key (a stolen refresh token can't be redeemed with an attacker-
// controlled key). Either mismatch collapses to 400 invalid_grant (oracle-leak).
// Returns true (response written) on a mismatch.
func refreshBindGuard(ctx core.HandlerContext, client *core.Client, info *oauth.RefreshToken, dpopJKT string) bool {
	if info.ClientID != client.ID {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return true
	}
	if info.ConfirmationJKT != "" && dpopJKT != info.ConfirmationJKT {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return true
	}
	return false
}

// refreshEnforceAbsoluteMaxLifetime enforces the OPTIONAL hard ceiling on a
// refresh-token FAMILY's total age since its original issuance
// (info.FamilyCreatedAt), independent of the per-rotation TTL/idle-expiry the
// store already enforces. It closes a gap the existing per-token TTL +
// rotation-velocity + reuse defenses don't cover: a family that keeps
// rotating legitimately (an active client refreshing on schedule) never
// re-triggers those, so absent this cap a single family could stay alive
// indefinitely. FAIL-CLOSED on a hit — the SAME invalid_grant wire shape as
// every other refresh failure (oracle-leak collapse, AGENTS.md §3), matching
// the family-reuse/rotation-velocity precedent in this file. A non-positive
// cap (disabled, the default) or a zero FamilyCreatedAt (a record minted
// before this field existed, or before the cap was ever configured) skip the
// check entirely — byte-identical to pre-feature behavior.
func refreshEnforceAbsoluteMaxLifetime(d RefreshGrantDeps, ctx core.HandlerContext, info *oauth.RefreshToken) bool {
	maxAge := d.RefreshAbsoluteMaxLifetime()
	if maxAge <= 0 || info.FamilyCreatedAt.IsZero() {
		return false
	}
	if time.Since(info.FamilyCreatedAt) <= maxAge {
		return false
	}
	ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
	return true
}

// refreshIssueAndRotate is the success tail (reached only after Consume, client
// bind, scope resolution and the velocity gate all pass): mint the access token,
// rotate the refresh token within the SAME family, record metrics, cache the
// successor for the double-submit grace window, and emit 200. Threading
// info.FamilyID into IssueRefreshToken keeps the new leaf in the family so future
// reuse anywhere in the chain is still detectable.
func refreshIssueAndRotate(d RefreshGrantDeps, ctx core.HandlerContext, client *core.Client, info *oauth.RefreshToken, refreshToken string, grantScopes []string, dpopJKT, mtlsX5T string) {
	strategy, ti, err := d.IssuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrNoTokenStrategy))
		return
	}
	issuedSub := d.ApplyPairwiseSubject(ctx.Request().Context(), client, info.UserID)
	subject := refreshRotatedSubject(client, info, issuedSub, dpopJKT, mtlsX5T)
	token, err := ti.Issue(ctx.Request().Context(), subject, grantScopes)
	if err != nil {
		d.LogErrorCtx(ctx, "token issuance failed", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	// Rotation: issue a NEW refresh token (the old one was deleted by Consume).
	// Pass info.FamilyID so the new leaf joins the same family — stores that track
	// families can detect any future reuse anywhere in the chain.
	newRefresh, err := refreshRotateFamily(d, ctx, client, info, grantScopes)
	if err != nil {
		d.LogErrorCtx(ctx, "refresh token rotation failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	d.RecordTokenIssued(ctx, client.ID, strategy, info.UserID)
	d.RecordRefreshTokenIssued(ctx, client.ID, info.UserID, true)
	d.RecordSubjectClientAccess(ctx.Request().Context(), info.UserID, client.ID)
	resp := map[string]any{
		core.KeyAccessToken:   token.AccessToken,
		core.KeyTokenType:     d.DPoPTokenTypeOr(token.TokenType, dpopJKT),
		core.KeyRefreshToken:  newRefresh,
		core.KeyExpiresIn:     token.ExpiresIn,
		core.KeyScope:         token.Scope,
		core.KeyTokenStrategy: strategy,
	}
	// Refresh double-submit grace: cache this successor keyed by the
	// just-consumed token so a benign concurrent re-presentation of the SAME
	// token replays it instead of tripping family-reuse (refresh_grace.go).
	if grace := d.RefreshGrace(); grace != nil {
		grace.Remember(refreshToken, resp, time.Now())
	}
	ctx.JSON(http.StatusOK, resp)
}

// refreshRotateFamily issues the rotated refresh token, threading the
// original auth context (RFC 9068 §2.2: AMR/ACR/AuthTime propagate
// UNCHANGED so the chain never down-trusts) and the family lineage fields —
// Generation is the one field that advances (parent+1, the max_refresh_depth
// input); FamilyCreatedAt propagates unchanged (the absolute-max-lifetime
// input). Extracted from refreshIssueAndRotate for the function-length budget.
func refreshRotateFamily(d RefreshGrantDeps, ctx core.HandlerContext, client *core.Client, info *oauth.RefreshToken, grantScopes []string) (string, error) {
	return d.IssueRefreshToken(ctx.Request().Context(),
		info.UserID, client.ID, info.Provider, grantScopes, info.Attributes, info.FamilyID, info.Resources,
		info.AuthorizationDetails, info.SID,
		oauth.RefreshAuthContext{
			AMR: info.Amr, ACR: info.Acr, AuthTime: info.AuthTime, Generation: info.Generation + 1,
			FamilyCreatedAt: info.FamilyCreatedAt,
		},
		client.RefreshTokenTTL, info.ConfirmationJKT) // RFC 9449: key binding propagates unchanged
}

// refreshRotatedSubject builds the Subject for a rotated access token. RFC 9068:
// a rotation does NOT reset auth_time and keeps the original AMR — the underlying
// authentication event is the original login, not this exchange.
func refreshRotatedSubject(client *core.Client, info *oauth.RefreshToken, issuedSub, dpopJKT, mtlsX5T string) *core.Subject {
	return &core.Subject{
		ID: issuedSub, Provider: info.Provider, Claims: info.Attributes,
		Resources: info.Resources,
		ClientID:  client.ID,
		// Refresh rotations don't reset auth_time per RFC 9068 — the underlying
		// authentication event is the original login, not the refresh exchange.
		// AMR/ACR/AuthTime are the ORIGINAL authentication event's, persisted on
		// the refresh record at issue and propagated unchanged through every
		// rotation. AmrOrProvider falls back to Provider only when the record
		// predates amr capture (empty Amr), reproducing the old behavior; a
		// resource server doing RFC 9470 step-up on amr/acr now sees the real
		// MFA context instead of a single-method down-trust.
		AMR:      handler.AmrOrProvider(info.Amr, info.Provider),
		ACR:      info.Acr,
		AuthTime: info.AuthTime,
		// RFC 9396: the authorization_details grant captured at the original
		// authorization survives the rotation — refreshed tokens MUST carry the
		// same fine-grained authorization the user already consented to.
		AuthorizationDetails: oauth.CloneRawJSON(info.AuthorizationDetails),
		// SID is locked to the original authorization's session — rotation never
		// opens a new session.
		SID:                 info.SID,
		TTL:                 client.AccessTokenTTL,
		ConfirmationJKT:     dpopJKT,
		ConfirmationX5TS256: mtlsX5T,
	}
}

// refreshHandleConsumeError handles a failed single-use Consume. It returns true
// ONLY when it has already written the response (the grace-window replay): the
// caller must then return without writing anything else. On the reuse path it
// kills the family (FAIL-CLOSED) but returns false so the caller emits the
// shared invalid_grant — keeping the wire shape byte-identical to the prior
// inline handler and the unknown/expired/consumed paths indistinguishable.
func refreshHandleConsumeError(d RefreshGrantDeps, ctx core.HandlerContext, client *core.Client, store oauth.RefreshTokenStore, refreshToken string, info *oauth.RefreshToken, err error) bool {
	// Refresh double-submit grace: if THIS token was rotated within the
	// grace window, replay the SAME successor it already produced —
	// idempotent, so a legitimate concurrent double-submit doesn't trip
	// the family-reuse kill below (a logout storm). A genuine post-window
	// replay finds no entry and falls through (BCP §4.13 unweakened).
	if grace := d.RefreshGrace(); grace != nil {
		if cached, ok := grace.Lookup(refreshToken, time.Now()); ok {
			ctx.JSON(http.StatusOK, cached)
			return true
		}
	}
	// OAuth Security BCP §4.13: a previously-consumed token presented again
	// is a reuse signal. Kill the whole family (every sibling and
	// descendant) before returning the wire error — an attacker who already
	// rotated after stealing the leaf loses access to the active descendant.
	if errors.Is(err, oauth.ErrRefreshTokenReused) && info != nil && info.FamilyID != "" {
		killed := 0
		if tracker, ok := store.(oauth.RefreshTokenFamilyTracker); ok {
			n, derr := tracker.DeleteFamily(ctx.Request().Context(), info.FamilyID)
			if derr != nil {
				d.LogErrorCtx(ctx, "family revocation on reuse failed",
					"error", derr, "family", info.FamilyID)
			} else {
				killed = n
				d.LogErrorCtx(ctx, "refresh token reuse detected — family revoked",
					"family", info.FamilyID, "killed", killed,
					"client", client.ID)
			}
		}
		d.RecordRefreshTokenReuse(ctx, client.ID, info.FamilyID, killed)
	}
	return false
}

// refreshResolveScopes applies RFC 6749 §6 scope rules: omitted scope keeps the
// original; a supplied scope MUST be a subset of the original (narrowing allowed,
// expansion forbidden). On expansion it writes the DISTINCT invalid_scope (not a
// credential oracle) and returns ok=false.
func refreshResolveScopes(ctx core.HandlerContext, info *oauth.RefreshToken, scope string) (grantScopes []string, ok bool) {
	grantScopes = info.Scopes
	if scope != "" {
		requested := strings.Split(scope, " ")
		if !oauth.IsScopeSubset(requested, info.Scopes) {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))
			return nil, false
		}
		grantScopes = requested
	}
	return grantScopes, true
}

// refreshVelocityGate is the per-family rotation-VELOCITY cap (OPTIONAL
// hardening, opt-in via a store implementing oauth.RefreshTokenRotationLimiter).
// Runs AFTER the single-use Consume (so it counts a genuine rotation) and BEFORE
// any token is minted. On windowExceeded the family is compromised: kill it via
// the SAME DeleteFamily path family-reuse uses, then reject with the SAME
// invalid_grant wire shape (detail lives only in the audit event + metric) and
// return true (FAIL-CLOSED). FAIL-OPEN on a limiter store error: log + proceed
// (the cap is a defense layer, not a correctness gate). familyID == "" (tracking
// opted out) → no-op, returns false.
func refreshVelocityGate(d RefreshGrantDeps, ctx core.HandlerContext, client *core.Client, store oauth.RefreshTokenStore, familyID string) bool {
	limiter, ok := store.(oauth.RefreshTokenRotationLimiter)
	if !ok || familyID == "" {
		return false
	}
	count, exceeded, lerr := limiter.RecordRotation(ctx.Request().Context(), familyID)
	if lerr != nil {
		// Availability class (§2): a store error must not block a legitimate
		// refresh, and must NOT kill the family.
		d.LogErrorCtx(ctx, "refresh rotation velocity check failed — proceeding (fail-open)",
			"error", lerr, "family", familyID, "client", client.ID)
		return false
	}
	if !exceeded {
		return false
	}
	killed := 0
	if tracker, ok := store.(oauth.RefreshTokenFamilyTracker); ok {
		n, derr := tracker.DeleteFamily(ctx.Request().Context(), familyID)
		if derr != nil {
			d.LogErrorCtx(ctx, "family revocation on rotation-velocity breach failed",
				"error", derr, "family", familyID)
		} else {
			killed = n
			d.LogErrorCtx(ctx, "refresh rotation velocity exceeded — family revoked",
				"family", familyID, "count", count, "killed", killed,
				"client", client.ID)
		}
	}
	d.IncRefreshRotationVelocityExceeded()
	d.RecordRefreshRotationVelocity(ctx, client.ID, familyID, count, killed)
	// Same wire shape as a reuse / bad refresh — oracle-leak collapse (§2).
	ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
	return true
}

// refreshCheckSessionLiveness checks whether the parent session behind the
// refresh token's SID is still alive. Returns true when the check failed and
// the caller must return (response already written). Contract:
//
//   - info.SID == "" → no-op (returns false)
//   - SessionManager not wired → no-op (returns false)
//   - sm.Get() error → LOG + treat as "session not found" → fail-closed
//   - session nil / expired / revoked → 400 invalid_grant (oracle-leak collapse)
func refreshCheckSessionLiveness(d RefreshGrantDeps, ctx core.HandlerContext, info *oauth.RefreshToken) bool {
	if info.SID == "" {
		return false
	}
	sm := d.SessionManager()
	if sm == nil {
		return false
	}
	sess, sErr := sm.Get(ctx.Request().Context(), info.SID)
	if sErr != nil {
		d.LogErrorCtx(ctx, "session liveness check failed (fail-closed)",
			"sid", info.SID, "error", sErr)
	} else if sess != nil && !sess.IsExpired() && !sess.Revoked {
		return false
	}
	d.LogErrorCtx(ctx, "session expired or revoked — refresh denied",
		"sid", info.SID, "user_id", info.UserID)
	ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
	return true
}
