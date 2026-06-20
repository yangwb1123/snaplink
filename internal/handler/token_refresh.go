package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

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
	RefreshGrace() *RefreshGraceCache
	IssuerForClient(c *core.Client) (string, core.TokenIssuer, error)
	ApplyPairwiseSubject(ctx context.Context, client *core.Client, localSub string) string
	IssueRefreshToken(ctx context.Context, userID, clientID, provider string, scopes []string, attributes map[string]string, familyID string, resources []string, authDetails []byte, sid string, clientTTLOverride time.Duration) (string, error)
	RecordTokenIssued(ctx core.HandlerContext, clientID, strategy, subjectID string)
	RecordRefreshTokenIssued(ctx core.HandlerContext, clientID, subjectID string, rotation bool)
	RecordSubjectClientAccess(ctx context.Context, subject, clientID string)
	RecordRefreshTokenReuse(ctx core.HandlerContext, clientID, familyID string, killed int)
	RecordRefreshRotationVelocity(ctx core.HandlerContext, clientID, familyID string, count, killed int)
	IncRefreshRotationVelocityExceeded()
	LogErrorCtx(ctx core.HandlerContext, msg string, kv ...any)
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
		// Refresh double-submit grace: if THIS token was rotated within the
		// grace window, replay the SAME successor it already produced —
		// idempotent, so a legitimate concurrent double-submit doesn't trip
		// the family-reuse kill below (a logout storm). A genuine post-window
		// replay finds no entry and falls through (BCP §4.13 unweakened).
		if grace := d.RefreshGrace(); grace != nil {
			if cached, ok := grace.Lookup(refreshToken, time.Now()); ok {
				ctx.JSON(http.StatusOK, cached)
				return
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
		// Unknown / expired / already-consumed all map to invalid_grant
		// per RFC 6749 §5.2 — clients can't distinguish, by design.
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return
	}
	// Bind the token to the client that's exchanging it (RFC 6749 §6).
	if info.ClientID != client.ID {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return
	}
	// Scope rules per RFC 6749 §6: omitted scope = keep original; supplied scope
	// MUST be a subset of the original (narrowing allowed, expansion forbidden).
	grantScopes := info.Scopes
	if scope != "" {
		requested := strings.Split(scope, " ")
		if !oauth.IsScopeSubset(requested, info.Scopes) {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))
			return
		}
		grantScopes = requested
	}
	// Per-family rotation-VELOCITY cap (OPTIONAL hardening, opt-in via a store
	// implementing oauth.RefreshTokenRotationLimiter). Runs AFTER the single-use
	// Consume (so it counts a genuine rotation) and BEFORE any token is minted.
	// On windowExceeded the family is compromised: kill it via the SAME
	// DeleteFamily path family-reuse uses, then reject with the SAME invalid_grant
	// wire shape (detail lives only in the audit event + metric). FAIL-OPEN on a
	// limiter store error: log + proceed (the cap is a defense layer, not a
	// correctness gate). info.FamilyID == "" (tracking opted out) → no-op.
	if limiter, ok := store.(oauth.RefreshTokenRotationLimiter); ok && info.FamilyID != "" {
		count, exceeded, lerr := limiter.RecordRotation(ctx.Request().Context(), info.FamilyID)
		if lerr != nil {
			// Availability class (§2): a store error must not block a legitimate
			// refresh, and must NOT kill the family.
			d.LogErrorCtx(ctx, "refresh rotation velocity check failed — proceeding (fail-open)",
				"error", lerr, "family", info.FamilyID, "client", client.ID)
		} else if exceeded {
			killed := 0
			if tracker, ok := store.(oauth.RefreshTokenFamilyTracker); ok {
				n, derr := tracker.DeleteFamily(ctx.Request().Context(), info.FamilyID)
				if derr != nil {
					d.LogErrorCtx(ctx, "family revocation on rotation-velocity breach failed",
						"error", derr, "family", info.FamilyID)
				} else {
					killed = n
					d.LogErrorCtx(ctx, "refresh rotation velocity exceeded — family revoked",
						"family", info.FamilyID, "count", count, "killed", killed,
						"client", client.ID)
				}
			}
			d.IncRefreshRotationVelocityExceeded()
			d.RecordRefreshRotationVelocity(ctx, client.ID, info.FamilyID, count, killed)
			// Same wire shape as a reuse / bad refresh — oracle-leak collapse (§2).
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
			return
		}
	}
	strategy, ti, err := d.IssuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrNoTokenStrategy))
		return
	}
	issuedSub := d.ApplyPairwiseSubject(ctx.Request().Context(), client, info.UserID)
	token, err := ti.Issue(ctx.Request().Context(), &core.Subject{
		ID: issuedSub, Provider: info.Provider, Claims: info.Attributes,
		Resources: info.Resources,
		ClientID:  client.ID,
		// Refresh rotations don't reset auth_time per RFC 9068 — the underlying
		// authentication event is the original login, not the refresh exchange.
		// AMR likewise stays the original method.
		AMR: []string{info.Provider},
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
	}, grantScopes)
	if err != nil {
		d.LogErrorCtx(ctx, "token issuance failed", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	// Rotation: issue a NEW refresh token (the old one was deleted by Consume).
	// Pass info.FamilyID so the new leaf joins the same family — stores that track
	// families can detect any future reuse anywhere in the chain.
	newRefresh, err := d.IssueRefreshToken(ctx.Request().Context(),
		info.UserID, client.ID, info.Provider, grantScopes, info.Attributes, info.FamilyID, info.Resources,
		info.AuthorizationDetails, info.SID, client.RefreshTokenTTL)
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
		core.KeyTokenType:     token.TokenType,
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
