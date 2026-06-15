package sso

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"github.com/snaplink/sso/oauth"

)

func (s *Server) handleRefreshTokenGrant(ctx HandlerContext, client *Client, refreshToken, scope, dpopJKT, mtlsX5T string) {
		if s.refreshTokenStore == nil {
			ctx.JSON(http.StatusNotImplemented, errorBody(ErrRefreshTokenNotConfigured))
			return
		}
		if refreshToken == "" {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
			return
		}
		info, err := s.refreshTokenStore.Consume(ctx.Request().Context(), refreshToken)
		if err != nil {
			// Refresh double-submit grace: if THIS token was rotated within the
			// grace window, replay the SAME successor it already produced —
			// idempotent, so a legitimate concurrent double-submit doesn't trip
			// the family-reuse kill below (a logout storm). A genuine post-window
			// replay finds no entry and falls through (BCP §4.13 unweakened).
			if s.refreshGrace != nil {
				if cached, ok := s.refreshGrace.Lookup(refreshToken, time.Now()); ok {
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
		if scope != "" {
			requested := strings.Split(scope, " ")
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
			s.refreshGrace.Remember(refreshToken, resp, time.Now())
		}
		ctx.JSON(http.StatusOK, resp)
}
