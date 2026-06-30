package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/snaplink/sso/shared/core"
)

// SubjectRefreshRevoker is the narrow capability HandleEndSession needs from the
// refresh-token store: wipe every refresh token a subject holds for a client.
// Declared consumer-side (here, not in oauth) so oidc need not import oauth — the
// root's oauth.RefreshTokenSubjectIndex satisfies it structurally.
type SubjectRefreshRevoker interface {
	DeleteAllForSubject(ctx context.Context, userID, clientID string) (int, error)
}

// EndSessionDeps is what HandleEndSession needs. *sso.Server
// satisfies it via accessor methods.
type EndSessionDeps interface {
	ClientStoreAccessor() core.ClientStore
	SubjectRefreshRevoker() SubjectRefreshRevoker
	ValidateAnyToken(ctx context.Context, token string) (*core.TokenClaims, string, error)
	ResolveLocalSubject(ctx context.Context, sub string) (string, error)
	RevokeAcrossIssuers(ctx context.Context, token string) (revoked, failed []string)
	AuditPartialRevokeFailure(ctx core.HandlerContext, revoked, failed []string)
	GatherFrontchannelLogoutIframes(ctx core.HandlerContext, subject string, primary *core.Client, sid string) []string
	FanOutBackchannelLogout(ctx core.HandlerContext, originClient *core.Client, subject, sid string)
	RenderFrontchannelLogout(ctx core.HandlerContext, iframeURIs []string, redirectURI string)
	RecordLogout(ctx core.HandlerContext, sessionID string, revoked []string)
	// DestroySession kills the server-side SSO session by its `sid` claim so
	// the session cookie cannot be reused after RP-Initiated Logout. nil
	// implementations (no session manager wired) are acceptable — the method
	// is called only when sid is non-empty.
	DestroySession(ctx context.Context, sessionID string) error
}

// HandleEndSession implements OpenID Connect RP-Initiated Logout 1.0.
// Unlike POST /logout (a session-scoped bearer-authenticated kill
// switch), this is a GET endpoint a relying party can redirect the
// user agent to so the SSO server logs the user out and then sends
// them back to the RP's post-logout page.
//
// Query parameters (per the spec §2):
//
//   - id_token_hint            REQUIRED to identify the user — a
//     previously-issued id_token. The server validates the signature
//     and uses the token's aud claim to look up the client.
//   - post_logout_redirect_uri Optional; MUST be in the client's
//     PostLogoutRedirectURIs allowlist.
//   - state                    Optional; echoed back on the redirect.
//   - client_id                Optional fallback when id_token_hint
//     is absent — used only for redirect-uri allowlist lookup, NOT
//     for session termination.
//
// Behavior:
//
//   - Always best-effort revokes the access token derived from the
//     id_token_hint (so a stolen id_token_hint can't be used to just
//     bounce the user without invalidating their session).
//   - When post_logout_redirect_uri is in the allowlist, returns 302
//     with Location pointing at the redirect_uri (+ state when
//     supplied).
//   - When the redirect_uri is missing or rejected, returns 204 —
//     the session is dead, but we don't open a redirect-vector for
//     callers without a registered URL.
//
// Security:
//
//   - id_token_hint signature MUST verify against the server's wired
//     token issuers (we treat ID tokens and access tokens as signed
//     by the same key pair).
//   - post_logout_redirect_uri MUST exact-match (no path tolerance,
//     no scheme-only match) — phishing defense per §3.
func HandleEndSession(d EndSessionDeps, ctx core.HandlerContext) {
	q := ctx.Request().URL.Query()
	idTokenHint := strings.TrimSpace(q.Get("id_token_hint"))
	postLogoutURI := strings.TrimSpace(q.Get("post_logout_redirect_uri"))
	state := q.Get("state")
	clientIDHint := strings.TrimSpace(q.Get("client_id"))

	client, userID, sid, handled := resolveEndSessionClient(d, ctx, idTokenHint, clientIDHint)
	if handled {
		return // a bad id_token_hint already wrote 400 invalid_token.
	}

	// Destroy the server-side SSO session so the browser's session cookie
	// cannot be replayed after logout. Must happen before token revocation
	// so the session is invalid even if the access-token revoke partially
	// fails. Fail-open: a store error is logged by the implementation.
	if sid != "" {
		_ = d.DestroySession(ctx.Request().Context(), sid)
	}

	revokeEndSessionTokens(d, ctx, idTokenHint, userID, client)
	fclIframes := endSessionNotifyPeers(d, ctx, userID, client, sid)
	target := composePostLogoutTarget(postLogoutURI, state, client)

	// Front-Channel Logout — render the hidden-iframe page (with a
	// meta-refresh to target when allowlisted) using the pre-BCL snapshot.
	if len(fclIframes) > 0 {
		d.RenderFrontchannelLogout(ctx, fclIframes, target)
		return
	}

	// Redirect ONLY to an allowlisted URI (phishing defense per §3);
	// otherwise 204 — session killed, nothing safe to render.
	if target != "" {
		ctx.Redirect(http.StatusFound, target)
		return
	}
	ctx.ResponseWriter().WriteHeader(http.StatusNoContent)
}

// resolveEndSessionClient validates the id_token_hint (best-effort: a bad
// signature is a phishing attempt, so we MUST NOT honor a post_logout_redirect_uri
// tied to its claimed audience) and resolves the client/userID/sid. Its ONLY
// early-return is the 400 invalid_token, signalled via handled=true. With only a
// client_id hint (no signed identity) it resolves the client for redirect-uri
// validation but returns no userID, so no session is terminated.
func resolveEndSessionClient(d EndSessionDeps, ctx core.HandlerContext, idTokenHint, clientIDHint string) (client *core.Client, userID, sid string, handled bool) {
	clientStore := d.ClientStoreAccessor()
	if idTokenHint != "" {
		claims, _, err := d.ValidateAnyToken(ctx.Request().Context(), idTokenHint)
		if err != nil || claims == nil {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidToken))
			return nil, "", "", true
		}
		userID = claims.Subject
		// OIDC §8 pairwise: translate the per-sector sub back to the local one.
		if local, perr := d.ResolveLocalSubject(ctx.Request().Context(), userID); perr == nil {
			userID = local
		}
		sid = claims.SID
		// RFC 9068 client_id claim, or fall back to first audience (pre-9068) —
		// matches handleLogout so the two logout endpoints behave consistently.
		clientLookupID := claims.ClientID
		if clientLookupID == "" && len(claims.Audience) > 0 {
			clientLookupID = claims.Audience[0]
		}
		if clientLookupID != "" && clientStore != nil {
			if c, err := clientStore.Get(ctx.Request().Context(), clientLookupID); err == nil {
				client = c
			}
		}
		return client, userID, sid, false
	}
	if clientIDHint != "" && clientStore != nil {
		if c, err := clientStore.Get(ctx.Request().Context(), clientIDHint); err == nil {
			client = c
		}
	}
	return client, "", "", false
}

// endSessionNotifyPeers gathers FCL iframes FIRST (BCL's SubjectClientIndex
// housekeeping can trim FCL-only clients if called before the snapshot), then
// fans out BCL notifications, and records the logout audit event. Returns the
// FCL iframe list for the caller to render after the redirect target is known.
func endSessionNotifyPeers(d EndSessionDeps, ctx core.HandlerContext, userID string, client *core.Client, sid string) []string {
	var fclIframes []string
	if userID != "" {
		fclIframes = d.GatherFrontchannelLogoutIframes(ctx, userID, client, sid)
	}
	if userID != "" && client != nil {
		d.FanOutBackchannelLogout(ctx, client, userID, sid)
	}
	if userID != "" {
		d.RecordLogout(ctx, "", []string{"id_token_hint"})
	}
	return fclIframes
}

// revokeEndSessionTokens kills the id_token_hint's access-side counterpart (so a
// stolen id_token_hint can't be a soft-logout leaving the access token alive)
// and wipes the user's refresh tokens for the client so rotations can't outlive
// the logout. Both are best-effort.
func revokeEndSessionTokens(d EndSessionDeps, ctx core.HandlerContext, idTokenHint, userID string, client *core.Client) {
	if idTokenHint != "" {
		revoked, failed := d.RevokeAcrossIssuers(ctx.Request().Context(), idTokenHint)
		d.AuditPartialRevokeFailure(ctx, revoked, failed)
	}
	if userID != "" && client != nil {
		if idx := d.SubjectRefreshRevoker(); idx != nil {
			_, _ = idx.DeleteAllForSubject(ctx.Request().Context(), userID, client.ID)
		}
	}
}

// composePostLogoutTarget returns the redirect destination ONLY when the URI
// exact-matches the client's allowlist (no path tolerance — phishing defense per
// §3), with state appended when supplied; otherwise the empty string. Shared by
// both the FCL HTML page and the legacy 302 path so the defense is uniform.
func composePostLogoutTarget(postLogoutURI, state string, client *core.Client) string {
	if postLogoutURI == "" || client == nil || !client.IsPostLogoutRedirectURIValid(postLogoutURI) {
		return ""
	}
	target := postLogoutURI
	if state != "" {
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		target = target + sep + "state=" + url.QueryEscape(state)
	}
	return target
}
