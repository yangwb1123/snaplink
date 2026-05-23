package sso

import "github.com/snaplink/sso/oauth"

import (
	"net/http"
	"net/url"
	"strings"
)

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
func (s *Server) handleEndSession(ctx HandlerContext) {
	q := ctx.Request().URL.Query()
	idTokenHint := strings.TrimSpace(q.Get("id_token_hint"))
	postLogoutURI := strings.TrimSpace(q.Get("post_logout_redirect_uri"))
	state := q.Get("state")
	clientIDHint := strings.TrimSpace(q.Get("client_id"))

	var (
		client *Client
		userID string
		sid    string
	)

	if idTokenHint != "" {
		// Best-effort verification: an id_token_hint with a bad
		// signature is a phishing attempt; we MUST not honor any
		// post_logout_redirect_uri tied to its claimed audience.
		claims, _, err := s.validateAnyToken(ctx.Request().Context(), idTokenHint)
		if err != nil || claims == nil {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidToken))
			return
		}
		userID = claims.Subject
		// OIDC §8 pairwise: translate the per-sector sub back to the
		// local one so downstream session bookkeeping finds the
		// right user. Non-pairwise deployments no-op.
		if local, perr := s.resolveLocalSubject(ctx.Request().Context(), userID); perr == nil {
			userID = local
		}
		sid = claims.SID
		// Resolve the client by RFC 9068 client_id claim (preferred,
		// first-class) or fall back to the first audience entry (the
		// pre-9068 heuristic) — matches handleLogout's lookup so
		// behavior is consistent across the two logout endpoints.
		clientLookupID := claims.ClientID
		if clientLookupID == "" && len(claims.Audience) > 0 {
			clientLookupID = claims.Audience[0]
		}
		if clientLookupID != "" && s.clientStore != nil {
			if c, err := s.clientStore.Get(ctx.Request().Context(), clientLookupID); err == nil {
				client = c
			}
		}
	} else if clientIDHint != "" && s.clientStore != nil {
		// Spec allows client_id without id_token_hint, but without
		// a signed user identity we won't revoke any session — we
		// only use the client to validate the redirect uri.
		if c, err := s.clientStore.Get(ctx.Request().Context(), clientIDHint); err == nil {
			client = c
		}
	}

	// Kill the presented id_token's access-side counterpart so a
	// stolen id_token_hint can't be used as a soft-logout that
	// leaves the access token alive until expiry.
	if idTokenHint != "" {
		revoked, failed := s.revokeAcrossIssuers(ctx.Request().Context(), idTokenHint)
		s.auditPartialRevokeFailure(ctx, revoked, failed)
	}
	// Wipe every refresh token the user holds for the client in
	// scope, so descendant rotations can't outlive the logout.
	if userID != "" && client != nil {
		if idx, ok := s.refreshTokenStore.(oauth.RefreshTokenSubjectIndex); ok {
			_, _ = idx.DeleteAllForSubject(ctx.Request().Context(), userID, client.ID)
		}
	}

	// Capture FCL fan-out targets BEFORE the BCL fan-out runs.
	// BCL's Forget-on-non-BCL behavior trims the security.SubjectClientIndex
	// of clients without a BackchannelLogoutURI; if FCL gathered
	// AFTER, those FCL-only peers would be missing from the index
	// by the time we walked it and silently dropped from the
	// iframe list. Render happens later — this just snapshots the
	// targets while the index is still complete.
	var fclIframes []string
	if userID != "" {
		fclIframes = s.gatherFrontchannelLogoutIframes(ctx, userID, client, sid)
	}

	// OIDC Back-Channel Logout 1.0 — mirror of the /logout
	// behavior. When the user logs out via the redirect-style
	// /end_session, the RP whose id_token_hint was presented
	// should also be notified via back-channel so its local
	// session can be torn down. No-op when BCL isn't wired or
	// the client doesn't declare a backchannel_logout_uri.
	if userID != "" && client != nil {
		s.fanOutBackchannelLogout(ctx, client, userID, sid)
	}

	if userID != "" {
		s.recordLogout(ctx, "", []string{"id_token_hint"})
	}

	// Resolve a safe redirect destination once — both the FCL HTML
	// page and the legacy 302 path want the same allowlist + state
	// composition; computing it in one place keeps phishing defense
	// uniform across the two response shapes.
	var target string
	if postLogoutURI != "" && client != nil && client.IsPostLogoutRedirectURIValid(postLogoutURI) {
		target = postLogoutURI
		if state != "" {
			sep := "?"
			if strings.Contains(target, "?") {
				sep = "&"
			}
			target = target + sep + "state=" + url.QueryEscape(state)
		}
	}

	// OIDC Front-Channel Logout 1.0 — when any client (the primary
	// from id_token_hint, or any other the subject is signed into
	// via the security.SubjectClientIndex) opts in via FrontchannelLogoutURI,
	// render an HTML page with one hidden iframe per such client.
	// The browser fires each iframe request (clearing RP cookies);
	// a meta-refresh then navigates to post_logout_redirect_uri if
	// one was allowlisted. FCL is purely additive to the
	// revoke/BCL pipeline above — those still ran. Iframe targets
	// were snapshotted above before BCL pruned the index.
	if len(fclIframes) > 0 {
		s.renderFrontchannelLogout(ctx, fclIframes, target)
		return
	}

	// Redirect ONLY if the client allowlists the URI. Phishing
	// defense: an attacker who crafts an end_session URL with
	// post_logout_redirect_uri=https://evil.example MUST not get
	// the user bounced there.
	if target != "" {
		ctx.Redirect(http.StatusFound, target)
		return
	}

	// Session killed, but no safe redirect destination. 204 is the
	// OIDC convention for "we did the work, nothing to render".
	ctx.ResponseWriter().WriteHeader(http.StatusNoContent)
}
