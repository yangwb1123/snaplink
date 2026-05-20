package sso

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// OIDC Back-Channel Logout 1.0.
//
// When a user logs out of the SSO server (via POST /logout or
// GET /end_session), every relying party that the user has an
// active session with should also tear down its local session
// — otherwise the user is "logged out of one app, still logged
// into N others". OIDC BCL closes that gap by having the AS
// POST a signed logout_token to each RP's registered
// `backchannel_logout_uri`. The RP verifies the token (it's a
// JWT signed by the same key serving the JWKS endpoint) and
// invalidates its session.
//
// Scope of THIS implementation:
//   - Single-RP notification: the client whose ID matches the
//     bearer token's aud / client_id claim. Multi-RP fan-out
//     (notify every RP the user is signed into) requires a
//     subject→clients index that is NOT in scope here — revisit
//     when the session store gains that pivot.
//   - sid claim NOT included. Per OIDC BCL §2.4 the sid claim
//     is REQUIRED only when the server supports session IDs;
//     this server does not yet stamp sid in access tokens, so
//     it's legitimately absent from logout tokens too.

// LogoutTokenIssuer mints OIDC Back-Channel Logout 1.0 §2.4
// logout tokens. Same signing key as the access-token issuer is
// the conventional and recommended setup so RPs verify with one
// JWKS entry.
type LogoutTokenIssuer interface {
	IssueLogoutToken(ctx context.Context, req *LogoutTokenRequest) (string, error)
}

// LogoutTokenRequest carries the issuance inputs. TTL falls
// back to a short default when zero — logout tokens are
// single-use and short-lived by nature (the RP processes one
// immediately on receipt).
type LogoutTokenRequest struct {
	Subject  string
	Audience string
	TTL      time.Duration

	// SID is the OIDC Back-Channel Logout 1.0 §2.4 session
	// identifier. When set, the issued logout_token carries a
	// `sid` claim — the RP uses it to invalidate the specific
	// session it received the matching id_token for, rather
	// than wiping every session for the subject. Empty omits
	// the claim (legacy/coarse behavior).
	SID string
}

// LogoutNotifier delivers a signed logout_token to the RP's
// backchannel_logout_uri per OIDC BCL §2.5. Implementations MUST
// respect the supplied context's deadline so the AS isn't
// blocked when an RP is slow or unreachable.
type LogoutNotifier interface {
	Notify(ctx context.Context, uri string, logoutToken string) error
}

// DefaultBackchannelLogoutTimeout caps an individual RP
// notification. Short on purpose — the user is waiting on the
// /logout response while this round-trips, and a slow RP must
// not delay the rest of the logout pipeline. A failure here is
// logged + audited but not fatal.
const DefaultBackchannelLogoutTimeout = 5 * time.Second

// HTTPLogoutNotifier is the production LogoutNotifier. POSTs
// `logout_token=<jwt>` as
// application/x-www-form-urlencoded per OIDC BCL §2.5.
type HTTPLogoutNotifier struct {
	Client *http.Client
}

// NewHTTPLogoutNotifier returns an HTTP notifier with a default
// 5s timeout. Callers may swap in a custom *http.Client to wire
// proxies, custom TLS roots, or tracing instrumentation.
func NewHTTPLogoutNotifier() *HTTPLogoutNotifier {
	return &HTTPLogoutNotifier{
		Client: &http.Client{Timeout: DefaultBackchannelLogoutTimeout},
	}
}

// Notify implements LogoutNotifier. Returns an error if the POST
// fails or the RP returns a non-2xx status — caller decides
// whether to retry or surface the failure to the user.
func (n *HTTPLogoutNotifier) Notify(ctx context.Context, uri string, logoutToken string) error {
	if uri == "" {
		return errors.New("backchannel_logout: empty uri")
	}
	form := url.Values{"logout_token": {logoutToken}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewReader([]byte(form)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "*/*")
	client := n.Client
	if client == nil {
		client = &http.Client{Timeout: DefaultBackchannelLogoutTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Drain the body up to a small cap so HTTP/1.1 connection reuse works
	// even when the RP sends a verbose error page; throw it away.
	_, _ = io.CopyN(io.Discard, resp.Body, 1<<14)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("backchannel_logout: non-2xx status %d from %s", resp.StatusCode, uri)
}

// sendBackchannelLogout fans out a logout notification for the
// given (subject, client). No-op when:
//   - The back-channel logout subsystem isn't wired
//     (logoutTokenIssuer + logoutNotifier MUST both be set).
//   - The client doesn't declare BackchannelLogoutURI.
//
// Failures are logged + audited but never block the parent
// /logout response — see the contract on LogoutNotifier.
func (s *Server) sendBackchannelLogout(ctx HandlerContext, client *Client, subject string, sid string) {
	if s.logoutTokenIssuer == nil || s.logoutNotifier == nil {
		return
	}
	if client == nil || client.BackchannelLogoutURI == "" {
		return
	}
	tokenCtx, cancel := context.WithTimeout(ctx.Request().Context(), DefaultBackchannelLogoutTimeout)
	defer cancel()
	logoutToken, err := s.logoutTokenIssuer.IssueLogoutToken(tokenCtx, &LogoutTokenRequest{
		Subject:  subject,
		Audience: client.ID,
		// OIDC BCL §2.4: `sid` lets the RP scope the logout to
		// the specific session it received the matching id_token
		// for. Empty when the inbound id_token_hint had no sid
		// claim (legacy tokens minted before sid plumbing).
		SID: sid,
	})
	if err != nil {
		s.logger.Error("backchannel logout: issue token failed",
			"error", err, "client", client.ID, "subject", subject)
		s.recordLogoutNotifyFailure(ctx, client.ID, subject, err.Error())
		return
	}
	if err := s.logoutNotifier.Notify(tokenCtx, client.BackchannelLogoutURI, logoutToken); err != nil {
		s.logger.Error("backchannel logout: notify failed",
			"error", err, "client", client.ID, "uri", client.BackchannelLogoutURI)
		s.recordLogoutNotifyFailure(ctx, client.ID, subject, err.Error())
		return
	}
	s.recordLogoutNotifySuccess(ctx, client.ID, subject, client.BackchannelLogoutURI)
}

// recordSubjectClientAccess stamps the (subject, clientID) pair into
// the SubjectClientIndex so multi-RP back-channel logout fan-out can
// reach this client later. No-op when the index isn't wired or
// either id is empty (client_credentials passes empty subject in
// some paths; just skip the bookkeeping write). Failures are logged
// but never block the calling flow — the index is a UX optimization,
// not a correctness gate.
func (s *Server) recordSubjectClientAccess(ctx context.Context, subject, clientID string) {
	if s.subjectClientIndex == nil || subject == "" || clientID == "" {
		return
	}
	if err := s.subjectClientIndex.RecordAccess(ctx, subject, clientID); err != nil {
		s.logger.Error("subject_client_index: record access failed",
			"error", err, "subject", subject, "client", clientID)
	}
}

// fanOutBackchannelLogout drives the multi-RP variant of
// sendBackchannelLogout. When the SubjectClientIndex is wired, every
// client the subject has been seen with — not just the one the
// bearer / id_token_hint named — gets a logout_token POST. The
// triggering client (passed via `originClient`) is included in the
// fan-out set; callers SHOULD NOT additionally call
// sendBackchannelLogout for that client.
//
// Each successful notification calls Forget so a follow-up logout
// for the same subject doesn't re-notify a client that already
// processed its logout — keeps the index trim and prevents
// duplicate logout_token POSTs on subsequent (no-op) logouts.
//
// When the index isn't wired, falls back to the single-RP path
// behind sendBackchannelLogout against originClient.
func (s *Server) fanOutBackchannelLogout(ctx HandlerContext, originClient *Client, subject string, sid string) {
	if s.subjectClientIndex == nil {
		// Legacy single-RP behavior.
		s.sendBackchannelLogout(ctx, originClient, subject, sid)
		return
	}
	if subject == "" || s.clientStore == nil {
		return
	}
	clientIDs, err := s.subjectClientIndex.ListClients(ctx.Request().Context(), subject)
	if err != nil {
		s.logger.Error("subject_client_index: list failed", "error", err, "subject", subject)
		// Fall through to single-RP so the triggering client at least
		// hears about the logout when the index is degraded.
		s.sendBackchannelLogout(ctx, originClient, subject, sid)
		return
	}
	// Always include the origin client even if the index missed it
	// (e.g. the very first login on a new replica before propagation).
	seen := make(map[string]struct{}, len(clientIDs)+1)
	if originClient != nil {
		clientIDs = append(clientIDs, originClient.ID)
	}
	for _, cid := range clientIDs {
		if cid == "" {
			continue
		}
		if _, dup := seen[cid]; dup {
			continue
		}
		seen[cid] = struct{}{}
		c, err := s.clientStore.Get(ctx.Request().Context(), cid)
		if err != nil || c == nil || c.BackchannelLogoutURI == "" {
			// Either the client was deleted or it doesn't speak
			// BCL — either way, nothing to notify. Forget so the
			// index doesn't carry it forever.
			_ = s.subjectClientIndex.Forget(ctx.Request().Context(), subject, cid)
			continue
		}
		// Per-client sid filter: the cross-RP fan-out passes the
		// SAME sid value. RPs that don't recognize the sid will
		// fall back to subject-wide logout per BCL §2.4 — exactly
		// the desired soft-degradation.
		s.sendBackchannelLogout(ctx, c, subject, sid)
		_ = s.subjectClientIndex.Forget(ctx.Request().Context(), subject, cid)
	}
}
