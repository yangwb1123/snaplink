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
