package sso

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
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
//   - Single-RP notification is the default; multi-RP fan-out
//     (notify every RP the user is signed into) engages when
//     [WithSubjectClientIndex] is wired — fanOutBackchannelLogout
//     walks the index for the subject and posts a logout_token to
//     every BCL-capable client.
//   - sid claim is included on the logout_token when the issuer
//     has a session id for the subject (Server-side SessionManager
//     populates one; the access-token issuer stamps it via the
//     RFC 9068 `sid` claim). Fan-out targets keep their original
//     sid when one is recorded; missing-sid targets omit the
//     claim per OIDC BCL §2.4.

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

// DefaultBackchannelLogoutMaxConcurrent caps the multi-RP fan-out
// parallelism so a user with 50+ active RPs doesn't have /end_session
// open 50 simultaneous outbound HTTP connections (which can starve
// the connection pool + exhaust ephemeral ports under burst). 8 is
// a conservative default that keeps p99 logout latency bounded at
// roughly `timeout × ceil(N / max)` instead of `timeout × N` in the
// serial path. Override with WithBackchannelLogoutMaxConcurrent.
const DefaultBackchannelLogoutMaxConcurrent = 8

// HTTPLogoutNotifier is the production LogoutNotifier. POSTs
// `logout_token=<jwt>` as
// application/x-www-form-urlencoded per OIDC BCL §2.5.
type HTTPLogoutNotifier struct {
	Client *http.Client
}

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
	defer func() { _ = resp.Body.Close() }()
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
// the security.SubjectClientIndex so multi-RP back-channel logout fan-out can
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
// sendBackchannelLogout. When the security.SubjectClientIndex is wired, every
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
	targets := s.collectBackchannelTargets(ctx, clientIDs, originClient, subject)
	if len(targets) == 0 {
		return
	}
	s.dispatchBackchannelFanOut(ctx, targets, subject, sid)
}

// collectBackchannelTargets deduplicates clientIDs (origin client
// appended first so it survives dedup), then filters to the
// BCL-capable subset. Filtering happens BEFORE worker spin-up so we
// know exactly how many to wait on and Forget calls for non-BCL
// clients fire immediately (no goroutine spin-up cost for them).
func (s *Server) collectBackchannelTargets(ctx HandlerContext, clientIDs []string, originClient *Client, subject string) []*Client {
	// Always include the origin client even if the index missed it
	// (e.g. the very first login on a new replica before propagation).
	seen := make(map[string]struct{}, len(clientIDs)+1)
	if originClient != nil {
		clientIDs = append(clientIDs, originClient.ID)
	}
	targets := make([]*Client, 0, len(clientIDs))
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
			// Client was deleted or doesn't speak BCL — Forget so the
			// index doesn't carry it forever; nothing else to do.
			_ = s.subjectClientIndex.Forget(ctx.Request().Context(), subject, cid)
			continue
		}
		targets = append(targets, c)
	}
	return targets
}

// dispatchBackchannelFanOut runs the bounded-concurrency worker pool
// over targets. Serial loop would stack each RP's
// `DefaultBackchannelLogoutTimeout` (5s default) linearly — a user
// with 10 RPs and one slow RP would block /end_session for 50s before
// unblocking. Bounded worker pool keeps p99 at roughly
// timeout × ceil(N / max) while avoiding the 50+-connection burst a
// naive unbounded goroutine-per-RP would emit. The Forget call follows
// the notification (success or failure) on the same worker — see
// sendBackchannelLogout for the audit recording contract.
func (s *Server) dispatchBackchannelFanOut(ctx HandlerContext, targets []*Client, subject string, sid string) {
	max := s.backchannelLogoutMaxConcurrent
	if max <= 0 {
		max = DefaultBackchannelLogoutMaxConcurrent
	}
	if max > len(targets) {
		max = len(targets)
	}
	work := make(chan *Client, len(targets))
	for _, c := range targets {
		work <- c
	}
	close(work)
	var wg sync.WaitGroup
	wg.Add(max)
	for i := 0; i < max; i++ {
		go func() {
			defer wg.Done()
			for c := range work {
				// Per-client sid filter: every fan-out RP gets the
				// SAME sid value. RPs that don't recognize the sid
				// fall back to subject-wide logout per BCL §2.4 —
				// exactly the desired soft-degradation.
				s.sendBackchannelLogout(ctx, c, subject, sid)
				_ = s.subjectClientIndex.Forget(ctx.Request().Context(), subject, c.ID)
			}
		}()
	}
	wg.Wait()
}

// OIDC Front-Channel Logout 1.0.
//
// When the user logs out via /end_session and one or more clients
// the subject is signed into expose a FrontchannelLogoutURI, the
// response body is an HTML page with a hidden iframe per such
// client. The browser loads each URI; the RPs respond by clearing
// their own session cookies. After a short delay the page redirects
// to post_logout_redirect_uri if one was supplied and allowlisted —
// the delay gives every iframe time to fire its request before the
// user agent navigates away.
//
// Multi-RP fan-out mirrors BCL: when [WithSubjectClientIndex] is
// wired, gatherFrontchannelLogoutIframes walks the index and emits
// one iframe per FCL-capable client the subject has logged into
// across the cluster. Without the index, only the primary client
// (the one matched by id_token_hint / client_id_hint) gets an
// iframe — the original single-RP behavior is preserved as a
// graceful fallback.
//
// Caveats:
//
//   - sid claim only on the primary iframe. Fan-out targets get an
//     empty sid because the AS doesn't keep per-(subject, client)
//     session IDs in the security.SubjectClientIndex; FCL §3 allows sid
//     omission when the AS doesn't have one for that target.
//   - Fire-and-forget: the AS has no signal whether the iframes
//     actually cleared the RPs' sessions. Matches BCL's fail-open
//     posture — logout completes regardless of RP cooperation.

// frontchannelLogoutTemplate renders the OIDC FCL 1.0 §3 HTML
// response. The two-second meta-refresh is the working compromise:
// long enough for the iframes to issue their requests, short enough
// that users don't perceive a hang. html/template auto-escapes
// every iframe `src` and the `.RedirectURI` in their respective
// attribute contexts — `src=` and `href=` are URL-safe, the
// meta-refresh `content=` is HTML-escaped. Operator-controlled
// inputs only, but escaping is belt-and-braces against future
// client-supplied values.
var frontchannelLogoutTemplate = template.Must(template.New("fcl").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Logout</title>
{{if .RedirectURI}}<meta http-equiv="refresh" content="2; url={{.RedirectURI}}">{{end}}
</head>
<body>
{{range .IframeURIs}}<iframe src="{{.}}" style="display:none" referrerpolicy="no-referrer" sandbox="allow-same-origin allow-scripts"></iframe>
{{end}}{{if .RedirectURI}}<p>You will be redirected to <a href="{{.RedirectURI}}">{{.RedirectURI}}</a> shortly.</p>{{end}}
</body>
</html>
`))

// frontchannelLogoutData is the template input. IframeURIs is a
// pre-composed slice (each URI already has sid+iss query params
// appended where applicable); the template only iterates.
type frontchannelLogoutData struct {
	IframeURIs  []string
	RedirectURI string
}

// renderFrontchannelLogout writes the FCL HTML response. Always
// 200 OK — the logout already happened by the time we render; the
// HTML page is the side-effect carrier, not the operation. X-Frame-
// Options: DENY prevents an attacker from embedding our /end_session
// response in their own iframe to trick users into involuntary
// logout (a low-impact but real clickjacking vector).
//
// iframeURIs are pre-composed by gatherFrontchannelLogoutIframes
// with sid + iss query params per OIDC Front-Channel Logout 1.0 §3
// — sid disambiguates the RP's concurrent sessions, iss helps
// multi-issuer RPs route the logout.
func (s *Server) renderFrontchannelLogout(ctx HandlerContext, iframeURIs []string, redirectURI string) {
	w := ctx.ResponseWriter()
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = frontchannelLogoutTemplate.Execute(w, frontchannelLogoutData{
		IframeURIs:  iframeURIs,
		RedirectURI: redirectURI,
	})
}

// gatherFrontchannelLogoutIframes returns the iframe URIs (with
// sid + iss query params appended) to render on the FCL page.
//
// The primary client — the one matched by id_token_hint /
// client_id_hint — comes first when it has a FrontchannelLogoutURI;
// it carries the sid from the inbound id_token so the RP can
// disambiguate which session to clear. When [WithSubjectClientIndex]
// is wired, every additional client the subject is logged into
// across the cluster contributes one more iframe (deduplicated;
// sorted for deterministic output). Fan-out targets get an empty
// sid — the AS doesn't keep per-(subject, client) session IDs in
// the index, and FCL §3 allows sid omission when the AS doesn't
// have one for that target.
//
// Returns an empty slice when no client has FCL configured; callers
// MUST check len(...) > 0 before deciding to render the HTML page
// (versus falling through to the 302 / 204 paths).
func (s *Server) gatherFrontchannelLogoutIframes(ctx HandlerContext, subject string, primary *Client, sid string) []string {
	iss := s.resolveIssuer(ctx)
	out := []string{}
	seen := map[string]bool{}
	if primary != nil && primary.FrontchannelLogoutURI != "" {
		out = append(out, appendFrontchannelLogoutSidIss(primary.FrontchannelLogoutURI, sid, iss))
		seen[primary.ID] = true
	}
	if s.subjectClientIndex == nil || subject == "" || s.clientStore == nil {
		return out
	}
	ids, err := s.subjectClientIndex.ListClients(ctx.Request().Context(), subject)
	if err != nil {
		s.logger.Error("subject_client_index: list failed (fcl fanout)", "error", err, "subject", subject)
		return out
	}
	sort.Strings(ids)
	for _, id := range ids {
		if seen[id] {
			continue
		}
		c, err := s.clientStore.Get(ctx.Request().Context(), id)
		if err != nil || c == nil || c.FrontchannelLogoutURI == "" {
			continue
		}
		out = append(out, appendFrontchannelLogoutSidIss(c.FrontchannelLogoutURI, "", iss))
		seen[id] = true
	}
	return out
}

// appendFrontchannelLogoutSidIss appends `sid` + `iss` query params
// to the iframe URI when present. Both empty = return URI unchanged.
// Preserves any pre-existing query string on the RP-registered URI.
func appendFrontchannelLogoutSidIss(uri, sid, iss string) string {
	if sid == "" && iss == "" {
		return uri
	}
	var params []string
	if sid != "" {
		params = append(params, "sid="+urlQueryEscape(sid))
	}
	if iss != "" {
		params = append(params, "iss="+urlQueryEscape(iss))
	}
	sep := "?"
	if strings.Contains(uri, "?") {
		sep = "&"
	}
	return uri + sep + strings.Join(params, "&")
}

// Small Server-coupled response helpers grouped here for navigability.
// Formerly lived in standalone files (token_no_store.go, bearer_challenge.go,
// audit_partial_revoke.go); merged because the concern is one: shape an
// HTTP response with security / audit headers or events.

// tokenNoStoreHeaders stamps RFC 6749 §5.1 cache-prevention headers
// on credential-bearing responses. /token, /token/introspect,
// /token/revoke and /par all return data that intermediaries MUST
// NOT retain — leaked tokens replayed off a cache would defeat
// the rotation + revocation invariants the rest of the server
// enforces. Pragma: no-cache is the HTTP/1.0 companion the RFC
// requires alongside Cache-Control; both go on every response
// regardless of status so error bodies (which include error_code
// shapes a snooping cache could fingerprint) get the same
// treatment as success.
// tokenNoStoreHeaders delegates to middleware.TokenNoStoreHeaders.
