package sso

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/platform/lifecycle/sessionhub"
	"github.com/yangwb1123/snaplink/protocols/oidc/bcl"
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
type LogoutTokenIssuer = bcl.Issuer

// LogoutTokenRequest carries the issuance inputs. TTL falls
// back to a short default when zero — logout tokens are
// single-use and short-lived by nature (the RP processes one
// immediately on receipt).
type LogoutTokenRequest = bcl.Request

// LogoutNotifier delivers a signed logout_token to the RP's
// backchannel_logout_uri per OIDC BCL §2.5. Implementations MUST
// respect the supplied context's deadline so the AS isn't
// blocked when an RP is slow or unreachable.
type LogoutNotifier = bcl.Notifier

// DefaultBackchannelLogoutTimeout caps an individual RP
// notification. Short on purpose — the user is waiting on the
// /logout response while this round-trips, and a slow RP must
// not delay the rest of the logout pipeline. A failure here is
// logged + audited but not fatal.
const DefaultBackchannelLogoutTimeout = 5 * time.Second

// Back-channel delivery retries transient failures with freshly signed tokens.
// All attempts share DefaultBackchannelLogoutTimeout, so retry never extends
// the logout request's existing per-RP latency budget.
const (
	DefaultBackchannelLogoutMaxAttempts = 3
	DefaultBackchannelLogoutRetryBase   = 50 * time.Millisecond
)

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
		// Redirect-follow is disabled: a registered BackchannelLogoutURI that
		// 302s to an internal host bypasses the https-only registration check
		// (same redirect-to-internal SSRF class as CAEP/SAML). Treat the stored
		// URI as authoritative; never follow redirects.
		Client: &http.Client{
			Timeout:       DefaultBackchannelLogoutTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
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
		client = &http.Client{
			Timeout:       DefaultBackchannelLogoutTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
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
	return &backchannelHTTPError{status: resp.StatusCode, uri: uri}
}

type backchannelHTTPError struct {
	status int
	uri    string
}

func (e *backchannelHTTPError) Error() string {
	return fmt.Sprintf("backchannel_logout: non-2xx status %d from %s", e.status, e.uri)
}

func (e *backchannelHTTPError) Retryable() bool {
	return e.status == http.StatusRequestTimeout || e.status == http.StatusTooManyRequests || e.status >= 500
}

// sendBackchannelLogout fans out a logout notification for the
// given (subject, client). No-op when:
//   - The back-channel logout subsystem isn't wired
//     (logoutTokenIssuer + logoutNotifier MUST both be set).
//   - The client doesn't declare BackchannelLogoutURI.
//
// Failures are logged + audited but never block the parent
// /logout response — see the contract on LogoutNotifier.
func (s *Server) sendBackchannelLogout(ctx HandlerContext, client *Client, subject string, sid string) bool {
	if s.logoutTokenIssuer == nil || s.logoutNotifier == nil {
		return true
	}
	if client == nil || client.BackchannelLogoutURI == "" {
		return true
	}
	// Preserve tenant/trace values but detach delivery from browser disconnects
	// and gateway cancellation. The absolute timeout still bounds all attempts.
	baseCtx := context.WithoutCancel(ctx.Request().Context())
	tokenCtx, cancel := context.WithTimeout(baseCtx, DefaultBackchannelLogoutTimeout)
	defer cancel()
	// OIDC BCL §2.1 + pairwise: the logout_token `sub` MUST be the identifier the
	// TARGET client received in its id_token. For a pairwise client that is its
	// per-sector pseudonym, NOT the local id. Emitting the local id would defeat
	// pairwise unlinkability (colluding RPs correlate the user by the shared
	// local id) AND break a sub-matching RP (the sub differs from the pseudonym
	// it stored). The audit + subject_client_index stay keyed by the local
	// subject; non-pairwise clients map to the local id unchanged.
	clientSub := s.applyPairwiseSubject(ctx.Request().Context(), client, subject)
	request := &LogoutTokenRequest{
		Subject:  clientSub,
		Audience: client.ID,
		// OIDC BCL §2.4: `sid` lets the RP scope the logout to
		// the specific session it received the matching id_token
		// for. Empty when the inbound id_token_hint had no sid
		// claim (legacy tokens minted before sid plumbing).
		SID: sid,
	}
	err := s.deliverBackchannelWithRetry(tokenCtx, client.BackchannelLogoutURI, request)
	if err != nil {
		s.queueBackchannelFailure(baseCtx, client, subject, request, err)
		var issueErr *backchannelIssueError
		if !errors.As(err, &issueErr) {
			s.logger.Error("backchannel logout: notify failed",
				"error", err, "client", client.ID, "uri", client.BackchannelLogoutURI)
			s.recordLogoutNotifyFailure(ctx, client.ID, subject, err.Error())
			return false
		}
		s.logger.Error("backchannel logout: issue token failed",
			"error", err, "client", client.ID, "subject", subject)
		s.recordLogoutNotifyFailure(ctx, client.ID, subject, err.Error())
		return false
	}
	s.recordLogoutNotifySuccess(ctx, client.ID, subject, client.BackchannelLogoutURI)
	return true
}

func (s *Server) queueBackchannelFailure(ctx context.Context, client *Client, subject string, req *LogoutTokenRequest, cause error) {
	recorder, ok := s.logoutNotifier.(bcl.FailureRecorder)
	if !ok {
		return
	}
	var statusErr *backchannelHTTPError
	permanent := errors.As(cause, &statusErr) && !statusErr.Retryable()
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	err := recorder.RecordFailure(recordCtx, bcl.Failure{
		TenantID: client.TenantID, ClientID: client.ID, Subject: subject,
		TokenSubject: req.Subject, URI: client.BackchannelLogoutURI, SID: req.SID,
		Attempts: DefaultBackchannelLogoutMaxAttempts, LastError: cause.Error(), Permanent: permanent,
	})
	if err != nil {
		s.logger.Error("backchannel logout: queue failure failed", "error", err, "client", client.ID)
	}
}

type backchannelIssueError struct{ err error }

func (e *backchannelIssueError) Error() string { return e.err.Error() }
func (e *backchannelIssueError) Unwrap() error { return e.err }

func (s *Server) deliverBackchannelWithRetry(ctx context.Context, uri string, req *LogoutTokenRequest) error {
	var lastErr error
	for attempt := 1; attempt <= DefaultBackchannelLogoutMaxAttempts; attempt++ {
		token, err := s.logoutTokenIssuer.IssueLogoutToken(ctx, req)
		if err != nil {
			return &backchannelIssueError{err: err}
		}
		lastErr = s.logoutNotifier.Notify(ctx, uri, token)
		if lastErr == nil || !retryableBackchannelError(lastErr) {
			return lastErr
		}
		if attempt == DefaultBackchannelLogoutMaxAttempts {
			break
		}
		base := DefaultBackchannelLogoutRetryBase << (attempt - 1)
		delay := time.Duration(float64(base) * (0.75 + rand.Float64()*0.5))
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return lastErr
}

func retryableBackchannelError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var statusErr *backchannelHTTPError
	if !errors.As(err, &statusErr) {
		return true
	}
	return statusErr.Retryable()
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
// Failed targets remain indexed, allowing a later logout/session-hub pass to
// retry instead of silently forgetting the undelivered revocation signal.
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
// a successful notification on the same worker — see
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
				s.dispatchBackchannelOne(ctx, c, subject, sid)
			}
		}()
	}
	wg.Wait()
}

// dispatchBackchannelOne delivers to ONE fan-out target and is wrapped in
// recover(): sendBackchannelLogout calls the pluggable LogoutTokenIssuer +
// LogoutNotifier, and Forget calls the pluggable SubjectClientIndex — a panic
// in any of those operator-supplied implementations must drop only this
// client's notification, not crash the worker goroutine (which has no
// recover of its own and would take the whole process down mid-/logout,
// aborting every other in-flight request). Mirrors the per-item recover in
// infrastructure/saml/idp/fanout.go's dispatchOne and
// protocols/caep.Transmitter.deliver.
func (s *Server) dispatchBackchannelOne(ctx HandlerContext, c *Client, subject, sid string) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("backchannel logout: worker panic recovered",
				"panic", r, "client", c.ID, "subject", subject)
		}
	}()
	// Per-client sid filter: every fan-out RP gets the
	// SAME sid value. RPs that don't recognize the sid
	// fall back to subject-wide logout per BCL §2.4 —
	// exactly the desired soft-degradation.
	if s.sendBackchannelLogout(ctx, c, subject, sid) {
		_ = s.subjectClientIndex.Forget(ctx.Request().Context(), subject, c.ID)
	}
}

// TriggerSessionHubLogout resolves the global_sid the Cross-protocol Session
// Hub (platform/lifecycle/sessionhub) linked at login for (subject, sid) and,
// if found, runs Coordinator.Logout. That redundantly re-destroys the
// already-destroyed core session leg (idempotent) and redundantly re-fans
// the OIDC backchannel logout (a safe no-op: fanOutBackchannelLogout's
// subjectClientIndex.Forget bookkeeping means every client this request
// already notified above won't be re-listed, and without an index wired the
// Coordinator's nil-originClient path never sends anything at all) — but
// CRITICALLY it also fires the SAML SLO fan-out when this login had a SAML
// leg ("where applicable"), which was otherwise unreachable from either real
// logout path: a user logging out of OIDC/session kept an active SAML SP
// session alive indefinitely. Best-effort: any resolution miss (no bearer,
// unlinked login, sessionHub outage) is a silent no-op — every revocation
// and fan-out already performed above is unaffected either way. Exported so
// it also satisfies protocols/oidc's EndSessionDeps for /end_session.
func (s *Server) TriggerSessionHubLogout(rctx context.Context, subject, sid string) {
	if s.sessionHub == nil || subject == "" || sid == "" {
		return
	}
	records, err := s.sessionHub.ListBySubject(rctx, subject)
	if err != nil {
		return
	}
	for _, r := range records {
		if r.Protocol == sessionhub.ProtocolCore && r.ExternalRef == sid {
			_ = s.sessionHub.Logout(rctx, r.GlobalSID)
			return
		}
	}
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
