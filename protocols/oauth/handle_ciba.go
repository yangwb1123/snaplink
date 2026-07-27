package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/protocols/oauth/oauthspi"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// maxCIBADeliveryRetries is the number of times to retry CIBA challenge
// delivery before giving up. 3 retries with exponential backoff cover
// transient APNs/FCM/SMS gateway blips without holding the request open
// too long.
const maxCIBADeliveryRetries = 3

// CIBADeps is what HandleBackchannelAuth needs. *sso.Server satisfies
// it via accessor methods (accessors.go). oauth/ must not import oidc/,
// so hint resolution + the out-of-band delivery transport are exposed
// as Deps methods the Server implements over its own machinery.
type CIBADeps interface {
	ClientStoreAccessor() core.ClientStore
	CIBAStore() CIBAStore
	CIBARequestTTL() time.Duration
	CIBAPollInterval() time.Duration
	ResolveIssuer(ctx core.HandlerContext) string
	VerifyJWTClientAssertion(ctx context.Context, assertion, formClientID, asIssuer string) (string, error)
	SrvLogger() spi.Logger

	// ResolveCIBAHint maps the supplied hints (login_hint /
	// id_token_hint / login_hint_token) to a known user's subject id.
	// Returns ("", nil) when no hint resolves — the handler collapses
	// that to unknown_user_id per the anti-enumeration contract. The
	// provider name is the authenticator recorded for the eventual
	// token's AMR claim.
	ResolveCIBAHint(ctx context.Context, loginHint, idTokenHint, loginHintToken string) (subjectID, provider string, err error)

	// DeliverCIBAChallenge pushes the auth_req_id (and binding_message)
	// out of band via the wired PushTransport so the user can confirm
	// on their authentication device. Errors propagate as a 500 —
	// the request was persisted but the channel refused delivery, so
	// the operator must investigate (vs leaking a usable auth_req_id).
	DeliverCIBAChallenge(ctx context.Context, authReqID, subjectID, bindingMessage string) error

	// RecordCIBAAuthRequest emits the ciba_auth_request audit event.
	RecordCIBAAuthRequest(ctx core.HandlerContext, clientID, subjectID, authReqID string)
}

// HandleBackchannelAuth implements OpenID Connect CIBA Core 1.0 §7 in
// POLL delivery mode. The client (Consumption Device) POSTs the
// backchannel authentication request here; the AS resolves the hint to
// a user, persists a pending request, delivers the challenge out of
// band (reusing the Push MFA transport), and returns an auth_req_id +
// expires_in + interval the client polls /token with
// (grant_type=urn:openid:params:grant-type:ciba).
//
// Auth: HTTP Basic OR client_id+client_secret form body per RFC 6749
// §2.3.1 (Basic wins when both present — same precedence as /token and
// /par). private_key_jwt accepted via client_assertion.
//
// Poll mode only: at least one of login_hint / id_token_hint /
// login_hint_token MUST resolve to a known user; missing-hint and
// unresolvable-hint collapse to unknown_user_id (anti-enumeration).
func HandleBackchannelAuth(d CIBADeps, ctx core.HandlerContext) {
	middleware.TokenNoStoreHeaders(ctx)
	if d.CIBAStore() == nil {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrCIBANotConfigured))
		return
	}
	if d.ClientStoreAccessor() == nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrServerMisconfigured))
		return
	}

	var req cibaRequest
	if err := BindParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if id, secret, ok := BasicClientCreds(ctx.Request()); ok {
		req.ClientID = id
		req.ClientSecret = secret
	}

	client, ok := authenticateCIBAClient(d, ctx, &req)
	if !ok {
		return
	}
	subjectID, provider, ok := resolveCIBASubject(d, ctx, &req)
	if !ok {
		return
	}
	issueAndDeliverCIBA(d, ctx, client, subjectID, provider, &req)
}

// cibaRequest is the bound backchannel-auth request body. Named (vs an
// anonymous struct) so it can cross the extracted-helper seam.
type cibaRequest struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	Scope                   string   `json:"scope"`
	LoginHint               string   `json:"login_hint"`                // OIDC Core §3.1.2.1
	IDTokenHint             string   `json:"id_token_hint"`             // OIDC Core §3.1.2.1
	LoginHintToken          string   `json:"login_hint_token"`          // CIBA Core §7.1
	BindingMessage          string   `json:"binding_message"`           // CIBA Core §7.1
	ACRValues               string   `json:"acr_values"`                // OIDC Core §3.1.2.1
	Nonce                   string   `json:"nonce"`                     // OIDC nonce
	Resource                []string `json:"resource"`                  // RFC 8707
	UserCode                string   `json:"user_code"`                 // CIBA Core §7.1 (user-code mode — unsupported)
	ClientNotificationToken string   `json:"client_notification_token"` // CIBA Core §7.1 (ping/push delivery)
	ClientAssertion         string   `json:"client_assertion"`          // RFC 7521 + 7523
	ClientAssertionType     string   `json:"client_assertion_type"`     // RFC 7521 + 7523
}

// authenticateCIBAClient runs client authentication: optional
// private_key_jwt (RFC 7521/7523), then client_id presence, lookup,
// active/tenant gates, and secret validation. On any failure it writes
// the response and returns ok=false. The invalid_client collapse
// (unknown client_id == bad secret) is preserved byte-for-byte to hide
// client_id enumeration. AreResourcesAllowed (invalid_target) stays
// BETWEEN secret-validation and hint-resolution.
func authenticateCIBAClient(d CIBADeps, ctx core.HandlerContext, req *cibaRequest) (*core.Client, bool) {
	clientStore := d.ClientStoreAccessor()

	if !applyCIBAClientAssertion(d, ctx, req) {
		return nil, false
	}

	if req.ClientID == "" {
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrMissingClientID))
		return nil, false
	}

	client, err := clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClient))
		return nil, false
	}
	if !client.Active {
		ctx.JSON(http.StatusForbidden, core.ErrorBody(core.ErrInactiveClient))
		return nil, false
	}
	if !tenant.ClientOK(ctx, client) {
		ctx.JSON(http.StatusForbidden, core.ErrorBody(core.ErrTenantMismatch))
		return nil, false
	}
	if req.ClientAssertion == "" {
		if err := clientStore.ValidateSecret(ctx.Request().Context(), req.ClientID, req.ClientSecret); err != nil {
			// RFC 6749 §5.2: client-auth failure is invalid_client (same code
			// as unknown-client above — oracle-safe, no client_id enumeration).
			ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClient))
			return nil, false
		}
	}
	if !client.AreResourcesAllowed(req.Resource) {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidTarget))
		return nil, false
	}
	return client, true
}

// applyCIBAClientAssertion runs RFC 7521/7523 private_key_jwt client
// authentication when a client_assertion is supplied (same as /token and
// /par), rewriting req.ClientID to the asserted id. Returns false (after
// writing the response) on wrong assertion type (400 invalid_request) or
// verification failure (401 invalid_client). No assertion present is a
// no-op success (secret auth applies later).
func applyCIBAClientAssertion(d CIBADeps, ctx core.HandlerContext, req *cibaRequest) bool {
	if req.ClientAssertion == "" && req.ClientAssertionType == "" {
		return true
	}
	if req.ClientAssertionType != ClientAssertionTypeJWTBearer {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return false
	}
	assertedID, err := d.VerifyJWTClientAssertion(
		ctx.Request().Context(), req.ClientAssertion, req.ClientID, d.ResolveIssuer(ctx),
	)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClient))
		return false
	}
	req.ClientID = assertedID
	return true
}

// resolveCIBASubject enforces poll-mode hint resolution. Empty-hint and
// unresolvable-hint (incl. resolver error) both collapse to a
// byte-identical 400 unknown_user_id so a client can't enumerate which
// usernames exist (anti-enumeration parity). The err!=nil logging
// side-effect is preserved.
func resolveCIBASubject(d CIBADeps, ctx core.HandlerContext, req *cibaRequest) (subjectID, provider string, ok bool) {
	// Poll mode only: at least one hint MUST be present. Empty-hint and
	// unresolvable-hint both collapse to unknown_user_id so a client
	// can't enumerate which usernames exist (anti-enumeration parity
	// with the rest of the surface).
	if req.LoginHint == "" && req.IDTokenHint == "" && req.LoginHintToken == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrUnknownUserID))
		return "", "", false
	}
	subjectID, provider, err := d.ResolveCIBAHint(
		ctx.Request().Context(), req.LoginHint, req.IDTokenHint, req.LoginHintToken,
	)
	if err != nil || subjectID == "" {
		if err != nil {
			d.SrvLogger().Info("ciba hint resolution failed", "client_id", req.ClientID, "error", err)
		}
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrUnknownUserID))
		return "", "", false
	}
	return subjectID, provider, true
}

// issueAndDeliverCIBA validates scope, persists the pending request, and
// delivers the challenge out of band. Delivery failure → 500 + cleanup
// of the dangling pending request (so no auth_req_id the user can never
// confirm). On success it records the audit event and writes the 200.
func issueAndDeliverCIBA(d CIBADeps, ctx core.HandlerContext, client *core.Client, subjectID, provider string, req *cibaRequest) {
	ttl := d.CIBARequestTTL()
	if ttl <= 0 {
		ttl = DefaultCIBARequestTTL
	}
	interval := d.CIBAPollInterval()
	if interval <= 0 {
		interval = DefaultCIBAPollInterval
	}

	authReqID, ok := persistCIBARequest(d, ctx, client, subjectID, provider, req, ttl, interval)
	if !ok {
		return
	}

	// Deliver the challenge out of band with exponential-backoff retry
	// so transient APNs/FCM/SMS gateway failures don't abort the entire
	// CIBA flow. After all retries are exhausted the pending request is
	// cleaned up (no dangling auth_req_id the user can never confirm).
	if err := deliverCIBAWithRetry(d, ctx.Request().Context(), authReqID, subjectID, req.BindingMessage); err != nil {
		d.SrvLogger().Error("ciba challenge delivery failed after retries", "error", err, "auth_req_id", authReqID)
		_ = d.CIBAStore().Delete(ctx.Request().Context(), authReqID)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}

	d.RecordCIBAAuthRequest(ctx, req.ClientID, subjectID, authReqID)

	ctx.JSON(http.StatusOK, map[string]any{
		"auth_req_id": authReqID,
		"expires_in":  int(ttl.Seconds()),
		"interval":    int(interval.Seconds()),
	})
}

// deliverCIBAWithRetry calls DeliverCIBAChallenge with exponential
// backoff up to maxCIBADeliveryRetries attempts. Returns the last
// error when all attempts fail.
func deliverCIBAWithRetry(d CIBADeps, ctx context.Context, authReqID, subjectID, bindingMessage string) error {
	var lastErr error
	for attempt := range maxCIBADeliveryRetries {
		if attempt > 0 {
			// backoff: 50ms, 250ms, 1s (attempt 1, 2, 3)
			backoff := time.Duration(math.Pow(5, float64(attempt))) * 10 * time.Millisecond
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if err := d.DeliverCIBAChallenge(ctx, authReqID, subjectID, bindingMessage); err != nil {
			lastErr = err
			d.SrvLogger().Error("ciba challenge delivery failed, retrying",
				"error", err, "attempt", attempt+1, "auth_req_id", authReqID)
			continue
		}
		return nil
	}
	return lastErr
}

// persistCIBARequest validates the requested scope and persists the
// pending CIBARequest. Returns (authReqID, true) on success; on
// disallowed scope it writes 400 invalid_scope, on store failure 500
// (with the ciba issue failed log), each returning ok=false.
//
// Scope authorization happens at backchannel-auth REQUEST time (not at
// /token redemption): the client is fully authenticated here and
// AllowedScopes is in scope, so an unapproved-scope CIBA request is
// rejected up front. The captured CIBARequest.Scopes is the GRANTED set
// (validated, or defaulted to the allowlist when empty), so the eventual
// token carries its entitled scope.
func persistCIBARequest(d CIBADeps, ctx core.HandlerContext, client *core.Client, subjectID, provider string, req *cibaRequest, ttl, interval time.Duration) (string, bool) {
	grantedScopes, err := GrantedScopes(SplitScope(req.Scope), client)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))
		return "", false
	}

	now := time.Now()
	authReqID, err := d.CIBAStore().Issue(ctx.Request().Context(), &CIBARequest{
		ClientID:                req.ClientID,
		SubjectID:               subjectID,
		Provider:                provider,
		Scopes:                  grantedScopes,
		ACRValues:               req.ACRValues,
		BindingMessage:          req.BindingMessage,
		Resources:               req.Resource,
		Nonce:                   req.Nonce,
		ClientNotificationToken: req.ClientNotificationToken,
		Status:                  CIBAPending,
		Interval:                interval,
		CreatedAt:               now,
		ExpiresAt:               now.Add(ttl),
	})
	if err != nil {
		d.SrvLogger().Error("ciba issue failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return "", false
	}
	return authReqID, true
}

// --- CIBA Push Delivery (CIBA Core §10.3) ---

// DefaultCIBAPushTimeout is the max time to wait for a push delivery HTTP response.
const DefaultCIBAPushTimeout = 5 * time.Second

// DefaultCIBAPushMaxRetries is the number of push delivery retries before deadletter.
const DefaultCIBAPushMaxRetries = 3

// CIBAPushNotifierOption configures a cibaPushNotifier.
type CIBAPushNotifierOption func(*cibaPushNotifier)

// WithCIBAPushHTTPClient sets the HTTP client for push delivery.
func WithCIBAPushHTTPClient(client *http.Client) CIBAPushNotifierOption {
	return func(pn *cibaPushNotifier) { pn.client = client }
}

// WithCIBAPushDeadLetterStore wires a deadletter store for failed deliveries.
func WithCIBAPushDeadLetterStore(dl oauthspi.CIBAPushDeadLetterStore) CIBAPushNotifierOption {
	return func(pn *cibaPushNotifier) { pn.deadLetter = dl }
}

// WithCIBAPushMaxRetries sets the number of push delivery retries.
func WithCIBAPushMaxRetries(n int) CIBAPushNotifierOption {
	return func(pn *cibaPushNotifier) { pn.maxRetries = n }
}

// WithCIBAPushLogger sets the logger for push delivery events.
func WithCIBAPushLogger(logger spi.Logger) CIBAPushNotifierOption {
	return func(pn *cibaPushNotifier) { pn.logger = logger }
}

// NewCIBAPushNotifier creates a CIBA Core §10.3 push delivery notifier that POSTs
// the token payload to the client's registered backchannel_token_delivery_uri.
// getDeliveryURI resolves a clientID to its registered push endpoint.
func NewCIBAPushNotifier(
	getDeliveryURI func(ctx context.Context, clientID string) (string, error),
	opts ...CIBAPushNotifierOption,
) oauthspi.CIBAPushNotifier {
	n := &cibaPushNotifier{
		// Redirect-follow is disabled: a registered delivery URI that 302s to
		// an internal/non-https target would otherwise bypass validatePushURI's
		// https-only gate (same redirect-to-internal SSRF class as CAEP/SAML/
		// backchannel-logout). Treat the resolved URI as authoritative and
		// never follow redirects — a 3xx response fails doPush's 2xx check
		// like any other non-2xx status, feeding the existing retry/dead-letter path.
		client: &http.Client{
			Timeout:       DefaultCIBAPushTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		getDeliveryURI: getDeliveryURI,
		maxRetries:     DefaultCIBAPushMaxRetries,
		logger:         spi.NopLogger{},
	}
	for _, opt := range opts {
		opt(n)
	}
	return n
}

type cibaPushNotifier struct {
	client         *http.Client
	getDeliveryURI func(ctx context.Context, clientID string) (string, error)
	deadLetter     oauthspi.CIBAPushDeadLetterStore
	maxRetries     int
	logger         spi.Logger
}

func (n *cibaPushNotifier) NotifyPush(ctx context.Context, clientID, authReqID, clientNotificationToken string, tokens oauthspi.PushPayload) error {
	uri, err := n.getDeliveryURI(ctx, clientID)
	if err != nil || uri == "" {
		return err
	}
	if err := validatePushURI(uri); err != nil {
		return fmt.Errorf("ciba push: invalid delivery URI: %w", err)
	}
	body, err := json.Marshal(tokens)
	if err != nil {
		return fmt.Errorf("ciba push: marshal payload: %w", err)
	}
	var lastErr error
	for attempt := 0; attempt <= n.maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<(attempt-1)) * time.Second
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if err := n.doPush(ctx, uri, clientNotificationToken, body); err != nil {
			lastErr = err
			n.logger.Error("ciba push failed", "error", err, "attempt", attempt+1, "client_id", clientID, "auth_req_id", authReqID)
			continue
		}
		return nil
	}
	if n.deadLetter != nil {
		_ = n.deadLetter.Record(ctx, authReqID, tokens, lastErr)
	}
	return fmt.Errorf("ciba push: delivery failed after %d retries: %w", n.maxRetries, lastErr)
}

func (n *cibaPushNotifier) doPush(ctx context.Context, uri, token string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set(core.HeaderContentType, core.ContentTypeJSON)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http %d (expected 2xx)", resp.StatusCode)
	}
	return nil
}

func validatePushURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return fmt.Errorf("scheme must be https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("empty host")
	}
	return nil
}
