package defaultimpl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// HTTPWebhookPushTransport delivers MFA push approvals to an
// operator-supplied HTTPS endpoint as a JSON POST. The operator's
// gateway translates the webhook into whatever channel actually
// reaches the user's device (FCM/APNs/SMS proxy/internal-mobile-app
// push), then later calls the SSO server's
// /push/approval/:id/:decision callback (or PushApprovalStore.SetStatus
// directly) to resolve the approval.
//
// Wire shape (POST body):
//
//	{
//	  "approval_id": "<opaque base64url>",
//	  "subject_id":  "<user the primary credential resolved to>",
//	  "metadata":    {"k1": "v1", ...}    // operator-supplied passthrough
//	}
//
// Wire semantics:
//   - 2xx response → Send returns nil (delivery accepted; the actual
//     user-device push is the gateway's concern).
//   - non-2xx OR transport error → retries up to MaxAttempts with
//     exponential backoff (InitialBackoff doubles on each retry,
//     capped at MaxBackoff). Final failure surfaces as the
//     wrapped HTTP error.
//   - context cancellation honored mid-retry.
//
// Auth: BearerToken / extra Headers populated on every request.
// Operators relying on signed payloads (HMAC body signing, mTLS
// client cert) fork this — the SPI for that varies per gateway.
type HTTPWebhookPushTransport struct {
	URL            string
	Client         *http.Client
	Headers        map[string]string
	BearerToken    string
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

// PushWebhookOption tunes the transport at construction time.
type PushWebhookOption func(*HTTPWebhookPushTransport)

// WithPushWebhookClient overrides the default http.Client (which
// uses a 5s timeout). Useful for embedders threading custom
// transports (TLS pin, dialer, etc).
func WithPushWebhookClient(c *http.Client) PushWebhookOption {
	return func(t *HTTPWebhookPushTransport) {
		if c != nil {
			t.Client = c
		}
	}
}

// WithPushWebhookHeader sets one additional HTTP header on every
// request. Repeated calls accumulate — operators wiring multiple
// headers call multiple times rather than passing a map.
func WithPushWebhookHeader(key, value string) PushWebhookOption {
	return func(t *HTTPWebhookPushTransport) {
		if t.Headers == nil {
			t.Headers = make(map[string]string)
		}
		t.Headers[key] = value
	}
}

// WithPushWebhookBearerToken sets the Authorization: Bearer header.
// Empty string disables (Authorization left untouched). Operator
// gateways typically gate on a deployment-stable bearer + an IP
// allowlist — same pattern as the push callback handler.
func WithPushWebhookBearerToken(token string) PushWebhookOption {
	return func(t *HTTPWebhookPushTransport) {
		t.BearerToken = token
	}
}

// WithPushWebhookRetry tunes the retry policy. MaxAttempts <= 0
// disables retries (single attempt). InitialBackoff defaults to
// 250ms; MaxBackoff defaults to 5s.
func WithPushWebhookRetry(maxAttempts int, initial, max time.Duration) PushWebhookOption {
	return func(t *HTTPWebhookPushTransport) {
		t.MaxAttempts = maxAttempts
		t.InitialBackoff = initial
		t.MaxBackoff = max
	}
}

// NewHTTPWebhookPushTransport validates url + returns the transport.
// url MUST be non-empty (the operator decision). Empty url →
// constructor error.
func NewHTTPWebhookPushTransport(url string, opts ...PushWebhookOption) (*HTTPWebhookPushTransport, error) {
	if url == "" {
		return nil, errors.New("push_webhook: url required")
	}
	t := &HTTPWebhookPushTransport{
		URL:            url,
		Client:         &http.Client{Timeout: 5 * time.Second},
		MaxAttempts:    3,
		InitialBackoff: 250 * time.Millisecond,
		MaxBackoff:     5 * time.Second,
	}
	for _, opt := range opts {
		opt(t)
	}
	return t, nil
}

// pushWebhookPayload is the JSON body shape — stable wire contract
// so operator gateways can parse it with their own struct.
type pushWebhookPayload struct {
	ApprovalID string            `json:"approval_id"`
	SubjectID  string            `json:"subject_id"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// Send POSTs the approval to the configured URL with the configured
// retry policy. Honors ctx cancel between retry attempts.
func (t *HTTPWebhookPushTransport) Send(ctx context.Context, approvalID, subjectID string, metadata map[string]string) error {
	if t == nil || t.URL == "" {
		return errors.New("push_webhook: transport not configured")
	}
	body, err := json.Marshal(pushWebhookPayload{
		ApprovalID: approvalID,
		SubjectID:  subjectID,
		Metadata:   metadata,
	})
	if err != nil {
		return fmt.Errorf("push_webhook: marshal payload: %w", err)
	}

	attempts := t.MaxAttempts
	if attempts <= 0 {
		attempts = 1
	}
	backoff := t.InitialBackoff
	if backoff <= 0 {
		backoff = 250 * time.Millisecond
	}
	maxBackoff := t.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = 5 * time.Second
	}

	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
		err := t.sendOnce(ctx, body)
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return fmt.Errorf("push_webhook: %d attempts failed, last: %w", attempts, lastErr)
}

// sendOnce builds + sends one HTTP attempt.
func (t *HTTPWebhookPushTransport) sendOnce(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if t.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+t.BearerToken)
	}
	for k, v := range t.Headers {
		req.Header.Set(k, v)
	}
	resp, err := t.Client.Do(req)
	if err != nil {
		return fmt.Errorf("http POST %s: %w", t.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http POST %s: status %d", t.URL, resp.StatusCode)
	}
	return nil
}

// Compile-time interface assertion.
var _ PushTransport = (*HTTPWebhookPushTransport)(nil)
