package auditsink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit/auditspi"
	"github.com/yangwb1123/snaplink/platform/tracing"
	"github.com/yangwb1123/snaplink/shared/security/securityverify"
	"go.opentelemetry.io/otel/attribute"
)

// DefaultWebhookTimeout is applied when WebhookOptions.Timeout is zero.
const DefaultWebhookTimeout = 5 * time.Second

// WebhookSink POSTs each event as JSON to a configured URL. Designed for a
// gateway-friendly setup where OpenResty and Go both push to the same HTTP
// collector that fans out to Kafka / Loki / S3.
//
// Like WriterSink, this is write-only — Get and Query return ErrSinkWriteOnly.
type WebhookSink struct {
	url            string
	client         *http.Client
	headers        map[string]string
	signingSecret  []byte
	rotatingSecret *securityverify.RotatingWebhookSecret
}

// WebhookOption configures a WebhookSink at construction.
type WebhookOption func(*WebhookSink)

// WithWebhookTimeout overrides the default per-request timeout.
func WithWebhookTimeout(d time.Duration) WebhookOption {
	return func(w *WebhookSink) { w.client.Timeout = d }
}

// WithWebhookHeader adds a static header (e.g., bearer auth) to every request.
func WithWebhookHeader(name, value string) WebhookOption {
	return func(w *WebhookSink) { w.headers[name] = value }
}

// WithWebhookHTTPClient injects a fully-customized *http.Client. Useful for
// tests or to plug in tracing / mTLS / circuit breakers.
func WithWebhookHTTPClient(c *http.Client) WebhookOption {
	return func(w *WebhookSink) {
		if c != nil {
			w.client = c
		}
	}
}

// WithWebhookSigningSecret enables HMAC-SHA256 payload signing — every POST
// carries securityverify.WebhookSignatureHeader (t=<unix>,v1=<hex>), letting
// receivers authenticate origin, integrity, and freshness. Empty is a no-op.
func WithWebhookSigningSecret(secret string) WebhookOption {
	return func(w *WebhookSink) {
		if secret != "" {
			w.signingSecret = []byte(secret)
		}
	}
}

// WithWebhookRotatingSecret enables HMAC-SHA256 payload signing from a
// securityverify.RotatingWebhookSecret instead of a static string, so the
// credential-rotation framework (platform/rotation) can mint a fresh secret
// on its schedule without an operator manually redistributing it: every send
// signs with the CURRENT version, and a receiver validating with the SAME
// RotatingWebhookSecret (or a static VerifyWebhookSignature kept in sync
// out-of-band) keeps accepting the prior secret until its overlap window
// closes. Takes precedence over WithWebhookSigningSecret when both are set.
func WithWebhookRotatingSecret(s *securityverify.RotatingWebhookSecret) WebhookOption {
	return func(w *WebhookSink) { w.rotatingSecret = s }
}

func NewWebhookSink(url string, opts ...WebhookOption) *WebhookSink {
	w := &WebhookSink{
		url: url,
		// Redirect-follow disabled: the configured url is treated as
		// authoritative, so a later 302 (compromised or misconfigured
		// receiver) can't silently redirect delivery off-host — same
		// SSRF-via-redirect class closed for CAEP/CIBA push/the generic
		// webhook Engine (platform/lifecycle/webhook/engine.go). A 3xx
		// response is surfaced as any other non-2xx status.
		client: &http.Client{
			Timeout:       DefaultWebhookTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		headers: make(map[string]string),
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

func (w *WebhookSink) Record(ctx context.Context, e *auditspi.Event) error {
	// Child of whatever span the caller's ctx carries — for the common
	// AsyncSink -> WebhookSink composition that's the reconstructed
	// audit.sink.deliver span (see audit.deliverSpanCtx); called directly
	// (synchronous Recorder, no AsyncSink) it's the live request span.
	ctx, span := tracing.StartSpan(ctx, "audit.webhook.deliver")
	defer span.End()

	if e.ID == "" {
		e.ID = auditspi.NewEventID()
	}
	body, err := json.Marshal(e)
	if err != nil {
		tracing.SetError(span, err)
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		tracing.SetError(span, err)
		return err
	}
	w.applyRequestHeaders(req, body)

	resp, err := w.client.Do(req)
	if err != nil {
		tracing.SetError(span, err)
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	span.SetAttributes(attribute.Int("http.response.status_code", resp.StatusCode))

	if resp.StatusCode >= 400 {
		err := fmt.Errorf("audit webhook: status %d", resp.StatusCode)
		tracing.SetError(span, err)
		return err
	}
	return nil
}

// applyRequestHeaders sets the content-type + operator static headers, then
// a computed HMAC signature (which wins over any static header of the same
// name). A rotating secret takes precedence over a static one — Current()
// always returns the version the rotation scheduler most recently installed.
func (w *WebhookSink) applyRequestHeaders(req *http.Request, body []byte) {
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}
	secret := w.signingSecret
	if w.rotatingSecret != nil {
		secret = w.rotatingSecret.Current()
	}
	if len(secret) > 0 {
		req.Header.Set(securityverify.WebhookSignatureHeader,
			securityverify.SignWebhookPayload(secret, time.Now(), body))
	}
}

func (*WebhookSink) Get(_ context.Context, _ string) (*auditspi.Event, error) {
	return nil, ErrSinkWriteOnly
}

func (*WebhookSink) Query(_ context.Context, _ auditspi.Query) ([]*auditspi.Event, error) {
	return nil, ErrSinkWriteOnly
}
