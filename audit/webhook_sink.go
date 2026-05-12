package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// DefaultWebhookTimeout is applied when WebhookOptions.Timeout is zero.
const DefaultWebhookTimeout = 5 * time.Second

// WebhookSink POSTs each event as JSON to a configured URL. Designed for a
// gateway-friendly setup where OpenResty and Go both push to the same HTTP
// collector that fans out to Kafka / Loki / S3.
//
// Like WriterSink, this is write-only — Get and Query return ErrSinkWriteOnly.
type WebhookSink struct {
	url     string
	client  *http.Client
	headers map[string]string
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

func NewWebhookSink(url string, opts ...WebhookOption) *WebhookSink {
	w := &WebhookSink{
		url:     url,
		client:  &http.Client{Timeout: DefaultWebhookTimeout},
		headers: make(map[string]string),
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

func (w *WebhookSink) Record(ctx context.Context, e *Event) error {
	if e.ID == "" {
		e.ID = newEventID()
	}
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("audit webhook: status %d", resp.StatusCode)
	}
	return nil
}

func (*WebhookSink) Get(_ context.Context, _ string) (*Event, error) {
	return nil, ErrSinkWriteOnly
}

func (*WebhookSink) Query(_ context.Context, _ Query) ([]*Event, error) {
	return nil, ErrSinkWriteOnly
}
