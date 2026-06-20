package audit

// The four stateless sink backends (RetryingSink, WebhookSink, WriterSink and
// the BatchSink batching adapter) live in the auditsink leaf so this directory
// stays within the per-directory file-count budget. auditsink depends only on
// the auditspi SPI leaf. These aliases preserve the historical audit.* import
// surface unchanged for the in-package sinks (async/multi), the Recorder wiring,
// and external consumers; type aliases keep interface identity intact.

import "github.com/snaplink/sso/platform/audit/auditsink"

type (
	BatchSink                = auditsink.BatchSink
	RetryOption              = auditsink.RetryOption
	RetryingSink             = auditsink.RetryingSink
	TransientErrorClassifier = auditsink.TransientErrorClassifier
	WebhookOption            = auditsink.WebhookOption
	WebhookSink              = auditsink.WebhookSink
	WriterSink               = auditsink.WriterSink
)

const (
	DefaultRetryInitialBackoff = auditsink.DefaultRetryInitialBackoff
	DefaultRetryMaxAttempts    = auditsink.DefaultRetryMaxAttempts
	DefaultRetryMaxBackoff     = auditsink.DefaultRetryMaxBackoff
	DefaultWebhookTimeout      = auditsink.DefaultWebhookTimeout
)

var (
	DefaultTransientClassifier = auditsink.DefaultTransientClassifier
	ErrNonTransient            = auditsink.ErrNonTransient
	ErrSinkWriteOnly           = auditsink.ErrSinkWriteOnly
	NewRetryingSink            = auditsink.NewRetryingSink
	NewWebhookSink             = auditsink.NewWebhookSink
	NewWriterSink              = auditsink.NewWriterSink
	WithRetryClassifier        = auditsink.WithRetryClassifier
	WithRetryInitialBackoff    = auditsink.WithRetryInitialBackoff
	WithRetryMaxAttempts       = auditsink.WithRetryMaxAttempts
	WithRetryMaxBackoff        = auditsink.WithRetryMaxBackoff
	WithWebhookHTTPClient      = auditsink.WithWebhookHTTPClient
	WithWebhookHeader          = auditsink.WithWebhookHeader
	WithWebhookTimeout         = auditsink.WithWebhookTimeout
)
