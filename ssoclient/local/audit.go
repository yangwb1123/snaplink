package local

import (
	"context"
	"errors"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/ssoclient"
)

// AuditClient wraps an *audit.Recorder. Record is a direct passthrough; the
// Recorder is nil-safe in the SDK, so it is OK for the wrapped value to be
// nil — the call becomes a no-op.
type AuditClient struct {
	recorder *audit.Recorder
}

func NewAuditClient(r *audit.Recorder) *AuditClient {
	return &AuditClient{recorder: r}
}

func (c *AuditClient) Record(ctx context.Context, e *ssoclient.Event) error {
	if e == nil {
		return errors.New("ssoclient/local: event required")
	}
	c.recorder.Record(ctx, e) // nil-safe at the SDK level
	return nil
}

// Close is a no-op for the in-process recorder — there is no connection
// to drain. Returning nil keeps the call site uniform with the remote
// variant which DOES need a Close.
func (c *AuditClient) Close() error { return nil }
