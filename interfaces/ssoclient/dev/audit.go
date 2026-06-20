package dev

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/snaplink/sso/interfaces/ssoclient"
)

// AuditClient is a stub ssoclient.AuditClient. By default Record is
// a complete no-op so dev runs don't pollute stdout. Pass WithSink
// to mirror events to stderr / a file / a buffered writer for
// debug visibility.
type AuditClient struct {
	sink io.Writer
}

type auditConfig struct {
	commonOption
	sink io.Writer
}

// NewAuditClient constructs the stub.
func NewAuditClient(opts ...AuditOption) *AuditClient {
	cfg := &auditConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	if !cfg.silent {
		warn("AuditClient")
	}
	return &AuditClient{sink: cfg.sink}
}

// WithSink mirrors every Record to the given writer (one event per
// line, fmt %+v form). Use io.Discard explicitly if you want to
// disable the default no-op behavior in a test that needs to be
// sure no writes happen.
func WithSink(w io.Writer) AuditOption {
	return func(c *auditConfig) { c.sink = w }
}

// WithStderrSink is the convenience for "I want to eyeball events in
// the terminal" without composing a writer.
func WithStderrSink() AuditOption {
	return WithSink(os.Stderr)
}

// Record drops the event into the configured sink (if any) and
// always returns nil. Never blocks — even when a slow sink is wired,
// the writer error is silently swallowed (this is dev tooling, not
// a delivery-guarantee pipeline).
func (c *AuditClient) Record(_ context.Context, e *ssoclient.Event) error {
	if c.sink == nil || e == nil {
		return nil
	}
	_, _ = fmt.Fprintf(c.sink, "[dev-audit] %+v\n", e)
	return nil
}

// Close is a no-op.
func (c *AuditClient) Close() error { return nil }

var _ ssoclient.AuditClient = (*AuditClient)(nil)
