package kafkaaudit

import "github.com/snaplink/sso/platform/audit/auditsink"

// sinkOptions holds New's optional construction parameters.
type sinkOptions struct {
	format auditsink.Formatter
}

// Option configures a Sink at construction.
type Option func(*sinkOptions)

// WithFormat overrides the wire formatter New uses per event — reuse the
// SDK's existing SIEM formatters (auditsink.FormatCEF / FormatOCSF /
// FormatSyslog) or supply a custom one. Omitting this keeps FormatJSON's
// explicit-schema_version envelope, the default. A nil f is a no-op (keeps
// whatever was previously set) so callers can pass a possibly-nil value
// without a branch.
func WithFormat(f auditsink.Formatter) Option {
	return func(o *sinkOptions) {
		if f != nil {
			o.format = f
		}
	}
}
