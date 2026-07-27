package auditsink

import (
	"context"
	"strings"

	"github.com/yangwb1123/snaplink/platform/audit/auditspi"
)

// EventTypeWildcardSuffix marks a trailing prefix-wildcard in an event-type
// filter entry: "admin_*" matches every type beginning "admin_". It is the
// ONLY wildcard form supported — there is deliberately no general globbing,
// so a stray "*" in the middle of an entry is treated as a literal character.
const EventTypeWildcardSuffix = "*"

// FilteringSink forwards to inner only the events whose Type is in the
// configured allow-set, dropping the rest as a silent success (Record
// returns nil) so a MultiSink fan-out's errors.Join stays clean — a filtered
// event is a routing decision, not a delivery failure.
//
// An empty allow-set is a firehose: every event passes. This preserves the
// pre-subscription single-webhook semantics for the legacy unfiltered path,
// where no event_types are configured.
//
// Read paths (Get, Query) delegate to inner unchanged — filtering is a
// write-side routing concern; a write-only inner (WebhookSink) therefore
// still reports ErrSinkWriteOnly through the wrapper.
type FilteringSink struct {
	inner    auditspi.Sink
	exact    map[auditspi.EventType]struct{}
	prefixes []string
}

// FilteringOption configures a FilteringSink at construction.
type FilteringOption func(*FilteringSink)

// WithEventTypeFilter restricts delivery to the given event types. Each entry
// is either an exact type ("login") or a trailing-* prefix wildcard
// ("admin_*"). Blank entries are ignored so an all-blank list collapses to
// the firehose rather than a deliver-nothing sink. Passing no non-blank
// entries leaves the allow-set empty = firehose.
func WithEventTypeFilter(types ...string) FilteringOption {
	return func(f *FilteringSink) {
		for _, t := range types {
			switch {
			case t == "":
				continue
			case strings.HasSuffix(t, EventTypeWildcardSuffix):
				f.prefixes = append(f.prefixes, strings.TrimSuffix(t, EventTypeWildcardSuffix))
			default:
				f.exact[auditspi.EventType(t)] = struct{}{}
			}
		}
	}
}

// NewFilteringSink wraps inner, delivering only events that pass the
// configured event-type filter. With no filter options it is a transparent
// pass-through (firehose).
func NewFilteringSink(inner auditspi.Sink, opts ...FilteringOption) *FilteringSink {
	f := &FilteringSink{
		inner: inner,
		exact: make(map[auditspi.EventType]struct{}),
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// allows reports whether t passes the filter. An empty allow-set (no exact
// entries and no prefixes) is the firehose and passes everything.
func (f *FilteringSink) allows(t auditspi.EventType) bool {
	if len(f.exact) == 0 && len(f.prefixes) == 0 {
		return true
	}
	if _, ok := f.exact[t]; ok {
		return true
	}
	for _, p := range f.prefixes {
		if strings.HasPrefix(string(t), p) {
			return true
		}
	}
	return false
}

func (f *FilteringSink) Record(ctx context.Context, e *auditspi.Event) error {
	if !f.allows(e.Type) {
		return nil
	}
	return f.inner.Record(ctx, e)
}

func (f *FilteringSink) Get(ctx context.Context, id string) (*auditspi.Event, error) {
	return f.inner.Get(ctx, id)
}

func (f *FilteringSink) Query(ctx context.Context, q auditspi.Query) ([]*auditspi.Event, error) {
	return f.inner.Query(ctx, q)
}
