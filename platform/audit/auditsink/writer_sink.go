package auditsink

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"

	"github.com/snaplink/sso/platform/audit/auditspi"
)

// ErrSinkWriteOnly is returned by sinks that only stream events outward and
// do not retain them for Query/Get. Callers that need readback should compose
// a write-only sink with a queryable one via MultiSink.
var ErrSinkWriteOnly = errors.New("audit: sink does not support readback")

// Formatter renders one Event to its wire-format bytes (no trailing
// newline — WriterSink appends that once, uniformly, regardless of
// format). Pure and transport-independent: it never touches e (a syslog
// wrapper composes another Formatter's output as its MSG, see
// FormatSyslog), and never performs I/O itself. This is the exact contract
// roadmap item 19 (Kafka/NATS export) reuses — a formatter decided here
// never needs to be redecided for a different transport.
type Formatter func(*auditspi.Event) ([]byte, error)

// defaultJSONFormatter is WriterSink's historical (pre-Formatter) behavior:
// the raw JSON encoding of Event. Kept as the zero-value default so every
// existing WriterSink caller (and its tests) sees byte-identical output.
func defaultJSONFormatter(e *auditspi.Event) ([]byte, error) {
	return json.Marshal(e)
}

// WriterSinkOption configures a WriterSink at construction.
type WriterSinkOption func(*WriterSink)

// WithWriterFormat overrides the wire format WriterSink emits per Event —
// e.g. FormatCEF, FormatOCSF, or FormatSyslog. Omitting this option keeps
// the original JSON-lines behavior (defaultJSONFormatter).
func WithWriterFormat(f Formatter) WriterSinkOption {
	return func(s *WriterSink) { s.format = f }
}

// WriterSink emits one formatted Event per line to the wrapped Writer.
// format defaults to JSON (see NewWriterSink); WithWriterFormat swaps in
// CEF/OCSF/syslog or any other pure Event-to-bytes encoder.
//
// Use it to stream events into:
//   - a log file or rotating logger
//   - stdout (for container log collection by Fluentd/Filebeat/Loki)
//   - a Unix socket or named pipe that a gateway log shipper drains
//
// WriterSink is write-only: Get and Query both return ErrSinkWriteOnly. Pair
// it with MemorySink via MultiSink if you want both streaming and readback.
type WriterSink struct {
	mu     sync.Mutex
	w      io.Writer
	format Formatter
}

func NewWriterSink(w io.Writer, opts ...WriterSinkOption) *WriterSink {
	s := &WriterSink{w: w, format: defaultJSONFormatter}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *WriterSink) Record(_ context.Context, e *auditspi.Event) error {
	if e.ID == "" {
		e.ID = auditspi.NewEventID()
	}
	data, err := s.format(e)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.w.Write(data)
	return err
}

func (*WriterSink) Get(_ context.Context, _ string) (*auditspi.Event, error) {
	return nil, ErrSinkWriteOnly
}

func (*WriterSink) Query(_ context.Context, _ auditspi.Query) ([]*auditspi.Event, error) {
	return nil, ErrSinkWriteOnly
}
