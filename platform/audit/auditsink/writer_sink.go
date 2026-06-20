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

// WriterSink emits one JSON-encoded Event per line to the wrapped Writer.
//
// Use it to stream events into:
//   - a log file or rotating logger
//   - stdout (for container log collection by Fluentd/Filebeat/Loki)
//   - a Unix socket or named pipe that a gateway log shipper drains
//
// WriterSink is write-only: Get and Query both return ErrSinkWriteOnly. Pair
// it with MemorySink via MultiSink if you want both streaming and readback.
type WriterSink struct {
	mu sync.Mutex
	w  io.Writer
}

func NewWriterSink(w io.Writer) *WriterSink {
	return &WriterSink{w: w}
}

func (s *WriterSink) Record(_ context.Context, e *auditspi.Event) error {
	if e.ID == "" {
		e.ID = auditspi.NewEventID()
	}
	data, err := json.Marshal(e)
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
