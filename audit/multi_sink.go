package audit

import (
	"context"
	"errors"
	"fmt"
)

// MultiSink fans Record out to multiple sinks (e.g., MemorySink for local
// query + WriterSink for off-host shipping). Get and Query are served by the
// first wrapped sink that supports readback (returns anything other than
// ErrSinkWriteOnly); write-only sinks are skipped for reads.
//
// Errors from individual Record calls are joined via errors.Join so the
// caller's audit.Recorder ErrorHandler still sees them.
type MultiSink struct {
	sinks []Sink
}

func NewMultiSink(sinks ...Sink) *MultiSink {
	return &MultiSink{sinks: sinks}
}

func (m *MultiSink) Record(ctx context.Context, e *Event) error {
	if e.ID == "" {
		e.ID = newEventID()
	}
	var errs []error
	for _, s := range m.sinks {
		if err := s.Record(ctx, e); err != nil {
			errs = append(errs, fmt.Errorf("audit multi: %T: %w", s, err))
		}
	}
	return errors.Join(errs...)
}

func (m *MultiSink) Get(ctx context.Context, id string) (*Event, error) {
	for _, s := range m.sinks {
		e, err := s.Get(ctx, id)
		if errors.Is(err, ErrSinkWriteOnly) {
			continue
		}
		return e, err
	}
	return nil, ErrEventNotFound
}

func (m *MultiSink) Query(ctx context.Context, q Query) ([]*Event, error) {
	for _, s := range m.sinks {
		out, err := s.Query(ctx, q)
		if errors.Is(err, ErrSinkWriteOnly) {
			continue
		}
		return out, err
	}
	return nil, ErrSinkWriteOnly
}
