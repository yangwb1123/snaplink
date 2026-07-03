package sse

import (
	"context"
	"encoding/json"
	"time"

	"github.com/snaplink/sso/platform/audit/auditsink"
	"github.com/snaplink/sso/platform/audit/auditspi"
)

// Summary is the redacted projection of an audit event pushed to SSE
// subscribers. It deliberately carries ONLY reference fields — never
// secrets, raw tokens, session ids, IPs, user agents, or the free-form
// Metadata blob. Consumers needing detail fetch the full (admin-gated)
// record via GET /api/v1/audit/events/:id using ID.
type Summary struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Outcome  string `json:"outcome,omitempty"`
	ActorID  string `json:"actor_id,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	// Resource carries the audit event's Reason field — for admin
	// mutations that is the "target=<resource>" reference; for other
	// events a short human-readable cause. Never credential material.
	Resource  string    `json:"resource,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Sink adapts the Broker to the audit Sink SPI: every recorded event
// is projected to a Summary and published. Write-only — reads are
// served by the primary sink in the MultiSink composition (the same
// contract as WebhookSink/WriterSink). Because the Recorder runs its
// Redactor BEFORE the sink, subscribers observe the same redacted
// ActorID the durable sink stored.
type Sink struct {
	b *Broker
}

// NewSink wires a Broker as an audit sink tap. Attach via
// Recorder.AddSink (or audit.NewMultiSink) during composition.
func NewSink(b *Broker) *Sink { return &Sink{b: b} }

// Record publishes the redacted summary. Never blocks: Publish evicts
// slow subscribers instead of waiting, so audit's hot path is bounded
// by a mutex-guarded channel send.
func (s *Sink) Record(_ context.Context, e *auditspi.Event) error {
	sum := Summary{
		ID:        e.ID,
		Type:      string(e.Type),
		Outcome:   string(e.Outcome),
		ActorID:   e.ActorID,
		TenantID:  e.TenantID,
		ClientID:  e.ClientID,
		Resource:  e.Reason,
		Timestamp: e.Timestamp,
	}
	data, err := json.Marshal(sum)
	if err != nil {
		return err
	}
	s.b.Publish(Event{Type: string(e.Type), TenantID: e.TenantID, Data: data})
	return nil
}

// Query implements the Sink SPI as write-only so MultiSink routes
// reads to the durable primary.
func (s *Sink) Query(context.Context, auditspi.Query) ([]*auditspi.Event, error) {
	return nil, auditsink.ErrSinkWriteOnly
}

// Get implements the Sink SPI as write-only.
func (s *Sink) Get(context.Context, string) (*auditspi.Event, error) {
	return nil, auditsink.ErrSinkWriteOnly
}

var _ auditspi.Sink = (*Sink)(nil)
