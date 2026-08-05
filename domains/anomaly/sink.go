package anomaly

import (
	"context"
	"strconv"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// Sink is what the runner does with each [Signal] surfaced
// by a detector. Implementations typically write an audit event +
// optionally fan out to a webhook / SIEM / SMTP notifier. The SSO
// server ships [NewRecorderSink] which writes an
// [audit.EventAnomalyDetected] event with the standard metadata
// shape — most embedders use that.
type Sink interface {
	Record(ctx context.Context, event *LoginEvent, anomaly Signal) error
}

// SinkFunc is a function adapter for Sink.
type SinkFunc func(ctx context.Context, event *LoginEvent, anomaly Signal) error

// Record implements Sink.
func (f SinkFunc) Record(ctx context.Context, event *LoginEvent, anomaly Signal) error {
	return f(ctx, event, anomaly)
}

// NewRecorderSink is the standard [Sink] that writes
// each anomaly as an [audit.EventAnomalyDetected] event into the
// supplied recorder. The audit event carries:
//
//   - Type:      audit.EventAnomalyDetected
//   - Outcome:   audit.OutcomeFailure (anomaly = something to look at)
//   - ActorID:   anomaly.SubjectID (falls back to event.SubjectID)
//   - ClientID:  event.ClientID
//   - Provider:  event.Provider
//   - Reason:    anomaly.Type ("impossible_travel", etc)
//   - Metadata:  anomaly.Evidence keys PLUS "anomaly.severity",
//     "anomaly.score" derived from the Signal struct.
//
// Use this when you want anomalies in the standard audit query
// surface (recommended). For SIEM-only routing, implement
// Sink directly without touching the recorder.
func NewRecorderSink(recorder *audit.Recorder) Sink {
	if recorder == nil {
		return nil
	}
	return SinkFunc(func(ctx context.Context, event *LoginEvent, a Signal) error {
		actor := a.SubjectID
		if actor == "" {
			actor = event.SubjectID
		}
		e := &audit.Event{
			Type:     audit.EventAnomalyDetected,
			Outcome:  audit.OutcomeFailure,
			ActorID:  actor,
			ActorIP:  event.RemoteIP,
			ClientID: event.ClientID,
			Provider: event.Provider,
			Reason:   a.Type,
			TraceID:  event.TraceID,
		}
		// Tenant-stamp the audit event from the event itself (the
		// runner is off the request path, so ctx routing cannot help)
		// — mirrors EnrichTenant's metadata vocabulary.
		if event.TenantID != "" {
			e.TenantID = event.TenantID
			audit.SetMeta(e, "tenant.id", event.TenantID)
		}
		audit.SetMeta(e, "anomaly.severity", string(a.Severity))
		if a.Score > 0 {
			audit.SetMeta(e, "anomaly.score", strconv.Itoa(a.Score))
		}
		for k, v := range a.Evidence {
			audit.SetMeta(e, k, v)
		}
		recorder.Record(ctx, e)
		return nil
	})
}
