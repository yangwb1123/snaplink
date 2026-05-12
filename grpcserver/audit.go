// Package grpcserver wires the snaplink/sso domain types
// (audit.Recorder, permissions.Provider, registry.Registry) to gRPC service
// interfaces generated from proto/. The handlers are intentionally thin —
// they translate between proto messages and Go types and delegate
// everything else to the underlying SDK component, so business logic lives
// in exactly one place.
package grpcserver

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/snaplink/sso/audit"
	auditv1 "github.com/snaplink/sso/gen/proto/audit/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuditService implements auditv1.AuditWriterServer over an audit.Recorder.
type AuditService struct {
	auditv1.UnimplementedAuditWriterServer
	recorder *audit.Recorder
}

// NewAuditService returns a service that writes through to recorder.
// recorder must be non-nil; nil-Recorder events are silently dropped on
// the SDK side, but accepting nil here would surface as confusing 200-OK
// responses with no persistence.
func NewAuditService(recorder *audit.Recorder) *AuditService {
	return &AuditService{recorder: recorder}
}

// Record handles the unary single-event RPC.
func (s *AuditService) Record(ctx context.Context, in *auditv1.Event) (*auditv1.RecordAck, error) {
	if s.recorder == nil {
		return nil, status.Error(codes.FailedPrecondition, "audit recorder not configured")
	}
	if in == nil {
		return nil, status.Error(codes.InvalidArgument, "event required")
	}
	evt := protoToEvent(in)
	s.recorder.Record(ctx, evt)
	return &auditv1.RecordAck{Id: evt.ID}, nil
}

// StreamEvents drains events from the client until the send half closes,
// recording each one. The terminal StreamAck reports counts so the client
// can detect partial losses.
func (s *AuditService) StreamEvents(stream grpc.ClientStreamingServer[auditv1.Event, auditv1.StreamAck]) error {
	if s.recorder == nil {
		return status.Error(codes.FailedPrecondition, "audit recorder not configured")
	}
	var received, persisted int64
	ctx := stream.Context()
	for {
		in, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&auditv1.StreamAck{
				ReceivedCount:  received,
				PersistedCount: persisted,
			})
		}
		if err != nil {
			return err
		}
		received++
		s.recorder.Record(ctx, protoToEvent(in))
		persisted++
	}
}

func protoToEvent(in *auditv1.Event) *audit.Event {
	e := &audit.Event{
		ID:            in.Id,
		Type:          audit.EventType(in.Type),
		Outcome:       audit.Outcome(in.Outcome),
		RequestID:     in.RequestId,
		TraceID:       in.TraceId,
		SpanID:        in.SpanId,
		ParentSpanID:  in.ParentSpanId,
		ActorID:       in.ActorId,
		ActorIP:       in.ActorIp,
		UserAgent:     in.UserAgent,
		ClientID:      in.ClientId,
		Provider:      in.Provider,
		TokenStrategy: in.TokenStrategy,
		SessionID:     in.SessionId,
		TokenID:       in.TokenId,
		Reason:        in.Reason,
		Metadata:      in.Metadata,
	}
	if in.TimestampUnix != 0 {
		e.Timestamp = time.Unix(in.TimestampUnix, 0)
	}
	return e
}
