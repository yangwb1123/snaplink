package remote

import (
	"context"
	"errors"

	auditv1 "github.com/yangwb1123/snaplink/gen/proto/audit/v1"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient"
	"google.golang.org/grpc"
)

// AuditClient ships events to the SSO server's gRPC AuditWriter. The simple
// path is Record (unary); high-throughput callers can build a wrapper that
// keeps a StreamEvents open if every-event-per-rpc proves too chatty.
type AuditClient struct {
	c auditv1.AuditWriterClient
}

func NewAuditClient(conn *grpc.ClientConn) *AuditClient {
	return &AuditClient{c: auditv1.NewAuditWriterClient(conn)}
}

func (a *AuditClient) Record(ctx context.Context, e *ssoclient.Event) error {
	if e == nil {
		return errors.New("ssoclient/remote: event required")
	}
	in := &auditv1.Event{
		Id:            e.ID,
		Type:          string(e.Type),
		Outcome:       string(e.Outcome),
		RequestId:     e.RequestID,
		TraceId:       e.TraceID,
		SpanId:        e.SpanID,
		ParentSpanId:  e.ParentSpanID,
		ActorId:       e.ActorID,
		ActorIp:       e.ActorIP,
		UserAgent:     e.UserAgent,
		ClientId:      e.ClientID,
		Provider:      e.Provider,
		TokenStrategy: e.TokenStrategy,
		SessionId:     e.SessionID,
		TokenId:       e.TokenID,
		Reason:        e.Reason,
		Metadata:      e.Metadata,
	}
	if !e.Timestamp.IsZero() {
		in.TimestampUnix = e.Timestamp.Unix()
	}
	_, err := a.c.Record(ctx, in)
	return err
}

// Close is a no-op: the remote AuditClient does not own the gRPC conn, so
// the caller is responsible for conn.Close(). This keeps lifetime
// management with whoever set up the dial.
func (a *AuditClient) Close() error { return nil }
