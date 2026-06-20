package grpcadmin

import (
	"context"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// recordAdmin writes one audit event with the ActorID + IP + UA derived from
// the gRPC context. The admin interceptor in the sso package stashes the
// actor's userID + clientID via sso.AdminActorFromContext; we read it back
// here. Safe to call with a nil recorder — checking saves work.
func recordAdmin(ctx context.Context, recorder *audit.Recorder, t audit.EventType, target string) {
	if recorder == nil {
		return
	}
	evt := &audit.Event{
		Type:      t,
		Outcome:   audit.OutcomeSuccess,
		Timestamp: time.Now().UTC(),
		Reason:    "target=" + target,
	}
	if userID, clientID, ok := sso.AdminActorFromContext(ctx); ok {
		evt.ActorID = userID
		evt.ClientID = clientID
	}
	if p, ok := peer.FromContext(ctx); ok && p != nil {
		evt.ActorIP = p.Addr.String()
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if ua := md.Get("user-agent"); len(ua) > 0 {
			evt.UserAgent = ua[0]
		}
	}
	recorder.Record(ctx, evt)
}
