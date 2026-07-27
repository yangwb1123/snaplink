package grpcadmin

import (
	"context"
	"net"
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// TestRecordAdmin_NilRecorderIsNoop proves the documented "safe to call with
// a nil recorder" contract: every mutating RPC calls recordAdmin
// unconditionally, so a server wired without an audit recorder must not
// panic on every single admin mutation.
func TestRecordAdmin_NilRecorderIsNoop(t *testing.T) {
	t.Parallel()
	// The mere absence of a panic is the assertion.
	recordAdmin(context.Background(), nil, audit.EventAdminClientCreated, "client-1")
}

// TestRecordAdmin_PlainContextIsNoopForActorPeerAndUA proves recordAdmin
// degrades gracefully when the context carries none of the optional
// extraction sources (no admin actor, no gRPC peer, no incoming metadata) —
// the event is still recorded, just with those fields empty. This is the
// only actor-context case exercisable from outside interfaces/admin: the
// context key that carries the actor (sso.AdminActorFromContext's backing
// store) is unexported to that package, so a white-box test in grpcadmin
// cannot fabricate an "actor present" context directly. The interceptor
// wiring itself is covered in interfaces/admin.
func TestRecordAdmin_PlainContextIsNoopForActorPeerAndUA(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(10)
	rec := audit.New(sink)

	recordAdmin(context.Background(), rec, audit.EventAdminUserDeleted, "user-42")

	events, err := sink.Query(context.Background(), audit.Query{})
	requireOK(t, err, "Query")
	if len(events) != 1 {
		t.Fatalf("expected 1 recorded event, got %d", len(events))
	}
	e := events[0]
	if e.Type != audit.EventAdminUserDeleted {
		t.Errorf("Type = %q, want %q", e.Type, audit.EventAdminUserDeleted)
	}
	if e.Reason != "target=user-42" {
		t.Errorf("Reason = %q, want %q", e.Reason, "target=user-42")
	}
	if e.Outcome != audit.OutcomeSuccess {
		t.Errorf("Outcome = %q, want %q", e.Outcome, audit.OutcomeSuccess)
	}
	if e.ActorID != "" || e.ClientID != "" {
		t.Errorf("expected no actor stamped from a plain context, got ActorID=%q ClientID=%q", e.ActorID, e.ClientID)
	}
	if e.ActorIP != "" {
		t.Errorf("expected no ActorIP without a gRPC peer, got %q", e.ActorIP)
	}
	if e.UserAgent != "" {
		t.Errorf("expected no UserAgent without incoming metadata, got %q", e.UserAgent)
	}
}

// TestRecordAdmin_ExtractsPeerAndUserAgent proves the two extraction paths
// that ARE reachable from this package: gRPC peer.Addr -> ActorIP, and the
// incoming "user-agent" metadata key -> UserAgent. Both are set the same way
// the real gRPC transport sets them on an inbound call.
func TestRecordAdmin_ExtractsPeerAndUserAgent(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(10)
	rec := audit.New(sink)

	addr := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 443}
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: addr})
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("user-agent", "admin-cli/1.0"))

	recordAdmin(ctx, rec, audit.EventAdminClientSecretRotated, "client-9")

	events, err := sink.Query(context.Background(), audit.Query{Type: audit.EventAdminClientSecretRotated})
	requireOK(t, err, "Query")
	if len(events) != 1 {
		t.Fatalf("expected 1 recorded event, got %d", len(events))
	}
	e := events[0]
	if e.ActorIP != addr.String() {
		t.Errorf("ActorIP = %q, want %q", e.ActorIP, addr.String())
	}
	if e.UserAgent != "admin-cli/1.0" {
		t.Errorf("UserAgent = %q, want %q", e.UserAgent, "admin-cli/1.0")
	}
}

// TestRecordAdmin_NilPeerInContextIsSafe proves the peer.FromContext(ctx)
// "ok but p is nil" edge case (peer.NewContext with a nil *peer.Peer) does
// not panic — recordAdmin explicitly guards on p != nil, not just ok.
func TestRecordAdmin_NilPeerInContextIsSafe(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(10)
	rec := audit.New(sink)
	var nilPeer *peer.Peer
	ctx := peer.NewContext(context.Background(), nilPeer)

	recordAdmin(ctx, rec, audit.EventAdminDomainCreated, "example.com")

	events, err := sink.Query(context.Background(), audit.Query{Type: audit.EventAdminDomainCreated})
	requireOK(t, err, "Query")
	if len(events) != 1 {
		t.Fatalf("expected 1 recorded event, got %d", len(events))
	}
	if events[0].ActorIP != "" {
		t.Errorf("expected no ActorIP from a nil peer, got %q", events[0].ActorIP)
	}
}
