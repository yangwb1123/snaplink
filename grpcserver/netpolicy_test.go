package grpcserver_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/snaplink/sso/audit"
	netpolicyv1 "github.com/snaplink/sso/gen/proto/netpolicy/v1"
	"github.com/snaplink/sso/grpcserver"
	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/netpolicy/memory"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// startNetPolicyGRPC stands up a bufconn-backed gRPC server with the
// PolicyService registered. classifier and recorder may be nil.
func startNetPolicyGRPC(t *testing.T, store netpolicy.Store, c *netpolicy.Classifier, r *audit.Recorder) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	netpolicyv1.RegisterPolicyServiceServer(srv, grpcserver.NewNetPolicyService(store, c, r))
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	})
	return conn
}

func TestNetPolicy_ApplyGet(t *testing.T) {
	store := memory.New()
	defer func() { _ = store.Close() }()
	conn := startNetPolicyGRPC(t, store, nil, nil)
	c := netpolicyv1.NewPolicyServiceClient(conn)

	_, err := c.Apply(context.Background(), &netpolicyv1.ApplyRequest{
		Policy: &netpolicyv1.NetworkPolicy{Name: "intranet", Cidrs: []string{"10.0.0.0/8"}, Priority: 100},
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	resp, err := c.Get(context.Background(), &netpolicyv1.GetRequest{Name: "intranet"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.Policy.Name != "intranet" || resp.Policy.Priority != 100 {
		t.Errorf("got %+v", resp.Policy)
	}
	if resp.Policy.Version == 0 {
		t.Error("Version not stamped")
	}
}

func TestNetPolicy_GetUnknownIsNotFound(t *testing.T) {
	store := memory.New()
	defer func() { _ = store.Close() }()
	conn := startNetPolicyGRPC(t, store, nil, nil)
	c := netpolicyv1.NewPolicyServiceClient(conn)
	_, err := c.Get(context.Background(), &netpolicyv1.GetRequest{Name: "ghost"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", err)
	}
}

func TestNetPolicy_ApplyMissingNameIsInvalidArgument(t *testing.T) {
	store := memory.New()
	defer func() { _ = store.Close() }()
	conn := startNetPolicyGRPC(t, store, nil, nil)
	c := netpolicyv1.NewPolicyServiceClient(conn)
	_, err := c.Apply(context.Background(), &netpolicyv1.ApplyRequest{Policy: &netpolicyv1.NetworkPolicy{}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestNetPolicy_ApplyWritesAuditEvent(t *testing.T) {
	store := memory.New()
	defer func() { _ = store.Close() }()
	sink := audit.NewMemorySink(10)
	recorder := audit.New(sink)
	conn := startNetPolicyGRPC(t, store, nil, recorder)
	c := netpolicyv1.NewPolicyServiceClient(conn)

	if _, err := c.Apply(context.Background(), &netpolicyv1.ApplyRequest{
		Policy: &netpolicyv1.NetworkPolicy{Name: "x"},
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := c.Delete(context.Background(), &netpolicyv1.DeleteRequest{Name: "x"}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if sink.Len() != 2 {
		t.Fatalf("expected 2 audit events, got %d", sink.Len())
	}
	evts, _ := sink.Query(context.Background(), audit.Query{Limit: 10})
	types := []audit.EventType{evts[0].Type, evts[1].Type}
	want := map[audit.EventType]bool{
		audit.EventNetPolicyApply:  true,
		audit.EventNetPolicyDelete: true,
	}
	for _, tp := range types {
		if !want[tp] {
			t.Errorf("unexpected audit type %s", tp)
		}
	}
}

func TestNetPolicy_DeleteIsIdempotent(t *testing.T) {
	store := memory.New()
	defer func() { _ = store.Close() }()
	conn := startNetPolicyGRPC(t, store, nil, nil)
	c := netpolicyv1.NewPolicyServiceClient(conn)
	if _, err := c.Delete(context.Background(), &netpolicyv1.DeleteRequest{Name: "ghost"}); err != nil {
		t.Fatalf("Delete of missing should succeed: %v", err)
	}
}

func TestNetPolicy_WatchStreamsAfterHeader(t *testing.T) {
	store := memory.New()
	defer func() { _ = store.Close() }()
	conn := startNetPolicyGRPC(t, store, nil, nil)
	c := netpolicyv1.NewPolicyServiceClient(conn)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := c.Watch(ctx, &netpolicyv1.WatchRequest{})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	// Block until subscription is live.
	if _, err := stream.Header(); err != nil {
		t.Fatalf("Header: %v", err)
	}

	pcli := netpolicyv1.NewPolicyServiceClient(conn)
	go func() {
		_, _ = pcli.Apply(context.Background(), &netpolicyv1.ApplyRequest{
			Policy: &netpolicyv1.NetworkPolicy{Name: "p"},
		})
		_, _ = pcli.Delete(context.Background(), &netpolicyv1.DeleteRequest{Name: "p"})
	}()

	type result struct {
		evt *netpolicyv1.PolicyEvent
		err error
	}
	for _, want := range []netpolicyv1.EventType{
		netpolicyv1.EventType_EVENT_TYPE_ADDED,
		netpolicyv1.EventType_EVENT_TYPE_REMOVED,
	} {
		ch := make(chan result, 1)
		go func() {
			evt, err := stream.Recv()
			ch <- result{evt, err}
		}()
		select {
		case r := <-ch:
			if r.err != nil {
				t.Fatalf("Recv: %v", r.err)
			}
			if r.evt.Type != want {
				t.Errorf("got %v, want %v", r.evt.Type, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting for %v", want)
		}
	}
}

func TestNetPolicy_Classify(t *testing.T) {
	store := memory.New()
	defer func() { _ = store.Close() }()
	_, _ = store.Apply(context.Background(), &netpolicy.Policy{
		Name: "intranet", CIDRs: []string{"10.0.0.0/8"},
	})
	classifier := netpolicy.NewClassifier()
	_ = classifier.Reload(context.Background(), store)

	conn := startNetPolicyGRPC(t, store, classifier, nil)
	c := netpolicyv1.NewPolicyServiceClient(conn)

	resp, err := c.Classify(context.Background(), &netpolicyv1.ClassifyRequest{RemoteAddr: "10.1.2.3"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if resp.Class != "intranet" {
		t.Errorf("class = %q", resp.Class)
	}
}

func TestNetPolicy_ClassifyWithoutClassifierIsUnimplemented(t *testing.T) {
	store := memory.New()
	defer func() { _ = store.Close() }()
	conn := startNetPolicyGRPC(t, store, nil, nil)
	c := netpolicyv1.NewPolicyServiceClient(conn)
	_, err := c.Classify(context.Background(), &netpolicyv1.ClassifyRequest{RemoteAddr: "1.2.3.4"})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected Unimplemented, got %v", err)
	}
}
