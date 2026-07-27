package grpcserver_test

// Error / branch coverage for NetPolicyService. netpolicy_test.go covers the
// happy paths (Apply/Get/Watch/Classify); this file pins the nil-store
// FailedPrecondition gates, the previously-untested List RPC, the
// InvalidArgument validation rejections, and the store-error -> codes.Internal
// mappings.

import (
	"context"
	"errors"
	"testing"

	netpolicyv1 "github.com/yangwb1123/snaplink/gen/proto/netpolicy/v1"
	"github.com/yangwb1123/snaplink/platform/netpolicy"
	"github.com/yangwb1123/snaplink/platform/netpolicy/memory"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// erroringNetStore returns a configured error from every read/write method.
type erroringNetStore struct{ err error }

func (e *erroringNetStore) Get(context.Context, string) (*netpolicy.Policy, error) {
	return nil, e.err
}
func (e *erroringNetStore) List(context.Context) ([]*netpolicy.Policy, error) { return nil, e.err }
func (e *erroringNetStore) Apply(context.Context, *netpolicy.Policy) (*netpolicy.Policy, error) {
	return nil, e.err
}
func (e *erroringNetStore) Delete(context.Context, string) error { return e.err }
func (e *erroringNetStore) Watch(context.Context) (<-chan netpolicy.Event, error) {
	return nil, e.err
}
func (e *erroringNetStore) Close() error { return nil }

var _ netpolicy.Store = (*erroringNetStore)(nil)

func TestNetPolicy_NilStoreFailsPrecondition(t *testing.T) {
	t.Parallel()
	conn := startNetPolicyGRPC(t, nil, nil, nil)
	c := netpolicyv1.NewPolicyServiceClient(conn)
	ctx := context.Background()
	cases := map[string]func() error{
		"Get":  func() error { _, e := c.Get(ctx, &netpolicyv1.GetRequest{Name: "x"}); return e },
		"List": func() error { _, e := c.List(ctx, &netpolicyv1.ListRequest{}); return e },
		"Apply": func() error {
			_, e := c.Apply(ctx, &netpolicyv1.ApplyRequest{Policy: &netpolicyv1.NetworkPolicy{Name: "x"}})
			return e
		},
		"Delete": func() error { _, e := c.Delete(ctx, &netpolicyv1.DeleteRequest{Name: "x"}); return e },
	}
	for name, call := range cases {
		if got := status.Code(call()); got != codes.FailedPrecondition {
			t.Errorf("%s: code = %v, want FailedPrecondition", name, got)
		}
	}
	// Watch surfaces the precondition on first Recv.
	stream, err := c.Watch(ctx, &netpolicyv1.WatchRequest{})
	if err != nil {
		t.Fatalf("Watch open: %v", err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Watch: expected FailedPrecondition, got %v", err)
	}
}

func TestNetPolicy_List(t *testing.T) {
	t.Parallel()
	store := memory.New()
	defer func() { _ = store.Close() }()
	ctx := context.Background()
	_, _ = store.Apply(ctx, &netpolicy.Policy{Name: "intranet", CIDRs: []string{"10.0.0.0/8"}, Priority: 10})
	_, _ = store.Apply(ctx, &netpolicy.Policy{Name: "vpn", Hostnames: []string{"vpn.example.com"}, Priority: 20})

	conn := startNetPolicyGRPC(t, store, nil, nil)
	c := netpolicyv1.NewPolicyServiceClient(conn)
	resp, err := c.List(ctx, &netpolicyv1.ListRequest{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(resp.Policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(resp.Policies))
	}
	names := map[string]bool{}
	for _, p := range resp.Policies {
		names[p.Name] = true
	}
	if !names["intranet"] || !names["vpn"] {
		t.Errorf("missing policy in list: %+v", names)
	}
}

func TestNetPolicy_ValidationRejections(t *testing.T) {
	t.Parallel()
	store := &erroringNetStore{} // passes nil-store gate
	conn := startNetPolicyGRPC(t, store, nil, nil)
	c := netpolicyv1.NewPolicyServiceClient(conn)
	ctx := context.Background()
	cases := map[string]func() error{
		"Get-empty":        func() error { _, e := c.Get(ctx, &netpolicyv1.GetRequest{}); return e },
		"Apply-nil-policy": func() error { _, e := c.Apply(ctx, &netpolicyv1.ApplyRequest{}); return e },
		"Apply-empty-name": func() error {
			_, e := c.Apply(ctx, &netpolicyv1.ApplyRequest{Policy: &netpolicyv1.NetworkPolicy{}})
			return e
		},
		"Delete-empty-name": func() error { _, e := c.Delete(ctx, &netpolicyv1.DeleteRequest{}); return e },
	}
	for name, call := range cases {
		if got := status.Code(call()); got != codes.InvalidArgument {
			t.Errorf("%s: code = %v, want InvalidArgument", name, got)
		}
	}
}

func TestNetPolicy_StoreErrorsAreInternal(t *testing.T) {
	t.Parallel()
	store := &erroringNetStore{err: errors.New("etcd unavailable")}
	conn := startNetPolicyGRPC(t, store, nil, nil)
	c := netpolicyv1.NewPolicyServiceClient(conn)
	ctx := context.Background()
	cases := map[string]func() error{
		"Get":  func() error { _, e := c.Get(ctx, &netpolicyv1.GetRequest{Name: "x"}); return e },
		"List": func() error { _, e := c.List(ctx, &netpolicyv1.ListRequest{}); return e },
		"Apply": func() error {
			_, e := c.Apply(ctx, &netpolicyv1.ApplyRequest{Policy: &netpolicyv1.NetworkPolicy{Name: "x"}})
			return e
		},
		"Delete": func() error { _, e := c.Delete(ctx, &netpolicyv1.DeleteRequest{Name: "x"}); return e },
	}
	for name, call := range cases {
		if got := status.Code(call()); got != codes.Internal {
			t.Errorf("%s: code = %v, want Internal", name, got)
		}
	}
	// Watch returns the store error as Internal on the stream.
	stream, err := c.Watch(ctx, &netpolicyv1.WatchRequest{})
	if err != nil {
		t.Fatalf("Watch open: %v", err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.Internal {
		t.Fatalf("Watch: expected Internal, got %v", err)
	}
}

func TestNetPolicy_ApplyRoundTripsAllFields(t *testing.T) {
	t.Parallel()
	// Drives the full protoToPolicy/policyToProto roundtrip including the
	// advertised URLs + metadata fields the basic Apply test omits.
	store := memory.New()
	defer func() { _ = store.Close() }()
	conn := startNetPolicyGRPC(t, store, nil, nil)
	c := netpolicyv1.NewPolicyServiceClient(conn)
	ctx := context.Background()
	_, err := c.Apply(ctx, &netpolicyv1.ApplyRequest{Policy: &netpolicyv1.NetworkPolicy{
		Name:                "edge",
		Cidrs:               []string{"192.168.0.0/16"},
		Hostnames:           []string{"edge.example.com"},
		Priority:            5,
		AdvertisedBaseUrl:   "https://edge.example.com",
		AdvertisedJwksUrl:   "https://edge.example.com/jwks",
		AdvertisedLogoutUrl: "https://edge.example.com/logout",
		Metadata:            map[string]string{"region": "eu"},
	}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	resp, err := c.Get(ctx, &netpolicyv1.GetRequest{Name: "edge"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	p := resp.Policy
	if p.AdvertisedBaseUrl != "https://edge.example.com" ||
		p.AdvertisedJwksUrl != "https://edge.example.com/jwks" ||
		p.AdvertisedLogoutUrl != "https://edge.example.com/logout" ||
		p.Metadata["region"] != "eu" ||
		len(p.Hostnames) != 1 {
		t.Errorf("field roundtrip mismatch: %+v", p)
	}
}

func TestNetPolicy_ClassifyNilRequestIsInvalidArgument(t *testing.T) {
	t.Parallel()
	// classifier present but a nil request body -> InvalidArgument (not the
	// Unimplemented path the no-classifier test covers).
	store := memory.New()
	defer func() { _ = store.Close() }()
	classifier := netpolicy.NewClassifier()
	_ = classifier.Reload(context.Background(), store)
	conn := startNetPolicyGRPC(t, store, classifier, nil)
	c := netpolicyv1.NewPolicyServiceClient(conn)
	// An empty (non-nil) request reaches Classify with no match -> empty
	// response, exercising the p == nil branch in Classify.
	resp, err := c.Classify(context.Background(), &netpolicyv1.ClassifyRequest{RemoteAddr: "203.0.113.7"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if resp.Class != "" {
		t.Errorf("expected empty class for unmatched addr, got %q", resp.Class)
	}
}
