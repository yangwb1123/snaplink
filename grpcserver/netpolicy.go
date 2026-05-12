package grpcserver

import (
	"context"
	"errors"
	"time"

	"github.com/snaplink/sso/audit"
	netpolicyv1 "github.com/snaplink/sso/gen/proto/netpolicy/v1"
	"github.com/snaplink/sso/netpolicy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// NetPolicyService implements netpolicyv1.PolicyServiceServer over a
// netpolicy.Store and an optional *netpolicy.Classifier (for the Classify
// RPC). Mutating RPCs (Apply, Delete) are mirrored to an audit.Recorder when
// one is wired in.
type NetPolicyService struct {
	netpolicyv1.UnimplementedPolicyServiceServer
	store      netpolicy.Store
	classifier *netpolicy.Classifier // optional
	recorder   *audit.Recorder       // optional
}

// NewNetPolicyService wires the gRPC adapter. classifier and recorder may be
// nil — Classify will return Unimplemented without a classifier; Apply/Delete
// silently skip audit when recorder is nil.
func NewNetPolicyService(store netpolicy.Store, classifier *netpolicy.Classifier, recorder *audit.Recorder) *NetPolicyService {
	return &NetPolicyService{store: store, classifier: classifier, recorder: recorder}
}

func (s *NetPolicyService) Get(ctx context.Context, in *netpolicyv1.GetRequest) (*netpolicyv1.GetResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "netpolicy store not configured")
	}
	if in == nil || in.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	p, err := s.store.Get(ctx, in.Name)
	if errors.Is(err, netpolicy.ErrNotFound) {
		return nil, status.Error(codes.NotFound, "policy not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get: %v", err)
	}
	return &netpolicyv1.GetResponse{Policy: policyToProto(p)}, nil
}

func (s *NetPolicyService) List(ctx context.Context, _ *netpolicyv1.ListRequest) (*netpolicyv1.ListResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "netpolicy store not configured")
	}
	all, err := s.store.List(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list: %v", err)
	}
	out := &netpolicyv1.ListResponse{Policies: make([]*netpolicyv1.NetworkPolicy, 0, len(all))}
	for _, p := range all {
		out.Policies = append(out.Policies, policyToProto(p))
	}
	return out, nil
}

func (s *NetPolicyService) Apply(ctx context.Context, in *netpolicyv1.ApplyRequest) (*netpolicyv1.ApplyResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "netpolicy store not configured")
	}
	if in == nil || in.Policy == nil || in.Policy.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "policy.name required")
	}
	stored, err := s.store.Apply(ctx, protoToPolicy(in.Policy))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "apply: %v", err)
	}
	s.recordAudit(ctx, audit.EventNetPolicyApply, stored.Name)
	return &netpolicyv1.ApplyResponse{Policy: policyToProto(stored)}, nil
}

func (s *NetPolicyService) Delete(ctx context.Context, in *netpolicyv1.DeleteRequest) (*netpolicyv1.DeleteResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "netpolicy store not configured")
	}
	if in == nil || in.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	if err := s.store.Delete(ctx, in.Name); err != nil {
		return nil, status.Errorf(codes.Internal, "delete: %v", err)
	}
	s.recordAudit(ctx, audit.EventNetPolicyDelete, in.Name)
	return &netpolicyv1.DeleteResponse{}, nil
}

func (s *NetPolicyService) Watch(_ *netpolicyv1.WatchRequest, stream grpc.ServerStreamingServer[netpolicyv1.PolicyEvent]) error {
	if s.store == nil {
		return status.Error(codes.FailedPrecondition, "netpolicy store not configured")
	}
	ctx := stream.Context()
	ch, err := s.store.Watch(ctx)
	if err != nil {
		return status.Errorf(codes.Internal, "watch: %v", err)
	}
	// Flush initial headers so clients can synchronize against subscription-
	// ready before issuing mutations whose events they expect to receive.
	_ = stream.SendHeader(metadata.MD{})
	for evt := range ch {
		if evt.Policy == nil {
			continue
		}
		if err := stream.Send(&netpolicyv1.PolicyEvent{
			Type:   eventTypeToNetProto(evt.Type),
			Policy: policyToProto(evt.Policy),
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *NetPolicyService) Classify(_ context.Context, in *netpolicyv1.ClassifyRequest) (*netpolicyv1.ClassifyResponse, error) {
	if s.classifier == nil {
		return nil, status.Error(codes.Unimplemented, "classifier not configured")
	}
	if in == nil {
		return nil, status.Error(codes.InvalidArgument, "request required")
	}
	p := s.classifier.Classify(in.RemoteAddr, in.Host)
	if p == nil {
		return &netpolicyv1.ClassifyResponse{}, nil
	}
	return &netpolicyv1.ClassifyResponse{Class: p.Name, Policy: policyToProto(p)}, nil
}

func (s *NetPolicyService) recordAudit(ctx context.Context, t audit.EventType, target string) {
	if s.recorder == nil {
		return
	}
	s.recorder.Record(ctx, &audit.Event{
		Type:    t,
		Outcome: audit.OutcomeSuccess,
		Reason:  "name=" + target,
	})
}

func policyToProto(p *netpolicy.Policy) *netpolicyv1.NetworkPolicy {
	if p == nil {
		return nil
	}
	return &netpolicyv1.NetworkPolicy{
		Name:                p.Name,
		Cidrs:               append([]string(nil), p.CIDRs...),
		Hostnames:           append([]string(nil), p.Hostnames...),
		Priority:            p.Priority,
		AdvertisedBaseUrl:   p.AdvertisedBaseURL,
		AdvertisedJwksUrl:   p.AdvertisedJWKSURL,
		AdvertisedLogoutUrl: p.AdvertisedLogoutURL,
		Metadata:            p.Metadata,
		Version:             p.Version,
		UpdatedAtUnix:       p.UpdatedAt.Unix(),
	}
}

func protoToPolicy(in *netpolicyv1.NetworkPolicy) *netpolicy.Policy {
	if in == nil {
		return nil
	}
	p := &netpolicy.Policy{
		Name:                in.Name,
		CIDRs:               append([]string(nil), in.Cidrs...),
		Hostnames:           append([]string(nil), in.Hostnames...),
		Priority:            in.Priority,
		AdvertisedBaseURL:   in.AdvertisedBaseUrl,
		AdvertisedJWKSURL:   in.AdvertisedJwksUrl,
		AdvertisedLogoutURL: in.AdvertisedLogoutUrl,
		Metadata:            in.Metadata,
	}
	if in.UpdatedAtUnix != 0 {
		p.UpdatedAt = time.Unix(in.UpdatedAtUnix, 0)
	}
	return p
}

func eventTypeToNetProto(t netpolicy.EventType) netpolicyv1.EventType {
	switch t {
	case netpolicy.EventAdded:
		return netpolicyv1.EventType_EVENT_TYPE_ADDED
	case netpolicy.EventUpdated:
		return netpolicyv1.EventType_EVENT_TYPE_UPDATED
	case netpolicy.EventRemoved:
		return netpolicyv1.EventType_EVENT_TYPE_REMOVED
	default:
		return netpolicyv1.EventType_EVENT_TYPE_UNSPECIFIED
	}
}
