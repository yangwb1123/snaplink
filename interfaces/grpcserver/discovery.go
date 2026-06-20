package grpcserver

import (
	"context"
	"errors"
	"time"

	discoveryv1 "github.com/snaplink/sso/gen/proto/discovery/v1"
	"github.com/snaplink/sso/platform/registry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// DiscoveryService implements discoveryv1.DiscoveryServer over a registry.Registry.
type DiscoveryService struct {
	discoveryv1.UnimplementedDiscoveryServer
	reg registry.Registry
}

func NewDiscoveryService(r registry.Registry) *DiscoveryService {
	return &DiscoveryService{reg: r}
}

func (s *DiscoveryService) Register(ctx context.Context, in *discoveryv1.RegisterRequest) (*discoveryv1.RegisterResponse, error) {
	if s.reg == nil {
		return nil, status.Error(codes.FailedPrecondition, "registry not configured")
	}
	if in.Service == nil {
		return nil, status.Error(codes.InvalidArgument, "service required")
	}
	if err := s.reg.Register(ctx, protoToService(in.Service)); err != nil {
		return nil, status.Errorf(codes.Internal, "register: %v", err)
	}
	return &discoveryv1.RegisterResponse{}, nil
}

func (s *DiscoveryService) Deregister(ctx context.Context, in *discoveryv1.DeregisterRequest) (*discoveryv1.DeregisterResponse, error) {
	if s.reg == nil {
		return nil, status.Error(codes.FailedPrecondition, "registry not configured")
	}
	if err := s.reg.Deregister(ctx, in.InstanceId); err != nil {
		return nil, status.Errorf(codes.Internal, "deregister: %v", err)
	}
	return &discoveryv1.DeregisterResponse{}, nil
}

func (s *DiscoveryService) Discover(ctx context.Context, in *discoveryv1.DiscoverRequest) (*discoveryv1.DiscoverResponse, error) {
	if s.reg == nil {
		return nil, status.Error(codes.FailedPrecondition, "registry not configured")
	}
	instances, err := s.reg.Discover(ctx, in.ServiceName)
	if err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "service not found")
		}
		return nil, status.Errorf(codes.Internal, "discover: %v", err)
	}
	out := &discoveryv1.DiscoverResponse{Instances: make([]*discoveryv1.Service, 0, len(instances))}
	for _, svc := range instances {
		out.Instances = append(out.Instances, serviceToProto(svc))
	}
	return out, nil
}

func (s *DiscoveryService) Watch(in *discoveryv1.WatchRequest, stream grpc.ServerStreamingServer[discoveryv1.ServiceEvent]) error {
	if s.reg == nil {
		return status.Error(codes.FailedPrecondition, "registry not configured")
	}
	ctx := stream.Context()
	ch, err := s.reg.Watch(ctx, in.ServiceName)
	if err != nil {
		return status.Errorf(codes.Internal, "watch: %v", err)
	}
	// Flush headers so the client knows the subscription is live before
	// it issues mutations whose events it expects to receive. Without this,
	// client.Watch returns before the server handler has actually subscribed
	// and early events can be missed.
	_ = stream.SendHeader(metadata.MD{})
	for evt := range ch {
		if err := stream.Send(&discoveryv1.ServiceEvent{
			Type:    eventTypeToProto(evt.Type),
			Service: serviceToProto(evt.Service),
		}); err != nil {
			return err
		}
	}
	return nil
}

func protoToService(in *discoveryv1.Service) *registry.Service {
	if in == nil {
		return nil
	}
	return &registry.Service{
		ID:       in.Id,
		Name:     in.Name,
		Address:  in.Address,
		Port:     int(in.Port),
		Tags:     append([]string{}, in.Tags...),
		Metadata: in.Metadata,
		Version:  in.Version,
		TTL:      time.Duration(in.TtlSeconds) * time.Second,
	}
}

func serviceToProto(in *registry.Service) *discoveryv1.Service {
	if in == nil {
		return nil
	}
	return &discoveryv1.Service{
		Id:         in.ID,
		Name:       in.Name,
		Address:    in.Address,
		Port:       int32(in.Port),
		Tags:       append([]string{}, in.Tags...),
		Metadata:   in.Metadata,
		Version:    in.Version,
		TtlSeconds: int64(in.TTL / time.Second),
	}
}

func eventTypeToProto(t registry.EventType) discoveryv1.EventType {
	switch t {
	case registry.EventAdded:
		return discoveryv1.EventType_EVENT_TYPE_ADDED
	case registry.EventRemoved:
		return discoveryv1.EventType_EVENT_TYPE_REMOVED
	case registry.EventUpdated:
		return discoveryv1.EventType_EVENT_TYPE_UPDATED
	default:
		return discoveryv1.EventType_EVENT_TYPE_UNSPECIFIED
	}
}
