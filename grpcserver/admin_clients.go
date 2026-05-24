package grpcserver

import (
	"context"
	"errors"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ClientAdminService implements admin CRUD over a sso.ClientStore. Secrets
// are never echoed in List/Get/Update responses — RotateSecret is the only
// RPC that returns one.
type ClientAdminService struct {
	adminv1.UnimplementedClientAdminServiceServer
	store    sso.ClientStore
	recorder *audit.Recorder
	// onDiscoveryChange is invoked after a mutation that alters the
	// discovery document (client scopes feed the discovery scope union).
	// Wire it to (*sso.Server).InvalidateDiscoveryCache so a client edit
	// converges across replicas immediately. nil = no-op.
	onDiscoveryChange func()
}

// NewClientAdminService builds the service. onDiscoveryChange may be nil
// (e.g. when no discovery cache / bus is wired); pass
// (*sso.Server).InvalidateDiscoveryCache to propagate client edits.
func NewClientAdminService(store sso.ClientStore, recorder *audit.Recorder, onDiscoveryChange func()) *ClientAdminService {
	if onDiscoveryChange == nil {
		onDiscoveryChange = func() {}
	}
	return &ClientAdminService{store: store, recorder: recorder, onDiscoveryChange: onDiscoveryChange}
}

func (s *ClientAdminService) List(ctx context.Context, _ *adminv1.ListClientsRequest) (*adminv1.ListClientsResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "client store not configured")
	}
	all, err := s.store.List(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list: %v", err)
	}
	out := &adminv1.ListClientsResponse{Clients: make([]*adminv1.Client, 0, len(all))}
	for _, c := range all {
		out.Clients = append(out.Clients, clientToProto(c, false))
	}
	return out, nil
}

func (s *ClientAdminService) Get(ctx context.Context, in *adminv1.GetClientRequest) (*adminv1.GetClientResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "client store not configured")
	}
	if in == nil || in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	c, err := s.store.Get(ctx, in.Id)
	if errors.Is(err, sso.ErrNoSuchClient) {
		return nil, status.Error(codes.NotFound, "client not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get: %v", err)
	}
	return &adminv1.GetClientResponse{Client: clientToProto(c, false)}, nil
}

func (s *ClientAdminService) Create(ctx context.Context, in *adminv1.CreateClientRequest) (*adminv1.CreateClientResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "client store not configured")
	}
	if in == nil || in.Client == nil || in.Client.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "client.id required")
	}
	c := protoToClient(in.Client)
	if err := s.store.Add(ctx, c); err != nil {
		if errors.Is(err, sso.ErrClientExists) {
			return nil, status.Error(codes.AlreadyExists, "client already exists")
		}
		return nil, status.Errorf(codes.Internal, "create: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminClientCreated, c.ID)
	s.onDiscoveryChange()
	return &adminv1.CreateClientResponse{Client: clientToProto(c, false)}, nil
}

func (s *ClientAdminService) Update(ctx context.Context, in *adminv1.UpdateClientRequest) (*adminv1.UpdateClientResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "client store not configured")
	}
	if in == nil || in.Client == nil || in.Client.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "client.id required")
	}
	c := protoToClient(in.Client)
	// Preserve the existing secret unless the caller explicitly set one —
	// the Update RPC shouldn't be a backdoor to overwrite secrets silently.
	if c.Secret == "" {
		existing, err := s.store.Get(ctx, c.ID)
		if err == nil && existing != nil {
			c.Secret = existing.Secret
		}
	}
	if err := s.store.Update(ctx, c); err != nil {
		if errors.Is(err, sso.ErrNoSuchClient) {
			return nil, status.Error(codes.NotFound, "client not found")
		}
		return nil, status.Errorf(codes.Internal, "update: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminClientUpdated, c.ID)
	s.onDiscoveryChange()
	return &adminv1.UpdateClientResponse{Client: clientToProto(c, false)}, nil
}

func (s *ClientAdminService) Delete(ctx context.Context, in *adminv1.DeleteClientRequest) (*adminv1.DeleteClientResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "client store not configured")
	}
	if in == nil || in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	if err := s.store.Delete(ctx, in.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminClientDeleted, in.Id)
	s.onDiscoveryChange()
	return &adminv1.DeleteClientResponse{}, nil
}

func (s *ClientAdminService) RotateSecret(ctx context.Context, in *adminv1.RotateSecretRequest) (*adminv1.RotateSecretResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "client store not configured")
	}
	if in == nil || in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	secret, err := s.store.RotateSecret(ctx, in.Id)
	if errors.Is(err, sso.ErrNoSuchClient) {
		return nil, status.Error(codes.NotFound, "client not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "rotate: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminClientSecretRotated, in.Id)
	return &adminv1.RotateSecretResponse{Secret: secret}, nil
}

func clientToProto(c *sso.Client, includeSecret bool) *adminv1.Client {
	if c == nil {
		return nil
	}
	out := &adminv1.Client{
		Id:                    c.ID,
		Name:                  c.Name,
		RedirectUris:          append([]string(nil), c.RedirectURIs...),
		AllowedScopes:         append([]string(nil), c.AllowedScopes...),
		AllowedAuthenticators: append([]string(nil), c.AllowedAuthenticators...),
		TokenStrategy:         c.TokenStrategy,
		Active:                c.Active,
	}
	if includeSecret {
		out.Secret = c.Secret
	}
	return out
}

func protoToClient(in *adminv1.Client) *sso.Client {
	if in == nil {
		return nil
	}
	return &sso.Client{
		ID:                    in.Id,
		Secret:                in.Secret,
		Name:                  in.Name,
		RedirectURIs:          append([]string(nil), in.RedirectUris...),
		AllowedScopes:         append([]string(nil), in.AllowedScopes...),
		AllowedAuthenticators: append([]string(nil), in.AllowedAuthenticators...),
		TokenStrategy:         in.TokenStrategy,
		Active:                in.Active,
	}
}
