package grpcserver

import (
	"context"
	"errors"

	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/caep"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// validateClientCAEP enforces the registration-time invariant that a
// client's CAEP receiver endpoint, when present, is an https URL — the
// anti-exfil rule shared with the YAML + DCR paths. No-op when the
// attribute is unset.
func validateClientCAEP(c *sso.Client) error {
	if c == nil || c.Attributes == nil {
		return nil
	}
	if ep := c.Attributes[caep.AttrReceiverEndpoint]; ep != "" {
		if err := caep.ValidateReceiverEndpoint(ep); err != nil {
			return err
		}
	}
	return nil
}

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
	// onClientChange is invoked with the affected client ID after a
	// per-client mutation (Create/Update/Delete/RotateSecret). Wire it to
	// (*sso.Server).InvalidateClientCache so the opt-in per-login client
	// cache evicts that client locally AND across replicas (bus). nil =
	// no-op. Mirrors the PermissionAdminService callback-field pattern (no
	// *sso.Server injection into grpcserver).
	onClientChange func(clientID string)
}

// NewClientAdminService builds the service. onDiscoveryChange may be nil
// (e.g. when no discovery cache / bus is wired); pass
// (*sso.Server).InvalidateDiscoveryCache to propagate client edits.
// onClientChange may be nil (no per-login client cache wired); pass
// (*sso.Server).InvalidateClientCache to evict the affected client on
// every mutation.
func NewClientAdminService(store sso.ClientStore, recorder *audit.Recorder, onDiscoveryChange func(), onClientChange func(clientID string)) *ClientAdminService {
	if onDiscoveryChange == nil {
		onDiscoveryChange = func() {}
	}
	if onClientChange == nil {
		onClientChange = func(string) {}
	}
	return &ClientAdminService{store: store, recorder: recorder, onDiscoveryChange: onDiscoveryChange, onClientChange: onClientChange}
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
	if err := validateClientCAEP(c); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := s.store.Add(ctx, c); err != nil {
		if errors.Is(err, sso.ErrClientExists) {
			return nil, status.Error(codes.AlreadyExists, "client already exists")
		}
		return nil, status.Errorf(codes.Internal, "create: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminClientCreated, c.ID)
	s.onDiscoveryChange()
	s.onClientChange(c.ID)
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
	// Likewise carry forward the existing Attributes: the admin proto has no
	// Attributes field, so an Update would otherwise silently WIPE a client's
	// registered CAEP receiver config (and any other server-side attribute).
	if c.Secret == "" || c.Attributes == nil {
		existing, err := s.store.Get(ctx, c.ID)
		if err == nil && existing != nil {
			if c.Secret == "" {
				c.Secret = existing.Secret
			}
			if c.Attributes == nil {
				c.Attributes = existing.Attributes
			}
		}
	}
	if err := validateClientCAEP(c); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := s.store.Update(ctx, c); err != nil {
		if errors.Is(err, sso.ErrNoSuchClient) {
			return nil, status.Error(codes.NotFound, "client not found")
		}
		return nil, status.Errorf(codes.Internal, "update: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminClientUpdated, c.ID)
	s.onDiscoveryChange()
	s.onClientChange(c.ID)
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
	s.onClientChange(in.Id)
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
	// RotateSecret changes the cached Secret field; evict so the metadata
	// cache doesn't serve the stale snapshot (ValidateSecret already
	// bypasses the cache, so this is metadata hygiene, not correctness).
	s.onClientChange(in.Id)
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
