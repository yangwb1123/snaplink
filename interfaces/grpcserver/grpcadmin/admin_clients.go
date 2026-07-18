package grpcadmin

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"

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

// List applies filter -> sort -> offset pagination over a full store.List(ctx)
// scan. See admin_paginate.go for why this bounds the RESPONSE but not the
// server-side materialization.
func (s *ClientAdminService) List(ctx context.Context, in *adminv1.ListClientsRequest) (*adminv1.ListClientsResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "client store not configured")
	}
	all, err := s.store.List(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list: %v", err)
	}
	all, err = filterClients(all, in.GetFilter())
	if err != nil {
		return nil, err
	}
	if err = sortClients(all, in.GetOrderBy()); err != nil {
		return nil, err
	}
	offset, err := decodeOffset(in.GetPageToken())
	if err != nil {
		return nil, err
	}
	lo, hi := pageBounds(offset, clampPageSize(in.GetPageSize()), len(all))
	out := &adminv1.ListClientsResponse{
		Clients:       make([]*adminv1.Client, 0, hi-lo),
		TotalSize:     int32(len(all)),
		NextPageToken: encodeOffset(hi, len(all)),
	}
	for _, c := range all[lo:hi] {
		out.Clients = append(out.Clients, clientToProto(c, false))
	}
	return out, nil
}

// filterClients narrows all to rows matching expr, or returns all unchanged
// when expr is empty. Unrecognized fields and unparseable expressions both
// reach clientMatches' default case, which errors — see parseAdminFilter.
func filterClients(all []*sso.Client, expr string) ([]*sso.Client, error) {
	field, value, ok := parseAdminFilter(expr)
	if !ok {
		return all, nil
	}
	out := make([]*sso.Client, 0, len(all))
	for _, c := range all {
		match, err := clientMatches(c, field, value)
		if err != nil {
			return nil, err
		}
		if match {
			out = append(out, c)
		}
	}
	return out, nil
}

// clientMatches evaluates one filter field against a client. Users field set
// is documented separately in admin_users.go — the two entities intentionally
// support different filter fields (Client has no email/created_at).
func clientMatches(c *sso.Client, field, value string) (bool, error) {
	switch strings.ToLower(field) {
	case "id":
		return c.ID == value, nil
	case "name":
		return strings.Contains(strings.ToLower(c.Name), strings.ToLower(value)), nil
	case "active":
		want, err := strconv.ParseBool(value)
		if err != nil {
			return false, status.Errorf(codes.InvalidArgument, "invalid filter value for active: %q", value)
		}
		return c.Active == want, nil
	default:
		return false, status.Errorf(codes.InvalidArgument, "unsupported filter field %q", field)
	}
}

// sortClients orders all in place by order_by (default: id ascending, the
// MANDATORY stable sort that makes offset paging deterministic over the
// memory store's random map iteration).
func sortClients(all []*sso.Client, orderBy string) error {
	field, desc := parseOrderBy(orderBy)
	less, err := clientLess(field)
	if err != nil {
		return err
	}
	sort.SliceStable(all, func(i, j int) bool {
		if desc {
			return less(all[j], all[i])
		}
		return less(all[i], all[j])
	})
	return nil
}

// clientLess returns the comparator for one order_by field. 'created_at'
// aliases to the id default because core.Client has no CreatedAt field
// (unlike core.User) — documented asymmetry, see admin_users.go userLess.
func clientLess(field string) (func(a, b *sso.Client) bool, error) {
	switch strings.ToLower(field) {
	case "", "id", "created_at":
		return func(a, b *sso.Client) bool { return a.ID < b.ID }, nil
	case "name":
		return func(a, b *sso.Client) bool { return a.Name < b.Name }, nil
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported order_by field %q", field)
	}
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
	// Start from the STORED client, not a fresh protoToClient() — the admin
	// Client proto exposes only 8 of the 30+ sso.Client fields (no
	// RequirePKCE, TenantID, AllowedResources, JWKS, ...). Overlaying just
	// the proto-exposed fields onto the existing record, rather than
	// building a mostly-zero-valued struct and patching a couple of fields
	// back in, means every field the proto CAN'T express survives an Update
	// automatically — including ones added to sso.Client after this RPC was
	// written.
	existing, err := s.store.Get(ctx, in.Client.Id)
	if err != nil || existing == nil {
		return nil, status.Error(codes.NotFound, "client not found")
	}
	c := applyProtoToExistingClient(existing, in.Client)
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

// Approve implements the developer-app registration review workflow's
// approval half: flips Active to true on an existing (typically
// pending, i.e. registered with active=false) client. Idempotent —
// approving an already-active client is a no-op beyond re-recording the
// audit event, since a registration review action should always leave a
// trail even if the state didn't change.
func (s *ClientAdminService) Approve(ctx context.Context, in *adminv1.ApproveClientRequest) (*adminv1.ApproveClientResponse, error) {
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
	c.Active = true
	if err := s.store.Update(ctx, c); err != nil {
		return nil, status.Errorf(codes.Internal, "approve: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminClientApproved, c.ID)
	s.onDiscoveryChange()
	s.onClientChange(c.ID)
	return &adminv1.ApproveClientResponse{Client: clientToProto(c, false)}, nil
}

// Reject implements the review workflow's rejection half: DELETES the
// never-activated client outright rather than leaving it permanently
// inactive — a rejected registration is done, not parked. The audit
// event captures the client's name (and the operator-supplied reason,
// if any) BEFORE deletion, since the record is gone afterward.
func (s *ClientAdminService) Reject(ctx context.Context, in *adminv1.RejectClientRequest) (*adminv1.RejectClientResponse, error) {
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
	if err := s.store.Delete(ctx, in.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "reject: %v", err)
	}
	meta := map[string]string{"client_name": c.Name}
	if in.Reason != "" {
		meta["reason"] = in.Reason
	}
	recordAdminMeta(ctx, s.recorder, audit.EventAdminClientRejected, in.Id, meta)
	s.onDiscoveryChange()
	s.onClientChange(in.Id)
	return &adminv1.RejectClientResponse{}, nil
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

// applyProtoToExistingClient overlays the admin proto's wire-representable
// fields onto a COPY of the existing client, so every core.Client field NOT
// in the admin.v1.Client message (TenantID, RequirePKCE, AllowedResources,
// JWKS, token TTLs, encrypted-response algs, ...) survives an Update
// untouched. Building forward from the existing record — rather than
// protoToClient's blank Client plus an ad-hoc list of fields to patch back —
// means a future core.Client field addition can never be silently wiped by
// this RPC again the way TenantID and ~15 other fields previously were.
// Secret is preserved unless the caller explicitly set one (Update
// shouldn't be a backdoor to overwrite it silently).
func applyProtoToExistingClient(existing *sso.Client, in *adminv1.Client) *sso.Client {
	c := *existing
	c.ID = in.Id
	if in.Secret != "" {
		c.Secret = in.Secret
	}
	c.Name = in.Name
	c.RedirectURIs = append([]string(nil), in.RedirectUris...)
	c.AllowedScopes = append([]string(nil), in.AllowedScopes...)
	c.AllowedAuthenticators = append([]string(nil), in.AllowedAuthenticators...)
	c.TokenStrategy = in.TokenStrategy
	c.Active = in.Active
	return &c
}
