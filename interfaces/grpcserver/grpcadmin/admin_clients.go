package grpcadmin

import (
	"context"
	"errors"
	"sort"
	"time"

	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/caep"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security/clientrotation"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// validateClientCAEP enforces the registration-time invariant that a
// client's CAEP receiver endpoint, when present, is an https URL — the
// anti-exfil rule shared with the YAML + DCR paths. No-op when the
// attribute is unset.
func validateClientCAEP(c *sso.Client) error {
	if c == nil {
		return nil
	}
	if c.LoginPageURI != "" && !sso.IsFederatedLoginPageURIValid(c.LoginPageURI) {
		return errors.New("login_page_uri must be HTTPS or loopback HTTP")
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
	// onClientDeleted releases quota using the full pre-delete record, whose
	// TenantID is intentionally read-only on the admin wire (surfaced by
	// clientToProto, never consumed by a mutation).
	onClientDeleted func(context.Context, *sso.Client)
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

// SetClientDeletedHook installs a post-delete lifecycle callback. It is
// additive so the admin protobuf and the historical constructor stay stable.
func (s *ClientAdminService) SetClientDeletedHook(fn func(context.Context, *sso.Client)) {
	s.onClientDeleted = fn
}

func (s *ClientAdminService) notifyClientDeleted(ctx context.Context, client *sso.Client) {
	if s.onClientDeleted != nil && client != nil {
		s.onClientDeleted(ctx, client)
	}
}

// List dispatches through runListPage (admin_paginate.go): keyset pushdown
// when the store implements core.PaginatedClientStore, else the legacy
// List(ctx) -> filter -> sort -> offset-slice path. The TotalSize hint
// resolver implements the D7 sourcing rules: exact SPI hint wins, a -1 hint
// with no filter falls back to ClientStoreStats.Stats(), else 0 (honest
// unknown — never a full scan just to count).
func (s *ClientAdminService) List(ctx context.Context, in *adminv1.ListClientsRequest) (*adminv1.ListClientsResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "client store not configured")
	}
	var ext pageLister[*sso.Client]
	if p, ok := s.store.(core.PaginatedClientStore); ok {
		ext = p
	}
	items, next, total, err := runListPage(ctx,
		in.GetPageToken(), in.GetPageSize(), in.GetOrderBy(), in.GetFilter(),
		ext,
		func(ctx context.Context) ([]*sso.Client, error) { return s.store.List(ctx) },
		func(items []*sso.Client, orderBy string) ([]*sso.Client, error) {
			return s.filterAndSortClients(items, in.GetFilter(), orderBy)
		},
		validateListSpecClient,
		"list: %v",
		func(ctx context.Context, hint int) int32 { return s.clientListHint(ctx, in.GetFilter(), hint) },
	)
	if err != nil {
		return nil, err
	}
	return clientsResponse(items, next, total), nil
}

// filterAndSortClients applies the admin filter expression and order spec to
// a fully-materialized page fallback (the non-keyset path).
func (s *ClientAdminService) filterAndSortClients(items []*sso.Client, filter, orderBy string) ([]*sso.Client, error) {
	items, err := filterClients(items, filter)
	if err != nil {
		return nil, err
	}
	if err := sortClients(items, orderBy); err != nil {
		return nil, err
	}
	return items, nil
}

// clientListHint resolves a store totalHint into TotalSize, falling back to a
// cheap Stats count for the unfiltered list (D7 sourcing rules).
func (s *ClientAdminService) clientListHint(ctx context.Context, filter string, hint int) int32 {
	if hint >= 0 {
		return int32(hint)
	}
	if filter == "" {
		if st, ok := s.store.(core.ClientStoreStats); ok {
			if count, _, err := st.Stats(ctx); err == nil {
				return int32(count)
			}
		}
	}
	return 0
}

// clientsResponse projects a page of clients onto the wire response.
func clientsResponse(items []*sso.Client, next string, total int32) *adminv1.ListClientsResponse {
	out := &adminv1.ListClientsResponse{
		Clients:       make([]*adminv1.Client, 0, len(items)),
		TotalSize:     total,
		NextPageToken: next,
	}
	for _, c := range items {
		out.Clients = append(out.Clients, clientToProto(c, false))
	}
	return out
}

// filterClients narrows all to rows matching expr, or returns all unchanged
// when expr is empty, via the shared core matcher (ParseFilterExpr +
// ClientMatches) — the fallback's semantics AND error strings, single-sourced
// with the memory store's ListPage. Unrecognized fields and unparseable
// expressions both error — see core.ParseFilterExpr.
func filterClients(all []*sso.Client, expr string) ([]*sso.Client, error) {
	field, value, ok := core.ParseFilterExpr(expr)
	if !ok {
		return all, nil
	}
	out := make([]*sso.Client, 0, len(all))
	for _, c := range all {
		match, err := core.ClientMatches(c, field, value)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		if match {
			out = append(out, c)
		}
	}
	return out, nil
}

// sortClients orders all in place by order_by (default: id ascending, the
// MANDATORY stable sort that makes offset paging deterministic over the
// memory store's random map iteration). Field validation + comparison come
// from core so the fallback and the extension store cannot drift.
func sortClients(all []*sso.Client, orderBy string) error {
	field, desc := parseOrderBy(orderBy)
	if err := core.ValidateClientOrderBy(field); err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if desc {
			return core.CompareClients(all[j], all[i], field) < 0
		}
		return core.CompareClients(all[i], all[j], field) < 0
	})
	return nil
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
	deletedClient, _ := s.store.Get(ctx, in.Id)
	if err := s.store.Delete(ctx, in.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete: %v", err)
	}
	s.notifyClientDeleted(ctx, deletedClient)
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
	overlap, lifetime, err := clientRotationPolicy(in)
	if err != nil {
		return nil, err
	}
	secret, err := rotateClientSecret(ctx, s.store, in.Id, overlap, lifetime)
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
	client, getErr := s.store.Get(ctx, in.Id)
	if getErr != nil {
		return nil, status.Errorf(codes.Internal, "read rotated client: %v", getErr)
	}
	return &adminv1.RotateSecretResponse{Secret: secret, ClientSecretExpiresAt: clientExpiryUnix(client)}, nil
}

func rotateClientSecret(ctx context.Context, store sso.ClientStore, id string, overlap, lifetime time.Duration) (string, error) {
	if lifecycleStore, ok := store.(clientrotation.ClientSecretLifecycleRotator); ok {
		return lifecycleStore.RotateSecretWithLifecycle(ctx, id, overlap, lifetime)
	}
	if overlapStore, ok := store.(clientrotation.ClientSecretOverlapRotator); ok {
		return overlapStore.RotateSecretWithOverlap(ctx, id, clientrotation.DefaultOverlap)
	}
	return store.RotateSecret(ctx, id)
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
	s.notifyClientDeleted(ctx, c)
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
		ClientSecretExpiresAt: clientExpiryUnix(c),
		LoginPageUri:          c.LoginPageURI,
		// Read-only projection of the stored binding: operators verify the
		// tenant and grant allowlist here, matching the token claim path
		// (Subject.TenantID) and /token enforcement.
		TenantId:   c.TenantID,
		GrantTypes: append([]string(nil), c.GrantTypes...),
	}
	if includeSecret {
		out.Secret = c.Secret
	}
	return out
}

// protoToClient maps the admin wire's writable fields only: TenantId and
// GrantTypes are read-only over the admin API (binding is established at
// registration time) and must never be consumed here.
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
		SecretExpiresAt:       timeFromUnix(in.ClientSecretExpiresAt),
		LoginPageURI:          in.LoginPageUri,
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
	c.LoginPageURI = in.LoginPageUri
	if in.ClientSecretExpiresAt != 0 {
		c.SecretExpiresAt = timeFromUnix(in.ClientSecretExpiresAt)
	}
	return &c
}

func clientExpiryUnix(c *sso.Client) int64 {
	if c == nil || c.SecretExpiresAt.IsZero() {
		return 0
	}
	return c.SecretExpiresAt.Unix()
}

func timeFromUnix(value int64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	return time.Unix(value, 0).UTC()
}

func validateListSpecClient(filter, orderBy string) error {
	return validateListSpec(filter, orderBy, core.ValidateClientFilter, core.ValidateClientOrderBy)
}
