package grpcadmin

import (
	"context"
	"errors"
	"sort"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/domains/tenant"
	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/platform/audit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Domain CRUD for TenantAdminService — split from admin_tenants.go (same
// receiver, same package) purely to stay under the 500-line file budget once
// ListTenants grew filter/sort support; see the note left in admin_tenants.go.

// ListDomains dispatches through runListPage (admin_paginate.go): keyset
// pushdown when the store implements tenant.PaginatedDomainStore (optionally
// pre-narrowed to one tenant), else the legacy full-scan path with a fixed
// deterministic hostname-ascending sort. Unlike ListTenants, this proto has
// no order_by/filter fields, so there is nothing to wire beyond the fixed
// sort — imposed here rather than assumed from the backing store, mirroring
// why sortClients/sortUsers always run even when order_by is empty.
func (s *TenantAdminService) ListDomains(ctx context.Context, in *adminv1.ListDomainsRequest) (*adminv1.ListDomainsResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant store not configured")
	}
	tenantID := ""
	if in != nil {
		tenantID = in.TenantId
	}
	var ext pageLister[*tenant.Domain]
	if p, ok := s.store.(tenant.PaginatedDomainStore); ok {
		ext = domainPageLister{inner: p, tenantID: tenantID}
	}
	items, next, total, err := runListPage(ctx,
		in.GetPageToken(), in.GetPageSize(), "", "",
		ext,
		func(ctx context.Context) ([]*tenant.Domain, error) {
			var all []*tenant.Domain
			var err error
			if tenantID != "" {
				all, err = s.store.ListDomainsByTenant(ctx, tenantID)
			} else {
				all, err = s.store.ListDomains(ctx)
			}
			if err != nil {
				return nil, status.Errorf(codes.Internal, "list domains: %v", err)
			}
			return all, nil
		},
		func(items []*tenant.Domain, _ string) ([]*tenant.Domain, error) {
			sort.Slice(items, func(i, j int) bool { return tenant.CompareDomains(items[i], items[j]) < 0 })
			return items, nil
		},
		nil, "list domains: %v", nil,
	)
	if err != nil {
		return nil, err
	}
	out := &adminv1.ListDomainsResponse{
		Domains:       make([]*adminv1.Domain, 0, len(items)),
		TotalSize:     total,
		NextPageToken: next,
	}
	for _, d := range items {
		out.Domains = append(out.Domains, domainToProto(d))
	}
	return out, nil
}

func (s *TenantAdminService) GetDomain(ctx context.Context, in *adminv1.GetDomainRequest) (*adminv1.GetDomainResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant store not configured")
	}
	if in == nil || in.Hostname == "" {
		return nil, status.Error(codes.InvalidArgument, "hostname required")
	}
	d, err := s.store.GetDomain(ctx, in.Hostname)
	if errors.Is(err, tenant.ErrDomainNotFound) {
		return nil, status.Error(codes.NotFound, "domain not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get domain: %v", err)
	}
	return &adminv1.GetDomainResponse{Domain: domainToProto(d)}, nil
}

func (s *TenantAdminService) CreateDomain(ctx context.Context, in *adminv1.CreateDomainRequest) (*adminv1.CreateDomainResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant store not configured")
	}
	if in == nil || in.Domain == nil || in.Domain.Hostname == "" {
		return nil, status.Error(codes.InvalidArgument, "domain.hostname required")
	}
	if _, err := s.store.GetDomain(ctx, in.Domain.Hostname); err == nil {
		return nil, status.Error(codes.AlreadyExists, "domain already exists")
	} else if !errors.Is(err, tenant.ErrDomainNotFound) {
		return nil, status.Errorf(codes.Internal, "preflight: %v", err)
	}
	d := protoToDomain(in.Domain)
	if err := s.store.PutDomain(ctx, d); err != nil {
		if errors.Is(err, tenant.ErrInvalidDomain) {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		if errors.Is(err, tenant.ErrDomainExists) {
			return nil, status.Error(codes.AlreadyExists, "domain already exists")
		}
		return nil, status.Errorf(codes.Internal, "create domain: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminDomainCreated, d.Hostname)
	fresh, _ := s.store.GetDomain(ctx, d.Hostname)
	if fresh == nil {
		fresh = d
	}
	return &adminv1.CreateDomainResponse{Domain: domainToProto(fresh)}, nil
}

func (s *TenantAdminService) UpdateDomain(ctx context.Context, in *adminv1.UpdateDomainRequest) (*adminv1.UpdateDomainResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant store not configured")
	}
	if in == nil || in.Domain == nil || in.Domain.Hostname == "" {
		return nil, status.Error(codes.InvalidArgument, "domain.hostname required")
	}
	if _, err := s.store.GetDomain(ctx, in.Domain.Hostname); err != nil {
		if errors.Is(err, tenant.ErrDomainNotFound) {
			return nil, status.Error(codes.NotFound, "domain not found")
		}
		return nil, status.Errorf(codes.Internal, "preflight: %v", err)
	}
	d := protoToDomain(in.Domain)
	if err := s.store.PutDomain(ctx, d); err != nil {
		if errors.Is(err, tenant.ErrInvalidDomain) {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "update domain: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminDomainUpdated, d.Hostname)
	fresh, _ := s.store.GetDomain(ctx, d.Hostname)
	if fresh == nil {
		fresh = d
	}
	return &adminv1.UpdateDomainResponse{Domain: domainToProto(fresh)}, nil
}

func (s *TenantAdminService) DeleteDomain(ctx context.Context, in *adminv1.DeleteDomainRequest) (*adminv1.DeleteDomainResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant store not configured")
	}
	if in == nil || in.Hostname == "" {
		return nil, status.Error(codes.InvalidArgument, "hostname required")
	}
	if err := s.store.DeleteDomain(ctx, in.Hostname); err != nil {
		return nil, status.Errorf(codes.Internal, "delete domain: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminDomainDeleted, in.Hostname)
	return &adminv1.DeleteDomainResponse{}, nil
}

func domainToProto(d *tenant.Domain) *adminv1.Domain {
	if d == nil {
		return nil
	}
	return &adminv1.Domain{
		Hostname:        d.Hostname,
		TenantId:        d.TenantID,
		DefaultClientId: d.DefaultClientID,
		IsApex:          d.IsApex,
		Branding:        d.Branding,
	}
}

func protoToDomain(p *adminv1.Domain) *tenant.Domain {
	if p == nil {
		return nil
	}
	return &tenant.Domain{
		Hostname:        p.Hostname,
		TenantID:        p.TenantId,
		DefaultClientID: p.DefaultClientId,
		IsApex:          p.IsApex,
		Branding:        p.Branding,
	}
}

// PermissionAdminService's SoD methods live in this split file because the
// permission CRUD adapter already owns the resource-catalog RPCs and is near
// the per-file budget. The receiver and wire contract remain unchanged.
func (s *PermissionAdminService) SetConflictSets(ctx context.Context, in *adminv1.SetConflictSetsRequest) (*adminv1.SetConflictSetsResponse, error) {
	p, err := s.sodProvider()
	if err != nil {
		return nil, err
	}
	if in == nil {
		return nil, status.Error(codes.InvalidArgument, "request required")
	}
	if err := p.SetConflictSets(ctx, in.ClientId, conflictSetsFromProto(in.ConflictSets)); err != nil {
		return nil, mapSoDError("set conflict sets", err)
	}
	s.invalidateAuthzPolicy(ctx, in.ClientId)
	return &adminv1.SetConflictSetsResponse{}, nil
}

func (s *PermissionAdminService) ListConflictSets(ctx context.Context, in *adminv1.ListConflictSetsRequest) (*adminv1.ListConflictSetsResponse, error) {
	p, err := s.sodProvider()
	if err != nil {
		return nil, err
	}
	if in == nil {
		return nil, status.Error(codes.InvalidArgument, "request required")
	}
	sets, err := p.ConflictSets(ctx, in.ClientId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list conflict sets: %v", err)
	}
	return &adminv1.ListConflictSetsResponse{ConflictSets: conflictSetsToProto(sets)}, nil
}

func (s *PermissionAdminService) SetActivationConflictSets(ctx context.Context, in *adminv1.SetActivationConflictSetsRequest) (*adminv1.SetActivationConflictSetsResponse, error) {
	p, err := s.sessionRoleActivator()
	if err != nil {
		return nil, err
	}
	if in == nil {
		return nil, status.Error(codes.InvalidArgument, "request required")
	}
	if err := p.SetActivationConflictSets(ctx, in.ClientId, conflictSetsFromProto(in.ConflictSets)); err != nil {
		return nil, mapSoDError("set activation conflict sets", err)
	}
	s.invalidateAuthzPolicy(ctx, in.ClientId)
	return &adminv1.SetActivationConflictSetsResponse{}, nil
}

func (s *PermissionAdminService) ListActivationConflictSets(ctx context.Context, in *adminv1.ListActivationConflictSetsRequest) (*adminv1.ListActivationConflictSetsResponse, error) {
	p, err := s.sessionRoleActivator()
	if err != nil {
		return nil, err
	}
	if in == nil {
		return nil, status.Error(codes.InvalidArgument, "request required")
	}
	sets, err := p.ActivationConflictSets(ctx, in.ClientId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list activation conflict sets: %v", err)
	}
	return &adminv1.ListActivationConflictSetsResponse{ConflictSets: conflictSetsToProto(sets)}, nil
}

func (s *PermissionAdminService) ActivateRoles(ctx context.Context, in *adminv1.ActivateRolesRequest) (*adminv1.ActivateRolesResponse, error) {
	p, err := s.sessionRoleActivator()
	if err != nil {
		return nil, err
	}
	if in == nil || in.UserId == "" || in.SessionId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id and session_id required")
	}
	if err := p.ActivateRoles(ctx, in.UserId, in.ClientId, in.SessionId, in.Roles); err != nil {
		return nil, mapSoDError("activate roles", err)
	}
	return &adminv1.ActivateRolesResponse{}, nil
}

func (s *PermissionAdminService) ListActiveRoles(ctx context.Context, in *adminv1.ListActiveRolesRequest) (*adminv1.ListActiveRolesResponse, error) {
	p, err := s.sessionRoleActivator()
	if err != nil {
		return nil, err
	}
	if in == nil || in.UserId == "" || in.SessionId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id and session_id required")
	}
	roles, err := p.ActiveRoles(ctx, in.UserId, in.ClientId, in.SessionId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list active roles: %v", err)
	}
	out := &adminv1.ListActiveRolesResponse{Roles: make([]*adminv1.Role, 0, len(roles))}
	for _, role := range roles {
		out.Roles = append(out.Roles, roleToProto(role))
	}
	return out, nil
}

func (s *PermissionAdminService) DeactivateSession(ctx context.Context, in *adminv1.DeactivateSessionRequest) (*adminv1.DeactivateSessionResponse, error) {
	p, err := s.sessionRoleActivator()
	if err != nil {
		return nil, err
	}
	if in == nil || in.UserId == "" || in.SessionId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id and session_id required")
	}
	if err := p.DeactivateSession(ctx, in.UserId, in.ClientId, in.SessionId); err != nil {
		return nil, status.Errorf(codes.Internal, "deactivate session: %v", err)
	}
	return &adminv1.DeactivateSessionResponse{}, nil
}

func (s *PermissionAdminService) sodProvider() (permissions.SoDProvider, error) {
	if s.prov == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	p, ok := s.prov.(permissions.SoDProvider)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "separation of duty not configured")
	}
	return p, nil
}

func (s *PermissionAdminService) sessionRoleActivator() (permissions.SessionRoleActivator, error) {
	if s.prov == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	p, ok := s.prov.(permissions.SessionRoleActivator)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "session role activation not configured")
	}
	return p, nil
}

func mapSoDError(op string, err error) error {
	switch {
	case errors.Is(err, permissions.ErrInvalidConflictSet), errors.Is(err, permissions.ErrRoleNotAssigned):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, permissions.ErrRoleConflict):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return status.Errorf(codes.Internal, "%s: %v", op, err)
	}
}

func conflictSetsFromProto(in []*adminv1.ConflictSet) [][]string {
	sets := make([][]string, 0, len(in))
	for _, set := range in {
		if set == nil {
			sets = append(sets, nil)
			continue
		}
		sets = append(sets, append([]string(nil), set.RoleCodes...))
	}
	return sets
}

func conflictSetsToProto(in [][]string) []*adminv1.ConflictSet {
	out := make([]*adminv1.ConflictSet, 0, len(in))
	for _, set := range in {
		out = append(out, &adminv1.ConflictSet{RoleCodes: append([]string(nil), set...)})
	}
	return out
}
