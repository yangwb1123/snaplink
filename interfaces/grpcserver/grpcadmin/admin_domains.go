package grpcadmin

import (
	"context"
	"errors"
	"sort"

	"github.com/snaplink/sso/domains/tenant"
	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/platform/audit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Domain CRUD for TenantAdminService — split from admin_tenants.go (same
// receiver, same package) purely to stay under the 500-line file budget once
// ListTenants grew filter/sort support; see the note left in admin_tenants.go.

// ListDomains applies offset pagination over a full store scan (optionally
// pre-narrowed to one tenant via ListDomainsByTenant). Unlike ListTenants,
// this proto has no order_by/filter fields, so there is nothing to wire
// beyond a fixed deterministic sort (hostname ascending) — imposed here
// rather than assumed from the backing store, mirroring why sortClients/
// sortUsers always run even when order_by is empty.
func (s *TenantAdminService) ListDomains(ctx context.Context, in *adminv1.ListDomainsRequest) (*adminv1.ListDomainsResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant store not configured")
	}
	var (
		all []*tenant.Domain
		err error
	)
	if in != nil && in.TenantId != "" {
		all, err = s.store.ListDomainsByTenant(ctx, in.TenantId)
	} else {
		all, err = s.store.ListDomains(ctx)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list domains: %v", err)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Hostname < all[j].Hostname })
	offset, err := decodeOffset(in.GetPageToken())
	if err != nil {
		return nil, err
	}
	lo, hi := pageBounds(offset, clampPageSize(in.GetPageSize()), len(all))
	out := &adminv1.ListDomainsResponse{
		Domains:       make([]*adminv1.Domain, 0, hi-lo),
		TotalSize:     int32(len(all)),
		NextPageToken: encodeOffset(hi, len(all)),
	}
	for _, d := range all[lo:hi] {
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
