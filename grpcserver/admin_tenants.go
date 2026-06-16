package grpcserver

import (
	"context"
	"errors"
	"strings"

	"github.com/snaplink/sso/audit"
	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/tenant"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TenantAdminService implements CRUD over a [tenant.Store] for
// admin operators. Mutations emit admin_tenant_* / admin_domain_*
// audit events.
//
// SetTenantStatus is the surgical Active/Suspended flip — kept
// separate from UpdateTenant so the call site can invalidate the
// per-request suspension cache cleanly. The optional
// invalidateSuspensionCache callback wires that to
// (*sso.Server).InvalidateTenantSuspensionCache.
type TenantAdminService struct {
	adminv1.UnimplementedTenantAdminServiceServer
	store                     tenant.Store
	recorder                  *audit.Recorder
	invalidateSuspensionCache func(tenantID string)
	// invalidateResidencyCache drops the cached data-residency policy for a
	// tenant after Create/Update writes new home_region/allowed_regions/
	// enforce_writes (wired to (*sso.Server).InvalidateTenantResidencyCache),
	// so a policy change takes effect on the next request instead of waiting
	// out the residency cache TTL. Optional — nil is a no-op (byte-identical
	// for non-residency deployments). Mirrors invalidateSuspensionCache.
	invalidateResidencyCache func(tenantID string)
	// revokeTenantTokens proactively purges the tenant's refresh tokens
	// when it is suspended (wired to (*sso.Server).RevokeTenantRefreshTokens).
	// Optional — nil is a no-op.
	revokeTenantTokens func(ctx context.Context, tenantID string)
}

// NewTenantAdminService wires the store, audit recorder, the suspension-cache
// invalidation callback, the residency-cache invalidation callback, and the
// active token-revocation hook fired on suspend. Pass nil for any callback
// when the SSO server doesn't have the corresponding feature enabled (the
// call is a no-op then).
func NewTenantAdminService(store tenant.Store, recorder *audit.Recorder, invalidateCache func(string), invalidateResidency func(string), revokeTokens func(context.Context, string)) *TenantAdminService {
	if invalidateCache == nil {
		invalidateCache = func(string) {}
	}
	if invalidateResidency == nil {
		invalidateResidency = func(string) {}
	}
	if revokeTokens == nil {
		revokeTokens = func(context.Context, string) {}
	}
	return &TenantAdminService{
		store:                     store,
		recorder:                  recorder,
		invalidateSuspensionCache: invalidateCache,
		invalidateResidencyCache:  invalidateResidency,
		revokeTenantTokens:        revokeTokens,
	}
}

// ---------- Tenant CRUD ----------

func (s *TenantAdminService) ListTenants(ctx context.Context, _ *adminv1.ListTenantsRequest) (*adminv1.ListTenantsResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant store not configured")
	}
	all, err := s.store.ListTenants(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list tenants: %v", err)
	}
	out := &adminv1.ListTenantsResponse{Tenants: make([]*adminv1.Tenant, 0, len(all))}
	for _, t := range all {
		out.Tenants = append(out.Tenants, tenantToProto(t))
	}
	return out, nil
}

func (s *TenantAdminService) GetTenant(ctx context.Context, in *adminv1.GetTenantRequest) (*adminv1.GetTenantResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant store not configured")
	}
	if in == nil || in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	t, err := s.store.GetTenant(ctx, in.Id)
	if errors.Is(err, tenant.ErrTenantNotFound) {
		return nil, status.Error(codes.NotFound, "tenant not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get tenant: %v", err)
	}
	return &adminv1.GetTenantResponse{Tenant: tenantToProto(t)}, nil
}

func (s *TenantAdminService) CreateTenant(ctx context.Context, in *adminv1.CreateTenantRequest) (*adminv1.CreateTenantResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant store not configured")
	}
	if in == nil || in.Tenant == nil || in.Tenant.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant.id required")
	}
	// Check-then-put: PutTenant is upsert in every shipped Store, so
	// Create vs Update has to be disambiguated here.
	if _, err := s.store.GetTenant(ctx, in.Tenant.Id); err == nil {
		return nil, status.Error(codes.AlreadyExists, "tenant already exists")
	} else if !errors.Is(err, tenant.ErrTenantNotFound) {
		return nil, status.Errorf(codes.Internal, "preflight: %v", err)
	}
	t := protoToTenant(in.Tenant)
	if err := s.store.PutTenant(ctx, t); err != nil {
		if errors.Is(err, tenant.ErrInvalidTenant) {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "create tenant: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminTenantCreated, t.ID)
	// A fresh id has nothing cached, but a delete-then-recreate could leave a
	// stale residency entry; evict it when Create actually sets a policy. Guard
	// on hasResidency so the common no-residency create stays a strict no-op.
	if hasResidency(t) {
		s.invalidateResidencyCache(t.ID)
	}
	// Re-fetch so the response carries the server-applied timestamps
	// and default Status.
	fresh, _ := s.store.GetTenant(ctx, t.ID)
	if fresh == nil {
		fresh = t
	}
	return &adminv1.CreateTenantResponse{Tenant: tenantToProto(fresh)}, nil
}

func (s *TenantAdminService) UpdateTenant(ctx context.Context, in *adminv1.UpdateTenantRequest) (*adminv1.UpdateTenantResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant store not configured")
	}
	if in == nil || in.Tenant == nil || in.Tenant.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant.id required")
	}
	existing, err := s.store.GetTenant(ctx, in.Tenant.Id)
	if errors.Is(err, tenant.ErrTenantNotFound) {
		return nil, status.Error(codes.NotFound, "tenant not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "preflight: %v", err)
	}
	t := protoToTenant(in.Tenant)
	// Update is for non-status fields; preserve the current status
	// so callers can't sneak a suspended flip past the cache by
	// piggybacking on Update.
	t.Status = existing.Status
	if err := s.store.PutTenant(ctx, t); err != nil {
		if errors.Is(err, tenant.ErrInvalidTenant) {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "update tenant: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminTenantUpdated, t.ID)
	// Update carries the data-residency policy (home_region/allowed_regions/
	// enforce_writes), so flush the per-tenant residency cache — mirroring how
	// SetTenantStatus flushes the suspension cache — so the new policy applies
	// on the next request instead of waiting out the residency cache TTL.
	// Unconditional: an Update that clears residency back to unconstrained must
	// also evict a stale cached policy. Nil-safe (no-op when unwired).
	s.invalidateResidencyCache(t.ID)
	fresh, _ := s.store.GetTenant(ctx, t.ID)
	if fresh == nil {
		fresh = t
	}
	return &adminv1.UpdateTenantResponse{Tenant: tenantToProto(fresh)}, nil
}

func (s *TenantAdminService) DeleteTenant(ctx context.Context, in *adminv1.DeleteTenantRequest) (*adminv1.DeleteTenantResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant store not configured")
	}
	if in == nil || in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	if err := s.store.DeleteTenant(ctx, in.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete tenant: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminTenantDeleted, in.Id)
	// Drop any cached suspension state — a deleted tenant must
	// re-resolve as "no tenant" on the next request, not stay cached
	// as Active until TTL expiry.
	s.invalidateSuspensionCache(in.Id)
	// A deleted tenant's cached residency policy must die with it too — symmetric
	// with UpdateTenant. Without this, a still-valid token keeps being residency-
	// gated against a policy that no longer exists until the cache TTL expires,
	// and peers stay stale (no KindTenantResidency bus event). Nil-safe no-op.
	s.invalidateResidencyCache(in.Id)
	// A deleted tenant must not leave usable refresh tokens behind for its
	// (now-orphaned) clients — purge them too, symmetric with the suspend
	// path. Best-effort; the hook logs + audits internally.
	s.revokeTenantTokens(ctx, in.Id)
	return &adminv1.DeleteTenantResponse{}, nil
}

func (s *TenantAdminService) SetTenantStatus(ctx context.Context, in *adminv1.SetTenantStatusRequest) (*adminv1.SetTenantStatusResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant store not configured")
	}
	if in == nil || in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	newStatus := tenant.Status(in.Status)
	if newStatus != tenant.StatusActive && newStatus != tenant.StatusSuspended {
		return nil, status.Errorf(codes.InvalidArgument, "status must be %q or %q",
			tenant.StatusActive, tenant.StatusSuspended)
	}
	existing, err := s.store.GetTenant(ctx, in.Id)
	if errors.Is(err, tenant.ErrTenantNotFound) {
		return nil, status.Error(codes.NotFound, "tenant not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "preflight: %v", err)
	}
	if existing.Status == newStatus {
		// No-op flip; skip the write but still invalidate the cache
		// in case it drifted (cheap; no audit event).
		s.invalidateSuspensionCache(in.Id)
		return &adminv1.SetTenantStatusResponse{Tenant: tenantToProto(existing)}, nil
	}
	existing.Status = newStatus
	if err := s.store.PutTenant(ctx, existing); err != nil {
		return nil, status.Errorf(codes.Internal, "set status: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminTenantStatusChanged, in.Id+":"+string(newStatus))
	s.invalidateSuspensionCache(in.Id)
	// Active revocation on suspend: the suspension check only lazily rejects
	// access tokens on their next validate (and never touches refresh
	// tokens), so without this a suspended tenant's session survives via a
	// still-valid refresh token. Best-effort — the hook logs + audits
	// internally; fires only on a real flip to Suspended (the no-op path
	// returned above, and a flip to Active must not purge).
	if newStatus == tenant.StatusSuspended {
		s.revokeTenantTokens(ctx, in.Id)
	}
	fresh, _ := s.store.GetTenant(ctx, in.Id)
	if fresh == nil {
		fresh = existing
	}
	return &adminv1.SetTenantStatusResponse{Tenant: tenantToProto(fresh)}, nil
}

// ---------- Domain CRUD ----------

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
	out := &adminv1.ListDomainsResponse{Domains: make([]*adminv1.Domain, 0, len(all))}
	for _, d := range all {
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

// hasResidency reports whether a tenant carries any non-zero data-residency
// policy field. Used to keep CreateTenant's residency-cache eviction a no-op
// for the common (no-residency) create.
func hasResidency(t *tenant.Tenant) bool {
	return t != nil && (t.HomeRegion != "" || len(t.AllowedRegions) > 0 || t.EnforceWrites)
}

// ---------- proto <-> SDK conversion ----------

func tenantToProto(t *tenant.Tenant) *adminv1.Tenant {
	if t == nil {
		return nil
	}
	return &adminv1.Tenant{
		Id:             t.ID,
		Slug:           t.Slug,
		Name:           t.Name,
		Status:         string(t.Status),
		Settings:       t.Settings,
		HomeRegion:     t.HomeRegion,
		AllowedRegions: t.AllowedRegions,
		EnforceWrites:  t.EnforceWrites,
	}
}

func protoToTenant(p *adminv1.Tenant) *tenant.Tenant {
	if p == nil {
		return nil
	}
	return &tenant.Tenant{
		ID:             p.Id,
		Slug:           p.Slug,
		Name:           p.Name,
		Status:         tenant.Status(p.Status),
		Settings:       p.Settings,
		HomeRegion:     strings.TrimSpace(p.HomeRegion),
		AllowedRegions: trimRegions(p.AllowedRegions),
		EnforceWrites:  p.EnforceWrites,
	}
}

// trimRegions normalizes the inbound allowed-regions list: trims surrounding
// whitespace on each entry and drops empties, mirroring the light HomeRegion
// trim. It does NOT validate region identity (the tenant store doesn't), so
// an unknown region is accepted here and enforced/ignored downstream by the
// residency layer — keeping admin write semantics aligned with config-seeded
// tenants. nil/empty in -> nil out (zero value = unconstrained).
func trimRegions(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, r := range in {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
