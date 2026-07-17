package grpcadmin

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/snaplink/sso/domains/tenant"
	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/platform/audit"
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

// ListTenants applies filter -> sort -> offset pagination over a full
// s.store.ListTenants(ctx) scan. See admin_paginate.go for why this bounds
// the RESPONSE but not the server-side materialization; mirrors
// ClientAdminService.List / UserAdminService.List exactly.
func (s *TenantAdminService) ListTenants(ctx context.Context, in *adminv1.ListTenantsRequest) (*adminv1.ListTenantsResponse, error) {
	if s.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "tenant store not configured")
	}
	all, err := s.store.ListTenants(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list tenants: %v", err)
	}
	all, err = filterTenants(all, in.GetFilter())
	if err != nil {
		return nil, err
	}
	if err = sortTenants(all, in.GetOrderBy()); err != nil {
		return nil, err
	}
	offset, err := decodeOffset(in.GetPageToken())
	if err != nil {
		return nil, err
	}
	lo, hi := pageBounds(offset, clampPageSize(in.GetPageSize()), len(all))
	out := &adminv1.ListTenantsResponse{
		Tenants:       make([]*adminv1.Tenant, 0, hi-lo),
		TotalSize:     int32(len(all)),
		NextPageToken: encodeOffset(hi, len(all)),
	}
	for _, t := range all[lo:hi] {
		out.Tenants = append(out.Tenants, tenantToProto(t))
	}
	return out, nil
}

// filterTenants narrows all to rows matching expr, or returns all unchanged
// when expr is empty. Field set: id/slug/status (exact) + name (substring) —
// the fields a Tenant carries that make sense as filter keys.
func filterTenants(all []*tenant.Tenant, expr string) ([]*tenant.Tenant, error) {
	field, value, ok := parseAdminFilter(expr)
	if !ok {
		return all, nil
	}
	out := make([]*tenant.Tenant, 0, len(all))
	for _, t := range all {
		match, err := tenantMatches(t, field, value)
		if err != nil {
			return nil, err
		}
		if match {
			out = append(out, t)
		}
	}
	return out, nil
}

// tenantMatches evaluates one filter field against a tenant.
func tenantMatches(t *tenant.Tenant, field, value string) (bool, error) {
	switch strings.ToLower(field) {
	case "id":
		return t.ID == value, nil
	case "slug":
		return t.Slug == value, nil
	case "name":
		return strings.Contains(strings.ToLower(t.Name), strings.ToLower(value)), nil
	case "status":
		return string(t.Status) == value, nil
	default:
		return false, status.Errorf(codes.InvalidArgument, "unsupported filter field %q", field)
	}
}

// sortTenants orders all in place by order_by (default: id ascending, the
// MANDATORY stable sort that makes offset paging deterministic regardless of
// the backing store's own return order).
func sortTenants(all []*tenant.Tenant, orderBy string) error {
	field, desc := parseOrderBy(orderBy)
	less, err := tenantLess(field)
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

// tenantLess returns the comparator for one order_by field.
func tenantLess(field string) (func(a, b *tenant.Tenant) bool, error) {
	switch strings.ToLower(field) {
	case "", "id":
		return func(a, b *tenant.Tenant) bool { return a.ID < b.ID }, nil
	case "slug":
		return func(a, b *tenant.Tenant) bool { return a.Slug < b.Slug }, nil
	case "name":
		return func(a, b *tenant.Tenant) bool { return a.Name < b.Name }, nil
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported order_by field %q", field)
	}
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
	// tenant.Tenant.Validate() (called inside store.PutTenant) only defaults
	// an EMPTY status to Active — it does not reject a garbage non-empty
	// value, so without this gate a caller could persist e.g. Status:"banana"
	// straight through Create. SetTenantStatus already rejects unknown values
	// (see the identical check below); Create must match so "known value or
	// omitted" is enforced on every path that can set Status, not just the
	// dedicated one.
	if !validCreateStatus(in.Tenant.Status) {
		return nil, status.Errorf(codes.InvalidArgument, "status must be empty, %q, or %q",
			tenant.StatusActive, tenant.StatusSuspended)
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

// Domain CRUD (ListDomains/GetDomain/CreateDomain/UpdateDomain/DeleteDomain)
// lives in admin_domains.go — split out to keep this file under the 500-line
// maintainability budget once ListTenants grew filter/sort support; same
// receiver (*TenantAdminService), same package.

// hasResidency reports whether a tenant carries any non-zero data-residency
// policy field. Used to keep CreateTenant's residency-cache eviction a no-op
// for the common (no-residency) create.
func hasResidency(t *tenant.Tenant) bool {
	return t != nil && (t.HomeRegion != "" || len(t.AllowedRegions) > 0 || t.EnforceWrites)
}

// validCreateStatus mirrors SetTenantStatus's allowlist: a CreateTenant body
// may omit status (tenant.Tenant.Validate defaults empty to Active) or set
// it to one of the two known values. Any other literal (a typo, or a status
// name from an unrelated system) is rejected here rather than silently
// persisted — domains/tenant's middleware treats anything other than
// StatusActive as "deny access" (fail-safe), so a garbage value wouldn't
// open a security hole, but it WOULD silently lock the tenant out with no
// indication why, and it would violate the documented contract that Status
// is only ever mutated through Create (known value) or SetTenantStatus.
func validCreateStatus(s string) bool {
	return s == "" || tenant.Status(s) == tenant.StatusActive || tenant.Status(s) == tenant.StatusSuspended
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

// domainToProto / protoToDomain live in admin_domains.go alongside the
// Domain CRUD methods that use them.
