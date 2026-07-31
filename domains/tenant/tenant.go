// Package tenant is the multi-tenant + multi-domain layer that
// sits in front of the SSO control plane. A Tenant is a business
// boundary (independent billing, audit, admin); a Domain is a
// hostname mapped to one Tenant. The same SSO server can host
// admin.acme.com + portal.acme.com (both → tenant "acme") and
// admin.beta.io (→ tenant "beta") without operators having to run
// separate binaries.
//
// Tenant ownership is intentionally one level above sso.Client:
// one tenant typically owns multiple clients (admin-portal,
// customer-portal, mobile-API, etc.) sharing the same audit
// trail and billing relationship. The Client → Tenant link lands
// in a follow-up; this package lays the routing foundation
// independently so middleware + audit can pick it up first.
package tenant

import (
	"context"
	"errors"
	"time"
)

// Tenant is one business boundary. Slug is the URL-safe
// identifier operators use in admin tooling ("acme-corp"); ID is
// the immutable primary key. Settings is intentionally loose —
// per-tenant feature flags, default locale, branding tokens —
// without forcing a wide table for every new toggle.
type Tenant struct {
	ID       string            `json:"id"`
	Slug     string            `json:"slug"`
	Name     string            `json:"name"`
	Status   Status            `json:"status"`
	Settings map[string]string `json:"settings,omitempty"`

	// HomeRegion + AllowedRegions + EnforceWrites are the data-residency
	// anchor consumed by the multi-region layer (region.ResidencyPolicy).
	// HomeRegion names the region this tenant's data primarily lives in;
	// AllowedRegions is the set a request may be served from; EnforceWrites
	// flips residency from an advisory signal into a hard write-routing gate
	// (a write served outside HomeRegion is rejected at the enforcement
	// layer). Plain strings (not region.ID) keep tenant/ a lower-level
	// package that region/ depends on — region/ maps these to region.ID, not
	// the reverse. Zero value ("" / nil / false) = unconstrained and
	// fail-open, so tenants predating these fields are byte-compatible.
	HomeRegion     string   `json:"home_region,omitempty"`
	AllowedRegions []string `json:"allowed_regions,omitempty"`
	EnforceWrites  bool     `json:"enforce_writes,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// Status enumerates the operational states an operator can flip.
// "suspended" tenants resolve at the routing layer but middleware
// SHOULD reject the request — handlers can surface a maintenance
// page rather than a generic 404.
type Status string

const (
	StatusActive    Status = "active"
	StatusSuspended Status = "suspended"
)

// Domain is one hostname pointing at a Tenant. Hostname is the
// unique key. DefaultClientID is consulted by handlers that need
// to pick a client without one in the URL (typical login page
// served at "auth.acme.com" with no client_id query param).
type Domain struct {
	Hostname        string            `json:"hostname"`
	TenantID        string            `json:"tenant_id"`
	DefaultClientID string            `json:"default_client_id,omitempty"`
	IsApex          bool              `json:"is_apex,omitempty"` // acme.com vs portal.acme.com
	Branding        map[string]string `json:"branding,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at,omitzero"`
}

// Store persists Tenants + Domains. Implementations live in
// tenant/<backend>/. A single Store interface owns both resource
// types because the routing-layer hot path always wants both
// (Domain → Tenant in one round trip).
//
// All lookups are read-mostly; the Tenant + Domain set rarely
// changes in flight, so backends MAY cache aggressively.
type Store interface {
	// Tenant CRUD.
	GetTenant(ctx context.Context, id string) (*Tenant, error)
	ListTenants(ctx context.Context) ([]*Tenant, error)
	PutTenant(ctx context.Context, t *Tenant) error
	DeleteTenant(ctx context.Context, id string) error

	// Domain CRUD. GetDomain is the hot-path resolution.
	GetDomain(ctx context.Context, hostname string) (*Domain, error)
	ListDomains(ctx context.Context) ([]*Domain, error)
	ListDomainsByTenant(ctx context.Context, tenantID string) ([]*Domain, error)
	PutDomain(ctx context.Context, d *Domain) error
	DeleteDomain(ctx context.Context, hostname string) error

	// Close releases backend resources (DB connections, watcher
	// goroutines). Safe to call multiple times.
	Close() error
}

// Branding is the independently versioned tenant branding resource.
// Branding is deliberately separate from Tenant.Settings so an editor cannot
// overwrite feature flags, locale, or other tenant configuration.
type Branding struct {
	Values  map[string]string `json:"branding"`
	Version string            `json:"version"`
}

// BrandingStore applies atomic optimistic concurrency to tenant branding.
// Expected version "0" creates the resource; every successful write advances
// the version. Implementations must not read-modify-write Tenant.Settings.
type BrandingStore interface {
	GetBranding(ctx context.Context, tenantID string) (Branding, error)
	PutBranding(
		ctx context.Context, tenantID string, values map[string]string, expectedVersion string,
	) (Branding, error)
}

// Sentinel errors. Admin RPCs map these to gRPC codes; middleware
// treats ErrTenantNotFound / ErrDomainNotFound as "no tenant for
// this request" (non-fatal — handlers decide).
var (
	ErrTenantNotFound       = errors.New("tenant: not found")
	ErrDomainNotFound       = errors.New("tenant: domain not found")
	ErrDomainExists         = errors.New("tenant: domain hostname already in use")
	ErrTenantExists         = errors.New("tenant: id already in use")
	ErrInvalidTenant        = errors.New("tenant: invalid")
	ErrInvalidDomain        = errors.New("tenant: invalid domain")
	ErrBrandingPrecondition = errors.New("tenant: branding precondition failed")
)

// Validate sanity-checks a Tenant before persistence. ID + Slug
// must both be set so callers can reference the tenant either way.
func (t *Tenant) Validate() error {
	if t.ID == "" {
		return errors.Join(ErrInvalidTenant, errors.New("id required"))
	}
	if t.Slug == "" {
		return errors.Join(ErrInvalidTenant, errors.New("slug required"))
	}
	if t.Status == "" {
		// Default to active so admins don't have to remember.
		t.Status = StatusActive
	}
	return nil
}

// Validate sanity-checks a Domain. Hostname + TenantID required;
// the Store enforces hostname uniqueness + TenantID existence on
// PutDomain.
func (d *Domain) Validate() error {
	if d.Hostname == "" {
		return errors.Join(ErrInvalidDomain, errors.New("hostname required"))
	}
	if d.TenantID == "" {
		return errors.Join(ErrInvalidDomain, errors.New("tenant_id required"))
	}
	return nil
}
