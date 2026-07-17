// Package region is the multi-region / data-residency layer's identity
// SPI. A serving-region ID names WHICH regional deployment is handling a
// request; a tenant's ResidencyPolicy names WHERE that tenant's data is
// allowed to live. The two together let an operator enforce that an EU
// tenant's writes only ever land on an EU-pinned replica.
//
// This package mirrors geo/'s discipline deliberately: it is opt-in and
// nil-default byte-identical (a server that never wires a Resolver behaves
// exactly as before), the middleware is non-fatal (a resolution failure
// stashes an empty region and the request proceeds — region is a routing
// signal, not a credential check), and the resolved value is stashed on
// core.HandlerContext the same way geo stashes *GeoInfo.
//
// The serving region is intentionally a DIFFERENT namespace from geo's
// GeoInfo.Region (an ISO 3166-2 subdivision derived from the client IP):
// geo.region describes WHERE THE CLIENT IS, region.serving describes WHICH
// DEPLOYMENT SERVED them. Conflating the two would let a client-IP geo hint
// masquerade as a serving-region governance signal.
package region

import (
	"context"
	"errors"
	"net/http"
)

// ID identifies a serving region (e.g. "eu-west-1", "us-east-1"). The
// empty string means unknown / unconstrained: a resolver that can't place
// the request returns "", and a tenant with no pinned region accepts any.
type ID string

// Resolver derives the serving-region ID for a request. Implementations
// live in this package (ConfigPinnedResolver / HeaderResolver /
// ChainResolver) or are operator-supplied. They run on the request hot
// path, so they must be cheap and safe for concurrent use.
//
// Returning ("", nil) is normal: it means "no region determined", which
// downstream layers treat as unconstrained. A non-nil error signals the
// resolution itself failed (a malformed source); the middleware logs it
// via OnError and proceeds with an empty region — resolution is never
// request-fatal here (enforcement is a later layer's concern).
type Resolver interface {
	Resolve(r *http.Request) (ID, error)
}

// ResidencyPolicy is a tenant's data-residency anchor. HomeRegion is the
// region the tenant's data primarily lives in; AllowedRegions is the set a
// request may be served from without violating residency (HomeRegion is
// implicitly allowed). EnforceWrites flips this from an advisory signal
// into a hard gate at the enforcement layer (interfaces/sso's
// WithTenantResidencyCheck, wired by cmd/sso-server via
// config.Region.ResidencyCheckCacheTTL) — when false the policy is
// observed but never blocks.
//
// The zero value (empty HomeRegion, nil AllowedRegions, EnforceWrites
// false) is unconstrained: every region is acceptable. This keeps tenants
// that never set a policy byte-compatible with pre-residency behavior.
type ResidencyPolicy struct {
	HomeRegion     ID
	AllowedRegions []ID
	EnforceWrites  bool
}

// PolicyStore resolves a tenant's ResidencyPolicy. It is keyed by tenant
// ID (a plain string — region/ sits above tenant/ and the residency policy
// is derived from the tenant's pinned-region fields). Absent or
// unconstrained tenants return the zero ResidencyPolicy, not an error, so
// callers never have to distinguish "no policy" from "unconstrained
// policy" — they are the same thing.
type PolicyStore interface {
	GetPolicy(ctx context.Context, tenantID string) (ResidencyPolicy, error)
}

// Governance error sentinels. Callers branch on these via errors.Is. They
// are residency-violation signals surfaced at the enforcement layer
// (interfaces/sso/server_tenant_residency.go), distinct from the
// credential-oracle errors in core/ — they reveal a tenant's
// data-residency binding the same way the existing tenant_mismatch
// reveals tenant binding, so they carry no anti-enumeration concern.
var (
	ErrResidencyViolation = errors.New("region: residency violation")
	ErrRegionNotAllowed   = errors.New("region: serving region not allowed for tenant")
)

// HandlerContextKey is the value-bag key the region middleware uses to
// stash the resolved serving-region ID on core.HandlerContext. Handlers
// should prefer FromHandlerContext to a raw ctx.Get — the helper does the
// type assertion + nil guard in one place (mirrors geo.HandlerContextKey).
const HandlerContextKey = "region:serving"
