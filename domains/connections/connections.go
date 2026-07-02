// Package connections models per-organization "enterprise connections" — a
// Tenant's binding to its own upstream identity provider (OIDC or SAML) — plus
// home-realm discovery (email-domain -> connection routing). This is the
// foundational B2B-SaaS primitive: "Acme's employees authenticate via Acme's
// Okta, BigCo's via BigCo's ADFS", routed by the user's email domain, with no
// per-tenant code.
//
// Scope: this package is the dependency-free MODEL + STORE SPI + RESOLVER.
// Wiring a resolved connection into the /auth/login upstream-authenticator
// selection (the global oidc_federation authenticator / the saml module) is a
// separate slice; the protocol-specific settings ride in Connection.Config as
// opaque key-values so this model pulls in no OIDC/SAML dependency.
package connections

import (
	"context"
	"errors"
	"strings"
)

// ConnectionType is the upstream IdP protocol a connection federates to.
type ConnectionType string

const (
	TypeOIDC ConnectionType = "oidc"
	TypeSAML ConnectionType = "saml"
)

// Connection binds a Tenant to one upstream IdP and the email domains that
// route to it (home-realm discovery).
type Connection struct {
	ID          string
	TenantID    string
	Type        ConnectionType
	DisplayName string

	// Domains are the email domains (e.g. "acme.com") whose users this
	// connection serves. A login identifier whose domain matches is routed to
	// this connection's upstream IdP. Matched case-insensitively.
	Domains []string

	// Enabled gates the connection; a disabled connection is never resolved by
	// home-realm discovery.
	Enabled bool

	// Config is opaque protocol-specific settings (e.g. oidc_issuer,
	// oidc_client_id, saml_metadata_url). Kept as a map so this model adds no
	// OIDC/SAML dependency; the authenticator that consumes the connection
	// interprets the keys it needs.
	Config map[string]string
}

// ErrNoConnection is returned when no enabled connection matches.
var ErrNoConnection = errors.New("connections: no matching connection")

// Store persists enterprise connections. Implementations MUST be safe for
// concurrent use and MUST return ErrNoConnection (not nil) on a miss.
type Store interface {
	// Get returns the connection by id, or ErrNoConnection.
	Get(ctx context.Context, id string) (*Connection, error)
	// ByTenant returns every connection owned by tenantID (possibly empty).
	ByTenant(ctx context.Context, tenantID string) ([]*Connection, error)
	// ByDomain returns the ENABLED connection routing emailDomain (home-realm
	// discovery), or ErrNoConnection. emailDomain is matched case-insensitively.
	ByDomain(ctx context.Context, emailDomain string) (*Connection, error)
	// Upsert inserts or replaces a connection (and its domain routing).
	Upsert(ctx context.Context, c *Connection) error
	// Delete removes the connection (and its domain routing). Idempotent.
	Delete(ctx context.Context, id string) error

	// DomainClaim returns connID's claim (pending or verified) on domain, or
	// ErrNoDomainClaim if connID has never claimed it. Upsert creates the
	// claim (with a fresh Token) the first time connID lists domain in its
	// Domains. domain is matched case-insensitively.
	DomainClaim(ctx context.Context, connID, domain string) (*DomainVerification, error)
	// DomainClaims returns every claim (pending + verified) connID currently
	// holds, so the admin UI can render "publish these TXT records" status.
	DomainClaims(ctx context.Context, connID string) ([]*DomainVerification, error)
	// VerifyDomain marks connID's claim on domain VERIFIED (idempotent) and
	// promotes connID to the ByDomain routing owner, demoting any prior
	// verified owner (DNS control changing hands is the correct signal).
	// Returns ErrNoDomainClaim if connID has not claimed domain. This is the
	// storage-only primitive: DNS-proof callers go through VerifyDomainOwnership,
	// while a boot-time/operator-trusted caller may call it directly to skip
	// the DNS round-trip.
	VerifyDomain(ctx context.Context, connID, domain string) error
}

// DomainFromIdentifier extracts the lowercase home-realm domain from a login
// identifier: the part after the last "@" for an email, or the whole string
// (lowercased, trimmed) for a bare domain. Returns "" for empty input.
func DomainFromIdentifier(identifier string) string {
	s := strings.ToLower(strings.TrimSpace(identifier))
	if s == "" {
		return ""
	}
	if at := strings.LastIndexByte(s, '@'); at >= 0 {
		s = s[at+1:]
	}
	return strings.TrimSpace(s)
}

// Resolve performs home-realm discovery: it maps a login identifier (email or
// bare domain) to the enabled connection serving that domain. Returns
// ErrNoConnection when the domain is empty or unmatched — the caller then falls
// back to the normal (non-federated) login path.
func Resolve(ctx context.Context, store Store, identifier string) (*Connection, error) {
	if store == nil {
		return nil, ErrNoConnection
	}
	domain := DomainFromIdentifier(identifier)
	if domain == "" {
		return nil, ErrNoConnection
	}
	return store.ByDomain(ctx, domain)
}
