package connections

import (
	"context"
	"net"
)

// DNSResolver is the seam VerifyDomainOwnership uses to read a domain's TXT
// records. It is an interface (mirroring domains/federation's fetcher seam) so
// tests inject a deterministic in-memory fake — no real network, no mocks — and
// operators can inject a DNS-over-HTTPS resolver via
// sso.WithDomainVerificationResolver.
type DNSResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// netDNSResolver is the production DNSResolver, backed by the stdlib default
// resolver.
type netDNSResolver struct{}

func (netDNSResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}

// NewDNSResolver returns the production stdlib-backed DNSResolver.
func NewDNSResolver() DNSResolver { return netDNSResolver{} }
