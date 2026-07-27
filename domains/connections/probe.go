package connections

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/shared/security"
)

// probe.go performs the admin-triggered lightweight reachability/handshake
// check against a connection's configured upstream — an OIDC discovery fetch
// or a SAML metadata fetch, depending on Connection.Type — and orchestrates
// persisting the outcome via Store.RecordHealth so GET .../health always
// reflects the LAST probe, not just whichever admin session last ran one.
//
// This is admin-triggered, trusted-input config (Connection.Config is only
// ever written through the admin:write API), NOT an attacker-influenceable
// fetch target the way federation's entity IDs are — so unlike
// domains/federation/fetcher.go this probe does not need the SSRF dial-time
// IP-block gate; an operator's on-prem IdP living on an internal address is
// a legitimate, common target here. It still bounds timeout + response size
// (shared/security.NewUpstreamClient + a LimitReader) so a slow or huge
// upstream can't hang or OOM the admin request that triggered it.

const (
	// ConfigKeyOIDCIssuer / ConfigKeySAMLMetadataURL name the Connection.Config
	// entries the probe reads to find the upstream to test — the same keys
	// Connection.Config's doc comment lists as protocol-specific settings.
	// This probe is the first actual consumer of them.
	ConfigKeyOIDCIssuer      = "oidc_issuer"
	ConfigKeySAMLMetadataURL = "saml_metadata_url"
)

// wellKnownOIDCConfigPath is the OIDC Discovery 1.0 §4.1 well-known suffix.
// Duplicated from interfaces/sso.PathOIDCDiscovery rather than imported: this
// package sits below interfaces/sso in the layer graph (imports point DOWN
// only), and the suffix is an RFC-fixed string neither side will
// independently rename.
const wellKnownOIDCConfigPath = "/.well-known/openid-configuration"

// DefaultProbeTimeout bounds a single probe's HTTP round-trip so a slow or
// hung upstream cannot stall the admin request that triggered it.
const DefaultProbeTimeout = 10 * time.Second

// maxProbeBodyBytes caps a fetched discovery/metadata document. Both are a
// few KB in normal operation; this is generous slack while keeping a
// pathological (or hostile) response's memory footprint bounded.
const maxProbeBodyBytes = 256 * 1024

// ProbeResult is one probe attempt's outcome — the Prober's return value.
// Kept distinct from ConnectionHealth (the STORED record) so a Prober
// implementation needs no knowledge of persistence or timestamps.
type ProbeResult struct {
	Status HealthStatus
	Err    string // human-readable detail, secret-free; "" when Status == HealthHealthy
}

// Prober performs the reachability check against a connection's configured
// upstream. Interface (mirrors DNSResolver) so tests run network-free with a
// fake; NewHTTPProber returns the production implementation.
type Prober interface {
	Probe(ctx context.Context, c *Connection) ProbeResult
}

// httpProber is the production Prober.
type httpProber struct {
	client *http.Client
}

// NewHTTPProber returns the production Prober. timeout <= 0 uses
// DefaultProbeTimeout.
func NewHTTPProber(timeout time.Duration) Prober {
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	return &httpProber{client: security.NewUpstreamClient(security.UpstreamClientConfig{Timeout: timeout})}
}

// Probe implements Prober.
func (p *httpProber) Probe(ctx context.Context, c *Connection) ProbeResult {
	switch c.Type {
	case TypeOIDC:
		return p.probeOIDC(ctx, c)
	case TypeSAML:
		return p.probeSAML(ctx, c)
	default:
		return ProbeResult{Status: HealthUnreachable, Err: TruncateHealthError(fmt.Sprintf("unsupported connection type %q", c.Type))}
	}
}

// probeOIDC fetches issuer's discovery document and requires a non-empty
// "issuer" claim — a bare 2xx isn't enough proof this is really a working
// OIDC provider (a misrouted load balancer can 200 with an HTML error page).
func (p *httpProber) probeOIDC(ctx context.Context, c *Connection) ProbeResult {
	issuer := strings.TrimSpace(c.Config[ConfigKeyOIDCIssuer])
	if issuer == "" {
		return ProbeResult{Status: HealthUnreachable, Err: fmt.Sprintf("connection config missing %q", ConfigKeyOIDCIssuer)}
	}
	body, status, err := p.get(ctx, strings.TrimRight(issuer, "/")+wellKnownOIDCConfigPath)
	if err != nil {
		return ProbeResult{Status: HealthUnreachable, Err: TruncateHealthError(err.Error())}
	}
	if status < 200 || status >= 300 {
		return ProbeResult{Status: HealthDegraded, Err: fmt.Sprintf("discovery endpoint returned status %d", status)}
	}
	var doc struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Issuer == "" {
		return ProbeResult{Status: HealthDegraded, Err: "discovery document missing issuer"}
	}
	return ProbeResult{Status: HealthHealthy}
}

// probeSAML fetches the configured metadata URL and requires the response to
// parse as XML with a root <EntityDescriptor> element (SAML Metadata §2.3.1).
func (p *httpProber) probeSAML(ctx context.Context, c *Connection) ProbeResult {
	metaURL := strings.TrimSpace(c.Config[ConfigKeySAMLMetadataURL])
	if metaURL == "" {
		return ProbeResult{Status: HealthUnreachable, Err: fmt.Sprintf("connection config missing %q", ConfigKeySAMLMetadataURL)}
	}
	body, status, err := p.get(ctx, metaURL)
	if err != nil {
		return ProbeResult{Status: HealthUnreachable, Err: TruncateHealthError(err.Error())}
	}
	if status < 200 || status >= 300 {
		return ProbeResult{Status: HealthDegraded, Err: fmt.Sprintf("metadata endpoint returned status %d", status)}
	}
	var doc struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal(body, &doc); err != nil || !strings.EqualFold(doc.XMLName.Local, "EntityDescriptor") {
		return ProbeResult{Status: HealthDegraded, Err: "metadata document is not a SAML EntityDescriptor"}
	}
	return ProbeResult{Status: HealthHealthy}
}

// get performs a bounded GET, returning the (capped) body and status code.
func (p *httpProber) get(ctx context.Context, rawURL string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json, application/xml, application/samlmetadata+xml")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBodyBytes))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read body: %w", err)
	}
	return body, resp.StatusCode, nil
}

// RunProbe executes prober against c and persists the outcome via
// store.RecordHealth, returning the updated ConnectionHealth. LastSuccessAt
// only advances on a HealthHealthy outcome — a failed probe keeps whatever
// LastSuccessAt was already on record, so the admin view keeps showing "last
// known good" through a flap instead of losing it. prober == nil uses
// NewHTTPProber(0) (the production default).
func RunProbe(ctx context.Context, store Store, prober Prober, c *Connection) (*ConnectionHealth, error) {
	if prober == nil {
		prober = NewHTTPProber(0)
	}
	result := prober.Probe(ctx, c)
	prior, err := store.Health(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	h := &ConnectionHealth{
		ConnectionID:  c.ID,
		Status:        result.Status,
		LastCheckedAt: time.Now().UTC(),
		LastSuccessAt: prior.LastSuccessAt,
		LastError:     TruncateHealthError(result.Err),
	}
	if result.Status == HealthHealthy {
		h.LastSuccessAt = h.LastCheckedAt
	}
	if err := store.RecordHealth(ctx, c.ID, h); err != nil {
		return nil, err
	}
	return h, nil
}
