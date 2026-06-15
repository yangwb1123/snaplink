package config

import "time"

type MeshConfig struct {
	ExtAuthz MeshExtAuthzConfig `yaml:"ext_authz"`
}

// MeshExtAuthzConfig opts into the Envoy/Istio ext_authz HTTP-mode
// authorization endpoint. A mesh sidecar (Envoy's ext_authz HTTP filter,
// or an Istio AuthorizationPolicy CUSTOM action with an HTTP provider)
// calls it per request: a 200 = ALLOW (and the sidecar injects the
// endpoint's X-Auth-* identity response headers into the upstream
// request), any other status = DENY. It reuses the same alg-confusion-safe
// bearer validation /userinfo uses (incl. the DPoP/mTLS sender-constraint
// checks), so a stolen sender-constrained token can't be replayed as a
// plain bearer.
//
// Disabled (the default) ⇒ the route is NOT mounted, byte-identical to a
// build without it. The endpoint is MESH-INTERNAL — only the trusted
// sidecar should reach it (operator network policy) — and the mesh MUST
// strip any client-supplied X-Auth-* at ingress (same edge-strip trust
// model as X-Forwarded-* / security.mtls.backend: header).
type MeshExtAuthzConfig struct {
	Enabled bool `yaml:"enabled"`

	// Path overrides the mount point. Empty ⇒ the SDK default
	// ("/mesh/ext-authz"). Must match the Envoy ext_authz HTTP filter's
	// path_prefix / the Istio provider URL.
	Path string `yaml:"path"`
}

// SPIFFEConfig opts into accepting a SPIFFE JWT-SVID as a token-exchange
// (RFC 8693) subject_token — the mesh-native service-to-service identity
// bridge (cluster C1). A mesh workload holding a SPIRE-issued JWT-SVID
// (a JWT whose `sub` is a spiffe:// URI, signed by the SPIRE server's JWT
// key) swaps it for THIS server's access token, exactly like upstream-IdP
// federation but via token-exchange instead of /auth/login.
//
// Disabled (the default) ⇒ byte-identical to a build without the feature:
// a spiffe-sub subject_token is rejected exactly as any other invalid
// subject_token. When Enabled, all three of TrustDomain / Audience /
// JWKSFile are REQUIRED (cmd fails loud otherwise) — there is no safe
// default for the trust domain or the audience the SVID must bind to.
//
// Scope: JWT-SVID only. x509-SVID / mTLS-SVID and the SPIRE Workload API
// are out (they need extra deps / a sidecar).
type SPIFFEConfig struct {
	Enabled bool `yaml:"enabled"`

	// TrustDomain is the ONLY SPIFFE trust domain whose SVIDs are
	// accepted, e.g. "example.org". An SVID whose `sub` trust-domain
	// differs is rejected — so a forged SVID from a foreign trust domain
	// cannot impersonate a local workload.
	TrustDomain string `yaml:"trust_domain"`

	// Audience is THIS server's identifier the SVID `aud` MUST contain
	// (strict aud-binding). A lax aud would let an SVID minted for a
	// different service be replayed here; typically set to the server
	// issuer URL or a dedicated audience the SPIRE registration entries
	// target.
	Audience string `yaml:"audience"`

	// JWKSFile is the path to the SPIRE trust-bundle JWKS document
	// (`{"keys":[...]}`) used to verify SVID signatures. Loaded once at
	// boot (StaticJWKS); rotating the SPIRE JWT key means redeploying the
	// file.
	JWKSFile string `yaml:"jwks_file"`

	// MaxClockSkew widens exp/nbf validation. 0 ⇒ SDK default (60s).
	MaxClockSkew time.Duration `yaml:"max_clock_skew"`
}

// CAEPConfig opts into the OpenID Shared Signals (CAEP/RISC) transmitter:
// real-time cross-RP revocation by pushing signed Security Event Tokens
// (RFC 8417) to the affected client's registered receiver endpoint
// (clients[].attributes.caep_receiver_endpoint). Disabled = byte-identical
// to no transmitter. The SET is signed by the same key already in JWKS, so
// no extra signing config is needed.
