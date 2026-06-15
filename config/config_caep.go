package config

import "time"

type CAEPConfig struct {
	Enabled bool `yaml:"enabled"`
	// ReceiverTimeout caps a single SET POST (per-receiver). 0 = the SDK
	// default (10s). A slow/dead receiver's SET is dropped past this bound;
	// the broadcast goroutine never pins on it.
	ReceiverTimeout time.Duration `yaml:"receiver_timeout"`
	// SETTTL bounds the lifetime stamped into each SET. 0 = SDK default (2m).
	SETTTL time.Duration `yaml:"set_ttl"`

	// Receiver opts into the INBOUND half of OpenID Shared Signals — the
	// CAEP/SSF push-delivery receiver that CONSUMES SETs from trusted
	// upstream transmitters and revokes local access. Independent of the
	// (outbound) transmitter above: a deployment may run either, both, or
	// neither. Disabled = the /ssf/receive route is NOT mounted.
	Receiver CAEPReceiverConfig `yaml:"receiver"`
}

// CAEPReceiverConfig opts into the OpenID Shared Signals (CAEP/SSF)
// push-delivery RECEIVER (RFC 8935) — the inbound half of Shared Signals.
// It mounts an endpoint that consumes signed Security Event Tokens from
// CONFIGURED trusted upstream transmitters and, on a fully-validated
// revocation event for a PRECISELY-mapped local subject, revokes that
// subject's local access (sessions + refresh tokens).
//
// Disabled (the default) ⇒ byte-identical to a build without the feature
// (the route is not mounted). When Enabled, BOTH Audience and at least one
// Transmitters[] entry are REQUIRED (cmd fails loud) — there is no safe
// default for the audience a SET must bind to, nor for the set of upstreams
// allowed to trigger a revocation.
//
// SECURITY: only a SET signed by a configured transmitter (iss-allowlist +
// signature against that transmitter's trust-bundle JWKS) addressed to this
// server's Audience can revoke anything; a stale/replayed/forged SET, or
// one for an unknown subject, does nothing.
type CAEPReceiverConfig struct {
	Enabled bool `yaml:"enabled"`

	// Path is the mount point for the push-delivery endpoint. Empty ⇒ the
	// SDK default ("/ssf/receive"). Must match the upstream transmitter's
	// configured delivery URL path.
	Path string `yaml:"path"`

	// Audience is THIS server's identifier the inbound SET `aud` MUST
	// contain (strict aud-binding — a lax aud would let a SET minted for a
	// different receiver be replayed here). Typically the server issuer URL
	// or a dedicated SSF audience the upstream targets.
	Audience string `yaml:"audience"`

	// MaxClockSkew widens SET iat/exp freshness validation. 0 ⇒ SDK default
	// (60s).
	MaxClockSkew time.Duration `yaml:"max_clock_skew"`

	// Transmitters is the trusted-transmitter allowlist. A SET whose `iss`
	// matches none of these is rejected before any signature work. At least
	// one is required when Enabled.
	Transmitters []CAEPTransmitterConfig `yaml:"transmitters"`
}

// CAEPTransmitterConfig describes ONE trusted upstream transmitter the
// receiver accepts SETs from. The set of these IS the trust allowlist.
type CAEPTransmitterConfig struct {
	// Issuer is the exact `iss` value the upstream stamps into its SETs,
	// matched case-sensitively. Required.
	Issuer string `yaml:"issuer"`

	// JWKSFile is the path to this transmitter's published signing-key JWKS
	// document (`{"keys":[...]}`, its trust bundle), loaded once at boot
	// into a StaticJWKS. The SET signature is verified against THESE keys.
	// Required.
	JWKSFile string `yaml:"jwks_file"`

	// SubjectMode selects how this transmitter's SET subjects map to local
	// users:
	//   - "opaque" (default) treats the SET sub_id `id` as the LOCAL user id
	//     directly. SECURITY: this grants the transmitter authority to revoke
	//     ANY local user it can name by id (a full-namespace "logout
	//     everywhere" primitive — the only guard is that the user exists, which
	//     any victim's id satisfies). Use it ONLY for a FULLY-trusted peer that
	//     shares this server's subject namespace — NOT for a partially-trusted
	//     upstream IdP.
	//   - "iss_sub" resolves the federation link
	//     (GetByExternalID(provider, sub)) for a partially-trusted upstream
	//     whose subject namespace differs from this server's. It confines the
	//     transmitter to subjects under its operator-pinned Provider (below),
	//     so it can NEVER revoke users federated from a different upstream.
	SubjectMode string `yaml:"subject_mode"`

	// Provider is the local federation provider name used to resolve an
	// iss_sub subject. REQUIRED under subject_mode: iss_sub (boot fails loud
	// on empty) — it MUST be operator-pinned to THIS transmitter's trusted
	// federated namespace and is NEVER derived from the SET's sub_id.iss
	// (which the transmitter controls; trusting it would let a transmitter
	// revoke users federated from ANY other provider — a cross-IdP subject
	// hijack). Ignored under subject_mode: opaque.
	Provider string `yaml:"provider"`

	// AllowedEvents, when non-empty, restricts which SSF event URIs from
	// THIS transmitter are honored (an event outside the set is ignored,
	// never an error). Empty ⇒ every revocation event the receiver knows is
	// honored.
	AllowedEvents []string `yaml:"allowed_events"`

	// AllowedAlgs restricts the asymmetric JWS algs accepted from this
	// transmitter's bundle. Empty ⇒ the receiver default
	// (ES256/RS256/PS256/EdDSA). A symmetric alg is rejected by the verifier.
	AllowedAlgs []string `yaml:"allowed_algs"`
}

// FederationConfig opts into the OpenID Federation 1.0 entity-configuration
// endpoint: the server publishes its SELF-SIGNED Entity Statement at
// /.well-known/openid-federation so it participates in a multilateral
// federation as an ENTITY. Disabled (the default) ⇒ the route is NOT mounted
// and behavior is byte-identical to a build without it. The Entity Statement
// is signed by the SAME key already in JWKS (the OP signing issuer's generic
// SignJWT seam), so no extra signing config is needed.
//
// This config wires BOTH the entity-PUBLISHING surface and the trust-chain
// RESOLUTION surface. TrustAnchors, empty by default, is now LIVE: each anchor's
// jwks_file is loaded as the root-of-trust key set the resolver validates a
// remote entity's chain against. With no anchors configured the resolver is
// inert (entity-publishing behavior is byte-identical).
