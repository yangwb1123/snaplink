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

// TxnTokenConfig opts into RFC 9321 OAuth 2.0 Transaction Tokens: minting a
// short-lived, workload-identity-bound token from an inbound access token
// (or, for a further hop, from a previously-issued Txn-Token) that a
// downstream microservice within the same Trust Domain verifies LOCALLY —
// no round trip back to this server. Lives here (not a new
// config_txntoken.go) for the SAME reason TrustConfig below does: the
// config/ directory is at its frozen file-count ceiling — see
// directory_fanout_test.go's dirFileCountExemptions.
//
// Disabled (the default) ⇒ byte-identical to a build without the feature.
// Mirrors TrustConfig's wiring model: the reference sso-server binary does
// NOT auto-wire this section (an Issuer/Validator pair is signing-key
// infrastructure — reusing the server's own signing issuer, whose
// SignJWT/JWKS methods already satisfy txntoken.Signer / core.JWKSProvider
// — not a simple bool flag). Operators wanting Transaction Tokens today
// construct txntoken.NewIssuer / txntoken.NewValidator directly and call
// sso.WithTransactionTokens; this section documents the shape a future
// cmd wiring would translate into that call.
type TxnTokenConfig struct {
	Enabled bool `yaml:"enabled"`

	// TrustDomain is the Trust Domain name every minted Txn-Token's `aud`
	// carries, and the ONLY value an inbound `audience` request parameter
	// may name (RFC 9321: a Txn-Token is valid in exactly one trust
	// domain, unlike a multi-audience exchanged access token). Required
	// when Enabled.
	TrustDomain string `yaml:"trust_domain"`

	// TTL bounds a minted Txn-Token's lifetime. 0 ⇒ txntoken.DefaultTTL
	// (30s) — deliberately much shorter than a normal access token.
	TTL time.Duration `yaml:"ttl"`
}

// CAEPConfig opts into the OpenID Shared Signals (CAEP/RISC) transmitter:
// real-time cross-RP revocation by pushing signed Security Event Tokens
// (RFC 8417) to the affected client's registered receiver endpoint
// (clients[].attributes.caep_receiver_endpoint). Disabled = byte-identical
// to no transmitter. The SET is signed by the same key already in JWKS, so
// no extra signing config is needed.

// TrustConfig opts into computing a Zero Trust Framework Phase 1 trust score
// (shared/trust) at login/token time — the mesh-adjacent building blocks
// this file already configures (ext_authz, SPIFFE) are exactly the policy
// enforcement points a later phase would gate on this score, hence its home
// here rather than a new config_trust.go (the config/ directory is at its
// frozen file-count ceiling — see directory_fanout_test.go's
// dirFileCountExemptions). It is a pure SCORING foundation: no
// conditional-access policy engine and no continuous/session-decay
// verification (Phase 2+, not implemented). Default (Enabled=false) means
// nothing is computed — byte-identical to a build without the feature.
//
// The reference sso-server binary DOES auto-wire this section
// (cmd/sso-server/serverbuildplatform.BuildTrustScorer, called from
// wireTrustScoring): each cfg.Weights entry names a reference scorer built
// from its own cfg.<Scorer> section into a trust.WeightedComposite, passed to
// sso.WithTrustScorer. When anomaly.enabled, the ip_reputation and behavior
// scorers read the SAME domains/anomaly stores (IPFailureCounter /
// RecentLoginStore) the anomaly detectors already populate, through
// composition-root adapters that reuse the anomaly.ip_salt hash space (one
// shared IP-hash space, not a second one) — see BuildTrustScorer's doc for the
// exact adapter shape. Embedders wanting a custom scorer instead of (or in
// addition to) the reference set still construct it directly via the SDK and
// call sso.WithTrustScorer themselves.
type TrustConfig struct {
	Enabled bool `yaml:"enabled"`

	// Weights sets each reference scorer's relative contribution to the
	// composite. Keys are the scorer's Name() ("geo_risk", "ip_reputation",
	// "behavior", "device_posture"); a missing key excludes that scorer.
	Weights map[string]float64 `yaml:"weights"`

	Geo           TrustGeoConfig           `yaml:"geo"`
	IPReputation  TrustIPReputationConfig  `yaml:"ip_reputation"`
	Behavior      TrustBehaviorConfig      `yaml:"behavior"`
	DevicePosture TrustDevicePostureConfig `yaml:"device_posture"`
	Serialization TrustSerializationConfig `yaml:"serialization"`
}

// TrustGeoConfig configures trust.GeoRiskScorer's country lists.
type TrustGeoConfig struct {
	TrustedCountries []string `yaml:"trusted_countries"`
	DeniedCountries  []string `yaml:"denied_countries"`
}

// TrustIPReputationConfig configures trust.IPReputationScorer's window and
// thresholds. Zero values fall back to the scorer's package defaults
// (trust.DefaultIPReputationWindow / DefaultIPFailureThreshold /
// DefaultIPDistinctSubjectThreshold).
type TrustIPReputationConfig struct {
	Window                   time.Duration `yaml:"window"`
	FailureThreshold         int           `yaml:"failure_threshold"`
	DistinctSubjectThreshold int           `yaml:"distinct_subject_threshold"`
	FloorOnError             float64       `yaml:"floor_on_error"`
}

// TrustBehaviorConfig configures trust.BehaviorScorer's history depth. Zero
// HistoryLimit falls back to trust.DefaultBehaviorHistoryLimit.
type TrustBehaviorConfig struct {
	HistoryLimit int     `yaml:"history_limit"`
	FloorOnError float64 `yaml:"floor_on_error"`
}

// TrustDevicePostureConfig configures the reserved trust.DevicePostureScorer
// stub (see trust.NewDevicePostureScorer) — DefaultScore is clamped to
// [0,1] and returned verbatim until an MDM integration replaces this
// scorer.
type TrustDevicePostureConfig struct {
	DefaultScore float64 `yaml:"default_score"`
}

// TrustSerializationConfig mirrors trust.SerializationConfig — see there for
// the default-off wire-safety contract (both flags false ⇒ no session
// metadata, no token claim, byte-identical to scoring never having run).
type TrustSerializationConfig struct {
	StampSessionMetadata bool   `yaml:"stamp_session_metadata"`
	IncludeTokenClaim    bool   `yaml:"include_token_claim"`
	ClaimName            string `yaml:"claim_name"`
}
