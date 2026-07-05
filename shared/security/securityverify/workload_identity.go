package securityverify

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Cloud workload-identity acceptance (AWS/GCP/Azure).
//
// A workload running on a cloud VM/container can hold a cloud-MINTED
// identity token (GCP: a metadata-server-issued OIDC ID token; AWS: an STS
// AssumeRoleWithWebIdentity-style OIDC token or the IMDSv2 instance identity
// document; Azure: an Azure AD Workload Identity Federation token) without
// ever touching a static client_secret. Accepting one as /token client
// authentication is the SAME shape of problem the SPIFFE JWT-SVID path
// already solves (spiffe_svid.go): verify a foreign, cryptographically
// signed token against the ISSUING party's OWN published JWKS, then map the
// verified identity onto something THIS server recognizes — a
// pre-registered Client here, rather than a Subject on a token-exchange.
//
// Shared core / per-cloud preset split (this file / workload_identity_presets.go):
// signature verification, temporal checks, issuer/audience binding, and JWKS
// fetch-with-cache are ALL cloud-agnostic and live once in
// WorkloadIdentityValidator. Each cloud only supplies its issuer + JWKS URL
// (or, for AWS, how to DERIVE the JWKS URL from an operator-supplied issuer)
// + a claims-mapping function (claimsMapper) that projects that cloud's
// token shape onto the common WorkloadIdentity result — so adding a cloud
// never means re-deriving signature verification.
//
// Status: GCP and AWS are fully implemented (workload_identity_presets.go —
// GCP: metadata-server-issued OIDC ID tokens verified against Google's
// stable public JWKS; AWS: an operator-configured OIDC issuer, typically a
// per-cluster EKS OIDC provider URL, with the JWKS URL derived from it via
// the `<issuer>/.well-known/jwks.json` convention). Azure is a DELIBERATE
// FOLLOW-UP, not started:
//
//   - Azure AD Workload Identity Federation tokens ARE OIDC-shaped
//     (issuer `https://login.microsoftonline.com/{tenant}/v2.0`, discovery
//     at the tenant's `/.well-known/openid-configuration`), so it likely
//     CAN reuse WorkloadIdentityValidator directly via
//     NewHTTPJWKSSource(tenantJWKSURL) plus an azureClaimsMapper (oid + tid
//     + appid claims) once a tenant-scoped constructor is added — smaller
//     lift than AWS was, still deferred to keep each change reviewable one
//     cloud at a time.
//
// Wiring: interfaces/sso.WithWorkloadIdentityProviders registers one or more
// WorkloadIdentityProvider values; a Client opts in by setting
// TokenEndpointAuthMethod to the workload-identity method AND both
// AttrWorkloadIdentityProvider ("gcp"/"aws") and AttrWorkloadIdentitySubject
// (the expected mapped identity, e.g. a GCP service-account email or an AWS
// EKS "system:serviceaccount:<namespace>:<name>" subject) in
// Client.Attributes — mirroring how CAEP reads its receiver endpoint out of
// Client.Attributes instead of growing core.Client.

// CloudProvider identifies which cloud issued a workload identity token.
type CloudProvider string

const (
	CloudProviderGCP   CloudProvider = "gcp"
	CloudProviderAWS   CloudProvider = "aws"
	CloudProviderAzure CloudProvider = "azure" // reserved: see package doc follow-up
)

// AttrWorkloadIdentityProvider / AttrWorkloadIdentitySubject are the
// Client.Attributes keys an operator sets to opt a client into workload-
// identity authentication: which registered WorkloadIdentityProvider.Name()
// to use, and the expected WorkloadIdentity.Subject the verified token MUST
// produce. Same "attributes carry the extension config" convention as
// caep.AttrReceiverEndpoint.
const (
	AttrWorkloadIdentityProvider = "workload_identity_provider"
	AttrWorkloadIdentitySubject  = "workload_identity_subject"
)

// WorkloadIdentity is the validated, cloud-agnostic identity extracted from
// an inbound cloud-issued token — the workload-identity analog of SPIFFEID.
type WorkloadIdentity struct {
	// Provider is the cloud that issued the token.
	Provider CloudProvider
	// Subject is the STABLE, comparison-ready identity string an operator
	// registers verbatim in Client.Attributes[AttrWorkloadIdentitySubject]
	// — e.g. for GCP a service-account email
	// "sa-name@project.iam.gserviceaccount.com". This is the field the
	// /token gate compares; every other field is informational.
	Subject string
	// AccountID is the cloud account/project/subscription id (GCP project
	// ID, AWS account id, Azure subscription id) when the token carries one.
	AccountID string
	// Attributes projects extra claims (region/zone/instance/etc) as string
	// attributes for audit logging — same shape as SPIFFEID.Attributes().
	Attributes map[string]string
}

// WorkloadIdentityProvider validates an inbound cloud-issued identity token
// and returns the mapped WorkloadIdentity. Each cloud gets its own thin
// preset (issuer + audience + JWKS source + claims mapper) built on the
// shared WorkloadIdentityValidator core, so N clouds share ONE verifier
// instead of N hand-rolled copies.
type WorkloadIdentityProvider interface {
	// Name is the short provider key an operator writes into
	// Client.Attributes[AttrWorkloadIdentityProvider] ("gcp", "aws", "azure").
	Name() string
	// Validate verifies token (a compact JWS) and returns the mapped cloud
	// identity. expectedAudience is THIS server's identifier — mirrors the
	// RFC 7523 private_key_jwt aud-binding requirement (the AS issuer),
	// stopping a token minted for a different relying party being replayed
	// here. Every failure returns ErrWorkloadIdentityInvalid — no cause is
	// distinguishable on the wire (oracle-leak hardening).
	Validate(ctx context.Context, token, expectedAudience string) (*WorkloadIdentity, error)
}

// ErrWorkloadIdentityInvalid is the SINGLE opaque error every workload-
// identity validation failure returns — bad signature, wrong issuer, wrong
// audience, expired, missing/unmapped claims, JWKS fetch failure. Mirrors
// ErrSPIFFESVIDInvalid: the /token client-authentication gate collapses
// every cause into the existing invalid_client wire response (AGENTS.md §3
// Oracle-Leak Hardening: "private_key_jwt failure -> invalid_client") so an
// attacker probing a misconfigured or targeted workload learns nothing about
// which check failed.
var ErrWorkloadIdentityInvalid = errors.New("workload_identity: token invalid")

// DefaultWorkloadIdentityMaxClockSkew tolerates clock drift between the
// cloud metadata service and this server when checking exp/nbf. Cloud
// workload-identity tokens are typically requested with a caller-chosen TTL
// (GCP: 1h default); a small skew is enough to absorb drift without
// meaningfully widening any replay window.
const DefaultWorkloadIdentityMaxClockSkew = 60 * time.Second

// claimsMapper turns verified JWT claims into a WorkloadIdentity. Each cloud
// preset supplies its own (GCP: email + project id; AWS/Azure: deferred —
// see package doc), keeping the shared validator core cloud-agnostic.
type claimsMapper func(claims map[string]any) (*WorkloadIdentity, error)

// WorkloadIdentityValidator is the SHARED verification core: JWKS fetch (via
// JWKSSource — the SAME interface the SPIFFE path uses) + VerifyCompactJWS +
// iss/aud/exp/nbf checks + a cloud-specific claims mapper. Parameterizing by
// issuer / JWKSSource / mapper is what lets GCP (and, once added, AWS/Azure)
// share one implementation instead of three hand-rolled verifiers.
type WorkloadIdentityValidator struct {
	name         string
	issuer       string
	source       JWKSSource
	mapper       claimsMapper
	maxClockSkew time.Duration
	allowedAlgs  map[string]struct{}
}

// WorkloadIdentityValidatorOption tunes a WorkloadIdentityValidator.
type WorkloadIdentityValidatorOption func(*WorkloadIdentityValidator)

// WithWorkloadIdentityMaxClockSkew overrides DefaultWorkloadIdentityMaxClockSkew.
func WithWorkloadIdentityMaxClockSkew(skew time.Duration) WorkloadIdentityValidatorOption {
	return func(v *WorkloadIdentityValidator) {
		if skew >= 0 {
			v.maxClockSkew = skew
		}
	}
}

// WithWorkloadIdentityAllowedAlgs restricts the asymmetric algs accepted
// from the cloud's JWKS. Empty/unset keeps the constructor's cloud-specific
// default. A symmetric alg is rejected by VerifyCompactJWS regardless.
func WithWorkloadIdentityAllowedAlgs(algs ...string) WorkloadIdentityValidatorOption {
	return func(v *WorkloadIdentityValidator) {
		if len(algs) == 0 {
			return
		}
		set := make(map[string]struct{}, len(algs))
		for _, a := range algs {
			set[a] = struct{}{}
		}
		v.allowedAlgs = set
	}
}

// NewWorkloadIdentityValidator builds the shared validator core for one
// cloud provider. name is the provider key (Name()); issuer is the token's
// required `iss`; source supplies the verification JWKS; mapper projects
// verified claims onto a WorkloadIdentity. All four are required. Cloud
// presets (NewGCPWorkloadIdentityValidator, ...) wrap this with their fixed
// issuer/mapper so callers never hand-assemble those.
func NewWorkloadIdentityValidator(name, issuer string, source JWKSSource, mapper claimsMapper, opts ...WorkloadIdentityValidatorOption) (*WorkloadIdentityValidator, error) {
	if name == "" {
		return nil, errors.New("workload_identity: provider name required")
	}
	if issuer == "" {
		return nil, errors.New("workload_identity: issuer required")
	}
	if source == nil {
		return nil, errors.New("workload_identity: jwks source required")
	}
	if mapper == nil {
		return nil, errors.New("workload_identity: claims mapper required")
	}
	v := &WorkloadIdentityValidator{
		name:         name,
		issuer:       issuer,
		source:       source,
		mapper:       mapper,
		maxClockSkew: DefaultWorkloadIdentityMaxClockSkew,
		allowedAlgs:  map[string]struct{}{jwsAlgRS256: {}},
	}
	for _, opt := range opts {
		opt(v)
	}
	return v, nil
}

// Name returns the provider key this validator was constructed with.
func (v *WorkloadIdentityValidator) Name() string { return v.name }

// workloadIdentityClaims is the standard-claim subset validated before the
// cloud-specific mapper ever runs. `aud` is string-or-array per RFC 7519
// §4.1.3.
type workloadIdentityClaims struct {
	Iss string         `json:"iss"`
	Aud stringOrString `json:"aud"`
	Exp int64          `json:"exp"`
	Nbf int64          `json:"nbf"`
	Iat int64          `json:"iat"`
}

// Validate verifies a compact cloud-issued token and returns the mapped
// WorkloadIdentity.
//
// Order (each step fails to the SAME opaque error, mirroring
// SPIFFEValidator.Validate):
//
//  1. signature: verify against the cloud JWKS via the shared
//     VerifyCompactJWS primitive — alg-allowlist (no alg=none, no HS*)
//     checked BEFORE the signature; key selected by kid.
//  2. temporal: exp/nbf with the configured skew.
//  3. issuer: `iss` MUST equal the cloud's fixed, well-known issuer.
//  4. aud binding: `aud` MUST contain expectedAudience — THE security crux
//     alongside the signature, exactly as for SPIFFE JWT-SVIDs: without it
//     a token minted for one relying party could be replayed against
//     another that trusts the same cloud provider.
//  5. claims mapping: the cloud-specific mapper extracts the identity;
//     an empty/unmapped Subject is treated as a failure, never a partial
//     success.
func (v *WorkloadIdentityValidator) Validate(ctx context.Context, compactJWS, expectedAudience string) (*WorkloadIdentity, error) {
	if expectedAudience == "" {
		// Misconfiguration, not an attacker input — still collapse to the
		// opaque error so the wire never reveals server state.
		return nil, ErrWorkloadIdentityInvalid
	}
	keys, err := v.source.GetJWKS(ctx)
	if err != nil || len(keys) == 0 {
		return nil, ErrWorkloadIdentityInvalid
	}

	payload, err := VerifyCompactJWS(compactJWS, keys, v.allowedAlgs)
	if err != nil {
		return nil, ErrWorkloadIdentityInvalid
	}

	var c workloadIdentityClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, ErrWorkloadIdentityInvalid
	}
	if !v.claimsInWindow(c, expectedAudience) {
		return nil, ErrWorkloadIdentityInvalid
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrWorkloadIdentityInvalid
	}
	id, err := v.mapper(claims)
	if err != nil || id == nil || id.Subject == "" {
		return nil, ErrWorkloadIdentityInvalid
	}
	id.Provider = CloudProvider(v.name)
	return id, nil
}

// claimsInWindow applies the non-cryptographic gates (steps 2-4 of the
// Validate doc): exp/nbf within the configured skew, `iss` equal to the
// cloud's fixed issuer, and `aud` containing expectedAudience. Split out of
// Validate for the per-function cyclomatic budget; the gate ORDER matches
// the doc exactly.
func (v *WorkloadIdentityValidator) claimsInWindow(c workloadIdentityClaims, expectedAudience string) bool {
	now := time.Now()
	skew := v.maxClockSkew
	if c.Exp == 0 || now.Add(-skew).After(time.Unix(c.Exp, 0)) {
		return false
	}
	if c.Nbf != 0 && now.Add(skew).Before(time.Unix(c.Nbf, 0)) {
		return false
	}
	if c.Iss != v.issuer {
		return false
	}
	return containsString(c.Aud, expectedAudience)
}

var _ WorkloadIdentityProvider = (*WorkloadIdentityValidator)(nil)

// stringOrString parses the RFC 7519 §4.1.3 `aud` claim (a string OR an
// array of strings). A local, non-SPIFFE-named copy of the same shape
// spiffeAudClaim handles — kept separate so this file has no dependency on
// spiffe_svid.go's naming.
type stringOrString []string

func (a *stringOrString) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = []string{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

func containsString(list stringOrString, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
