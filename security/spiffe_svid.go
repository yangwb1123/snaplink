package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/snaplink/sso/core"
)

// SPIFFE JWT-SVID acceptance (SPIFFE-ID + JWT-SVID specs).
//
// A SPIFFE JWT-SVID is an ordinary JWT whose `sub` claim is a
// `spiffe://<trust-domain>/<path>` URI, signed by the SPIRE server's JWT
// signing key (published in a JWKS "trust bundle"). Accepting one as a
// token-exchange subject_token lets a mesh workload that holds a
// SPIRE-issued SVID swap it for THIS SSO's access token — conceptually
// identical to upstream-IdP federation (validate an external JWT against
// the external party's JWKS), only via RFC 8693 token-exchange instead of
// /auth/login.
//
// Scope: JWT-SVID only. x509-SVID / mTLS-SVID and the SPIRE Workload API
// are OUT (they need extra deps / a sidecar). The trust bundle is supplied
// out of band by the operator (StaticJWKS from a file); an HTTP/etcd
// JWKSSource is a clean follow-up.

const (
	// spiffeScheme is the only URI scheme a SPIFFE ID may use.
	spiffeScheme = "spiffe"

	// SPIFFE workload-path segments SPIRE emits for Kubernetes
	// registration entries (spiffe://<td>/ns/<ns>/sa/<sa>). Parsed
	// best-effort into attributes; a non-k8s path still yields the
	// trust domain + raw path.
	spiffePathSegNS = "ns"
	spiffePathSegSA = "sa"

	// Attribute keys projected onto the issued Subject's claims so a
	// downstream service can authorize on the mesh identity.
	AttrSPIFFETrustDomain    = "spiffe_trust_domain"
	AttrSPIFFENamespace      = "spiffe_namespace"
	AttrSPIFFEServiceAccount = "spiffe_service_account"
	AttrSPIFFEID             = "spiffe_id"
)

// SPIFFEID is a parsed spiffe:// URI.
type SPIFFEID struct {
	// TrustDomain is the authority component, e.g. "example.org".
	TrustDomain string
	// Path is the workload path WITHOUT the leading slash, e.g.
	// "ns/prod/sa/payments". Empty for a bare trust-domain ID.
	Path string
	// Namespace + ServiceAccount are the parsed k8s registration
	// segments (ns/<ns>/sa/<sa>), empty when the path isn't that shape.
	Namespace      string
	ServiceAccount string
	// URI is the canonical spiffe:// string (lowercase scheme + host).
	URI string
}

// ParseSPIFFEURI parses a `spiffe://<trust-domain>/<path>` URI per the
// SPIFFE-ID spec. It rejects a non-spiffe scheme, an empty trust domain,
// any userinfo / port / query / fragment (a SPIFFE ID has none of those),
// and a path with empty segments. Best-effort extraction of the
// k8s-style ns/<ns>/sa/<sa> segments populates Namespace/ServiceAccount.
func ParseSPIFFEURI(uri string) (*SPIFFEID, error) {
	if uri == "" {
		return nil, errors.New("spiffe: empty id")
	}
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("spiffe: parse: %w", err)
	}
	// The SPIFFE-ID spec mandates a lowercase scheme; url.Parse already
	// lowercases the scheme, but compare explicitly so a future change
	// can't silently weaken this.
	if u.Scheme != spiffeScheme {
		return nil, fmt.Errorf("spiffe: scheme %q is not spiffe", u.Scheme)
	}
	if u.User != nil {
		return nil, errors.New("spiffe: id must not contain userinfo")
	}
	if u.Port() != "" {
		return nil, errors.New("spiffe: id must not contain a port")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("spiffe: id must not contain query or fragment")
	}
	td := u.Hostname()
	if td == "" {
		return nil, errors.New("spiffe: empty trust domain")
	}
	// A SPIFFE trust domain is a DNS-name-like authority; it must be
	// lowercase and contain no path-confusing characters. url.Hostname
	// already strips brackets/port; reject an uppercase host so two IDs
	// differing only in case can't be confused.
	if td != strings.ToLower(td) {
		return nil, errors.New("spiffe: trust domain must be lowercase")
	}

	path := strings.TrimPrefix(u.Path, "/")
	if path != "" {
		for _, seg := range strings.Split(path, "/") {
			if seg == "" {
				return nil, errors.New("spiffe: path has an empty segment")
			}
		}
	}

	id := &SPIFFEID{
		TrustDomain: td,
		Path:        path,
		URI:         spiffeScheme + "://" + td + u.Path,
	}
	id.Namespace, id.ServiceAccount = parseK8sWorkloadPath(path)
	return id, nil
}

// parseK8sWorkloadPath extracts (namespace, service-account) from a
// SPIRE Kubernetes workload path of the form ns/<ns>/sa/<sa>. Returns
// empties when the path isn't that exact shape — a non-k8s SVID is still
// accepted; it just carries no ns/sa attributes.
func parseK8sWorkloadPath(path string) (ns, sa string) {
	segs := strings.Split(path, "/")
	if len(segs) == 4 && segs[0] == spiffePathSegNS && segs[2] == spiffePathSegSA {
		return segs[1], segs[3]
	}
	return "", ""
}

// Attributes projects the SPIFFE identity onto string claims for the
// issued Subject. Always includes the trust domain + full id; ns/sa only
// when the path matched the k8s shape.
func (s *SPIFFEID) Attributes() map[string]string {
	attrs := map[string]string{
		AttrSPIFFETrustDomain: s.TrustDomain,
		AttrSPIFFEID:          s.URI,
	}
	if s.Namespace != "" {
		attrs[AttrSPIFFENamespace] = s.Namespace
	}
	if s.ServiceAccount != "" {
		attrs[AttrSPIFFEServiceAccount] = s.ServiceAccount
	}
	return attrs
}

// JWKSSource supplies the SPIRE trust-bundle JWKS used to verify SVID
// signatures. StaticJWKS is the in-scope (operator file) implementation;
// an HTTP/etcd-backed source can be added later behind the same seam.
type JWKSSource interface {
	GetJWKS(ctx context.Context) ([]core.JWK, error)
}

// StaticJWKS is a fixed trust bundle, typically loaded from an
// operator-supplied JWKS file at boot. It never changes for the process
// lifetime; rotating the SPIRE JWT key means re-deploying the file (or
// switching to a refreshing source).
type StaticJWKS struct {
	keys []core.JWK
}

// NewStaticJWKS copies the supplied keys into an immutable source.
func NewStaticJWKS(keys []core.JWK) *StaticJWKS {
	return &StaticJWKS{keys: append([]core.JWK(nil), keys...)}
}

// ParseStaticJWKS builds a StaticJWKS from a raw `{"keys":[...]}` JWKS
// document (the on-disk SPIRE trust-bundle format).
func ParseStaticJWKS(doc []byte) (*StaticJWKS, error) {
	var parsed struct {
		Keys []core.JWK `json:"keys"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		return nil, fmt.Errorf("spiffe: parse trust bundle: %w", err)
	}
	if len(parsed.Keys) == 0 {
		return nil, errors.New("spiffe: trust bundle has no keys")
	}
	return NewStaticJWKS(parsed.Keys), nil
}

// GetJWKS returns a copy of the static key set.
func (s *StaticJWKS) GetJWKS(_ context.Context) ([]core.JWK, error) {
	return append([]core.JWK(nil), s.keys...), nil
}

var _ JWKSSource = (*StaticJWKS)(nil)

// DefaultSPIFFEMaxClockSkew widens exp/nbf validation. JWT-SVIDs are
// short-lived (SPIRE default ~5min); a small skew tolerates clock drift
// between the SPIRE server and this SSO without meaningfully extending the
// replay window.
const DefaultSPIFFEMaxClockSkew = 60 * time.Second

// ErrSPIFFESVIDInvalid is the SINGLE opaque error every SVID validation
// failure returns — bad signature, alg=none, wrong aud, wrong trust
// domain, expired, malformed sub, etc. The token-exchange caller maps it
// to one `400 invalid_grant`, so the wire NEVER distinguishes the cause
// (oracle-leak hardening, AGENTS.md §2). The operator-facing detail
// surfaces only via the internal audit event, never on the wire.
var ErrSPIFFESVIDInvalid = errors.New("spiffe: svid invalid")

// SPIFFEValidator validates an inbound JWT-SVID against an
// operator-configured SPIRE trust bundle and trust domain.
type SPIFFEValidator struct {
	source       JWKSSource
	trustDomain  string
	maxClockSkew time.Duration
	// allowedAlgs is the asymmetric-alg allowlist passed to the shared
	// VerifyCompactJWS primitive. SPIRE signs JWT-SVIDs with ES256 (its
	// default), RS256, or EdDSA; all three are admitted, none symmetric.
	allowedAlgs map[string]struct{}
}

// SPIFFEValidatorOption tunes the validator.
type SPIFFEValidatorOption func(*SPIFFEValidator)

// WithSPIFFEMaxClockSkew overrides DefaultSPIFFEMaxClockSkew.
func WithSPIFFEMaxClockSkew(skew time.Duration) SPIFFEValidatorOption {
	return func(v *SPIFFEValidator) {
		if skew >= 0 {
			v.maxClockSkew = skew
		}
	}
}

// WithSPIFFEAllowedAlgs restricts the asymmetric algs accepted from the
// trust bundle. Empty / unset keeps the default (ES256, RS256, PS256,
// EdDSA). A symmetric alg in the set is rejected by VerifyCompactJWS.
func WithSPIFFEAllowedAlgs(algs ...string) SPIFFEValidatorOption {
	return func(v *SPIFFEValidator) {
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

// NewSPIFFEValidator builds the validator. trustDomain is the ONLY trust
// domain whose SVIDs are accepted; source supplies the verification
// JWKS. Both are required.
func NewSPIFFEValidator(trustDomain string, source JWKSSource, opts ...SPIFFEValidatorOption) (*SPIFFEValidator, error) {
	if trustDomain == "" {
		return nil, errors.New("spiffe: trust domain required")
	}
	if source == nil {
		return nil, errors.New("spiffe: jwks source required")
	}
	v := &SPIFFEValidator{
		source:       source,
		trustDomain:  strings.ToLower(trustDomain),
		maxClockSkew: DefaultSPIFFEMaxClockSkew,
		allowedAlgs: map[string]struct{}{
			jwsAlgES256: {},
			jwsAlgRS256: {},
			jwsAlgPS256: {},
			jwsAlgEdDSA: {},
		},
	}
	for _, opt := range opts {
		opt(v)
	}
	return v, nil
}

// TrustDomain exposes the configured trust domain (audit/logging only).
func (v *SPIFFEValidator) TrustDomain() string { return v.trustDomain }

// svidClaims is the JWT-SVID claim subset we validate. `aud` is a
// string-or-array per RFC 7519 §4.1.3.
type svidClaims struct {
	Sub string         `json:"sub"`
	Aud spiffeAudClaim `json:"aud"`
	Exp int64          `json:"exp"`
	Nbf int64          `json:"nbf"`
	Iat int64          `json:"iat"`
}

// Validate verifies a compact JWT-SVID and returns the parsed SPIFFE ID.
// expectedAudience is THIS SSO's identifier (the configured SVID
// audience); the SVID's `aud` MUST contain it.
//
// Order (each step fails to the SAME opaque error):
//
//	a. signature: verify against the trust-bundle JWKS via the shared
//	   VerifyCompactJWS primitive — alg-allowlist (no alg=none, no HS*)
//	   checked BEFORE the signature; key selected by kid.
//	b. temporal: exp/nbf with the configured skew.
//	c. aud binding: `aud` MUST contain expectedAudience. THIS IS THE
//	   SECURITY CRUX alongside the signature — a lax aud would let an
//	   SVID minted for service-B be replayed to mint a token for
//	   service-A (the classic audience-confusion / token-replay attack).
//	d. trust domain: `sub` parses as spiffe:// AND its trust domain
//	   equals the operator-configured one — so an SVID from a foreign
//	   (attacker-controlled) trust domain whose key somehow appears in
//	   the bundle still can't impersonate a local workload.
//
// ALL failures return ErrSPIFFESVIDInvalid; the caller maps that to one
// 400 invalid_grant (no oracle).
func (v *SPIFFEValidator) Validate(ctx context.Context, compactJWS, expectedAudience string) (*SPIFFEID, error) {
	if expectedAudience == "" {
		// Misconfiguration, not an attacker input — but still collapse to
		// the opaque error so the wire never reveals server state.
		return nil, ErrSPIFFESVIDInvalid
	}
	keys, err := v.source.GetJWKS(ctx)
	if err != nil || len(keys) == 0 {
		return nil, ErrSPIFFESVIDInvalid
	}

	// (a) signature + alg-allowlist (no alg=none / no symmetric).
	payload, err := VerifyCompactJWS(compactJWS, keys, v.allowedAlgs)
	if err != nil {
		return nil, ErrSPIFFESVIDInvalid
	}

	var c svidClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, ErrSPIFFESVIDInvalid
	}

	// (b) temporal validation. A JWT-SVID MUST carry exp.
	now := time.Now()
	skew := v.maxClockSkew
	if c.Exp == 0 || now.Add(-skew).After(time.Unix(c.Exp, 0)) {
		return nil, ErrSPIFFESVIDInvalid
	}
	if c.Nbf != 0 && now.Add(skew).Before(time.Unix(c.Nbf, 0)) {
		return nil, ErrSPIFFESVIDInvalid
	}

	// (c) STRICT aud binding — the security crux: refuse an SVID not
	// explicitly minted for this SSO.
	if !spiffeAudContains(c.Aud, expectedAudience) {
		return nil, ErrSPIFFESVIDInvalid
	}

	// (d) sub must be a spiffe:// URI in the configured trust domain.
	id, err := ParseSPIFFEURI(c.Sub)
	if err != nil {
		return nil, ErrSPIFFESVIDInvalid
	}
	if id.TrustDomain != v.trustDomain {
		return nil, ErrSPIFFESVIDInvalid
	}

	return id, nil
}

// spiffeAudClaim parses the RFC 7519 §4.1.3 `aud` claim (a string OR an
// array of strings). Local to security/ so the SVID path doesn't depend
// on the root package's audClaim type.
type spiffeAudClaim []string

func (a *spiffeAudClaim) UnmarshalJSON(data []byte) error {
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

func spiffeAudContains(aud spiffeAudClaim, want string) bool {
	for _, a := range aud {
		if a == want {
			return true
		}
	}
	return false
}
