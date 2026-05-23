package sso

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/snaplink/sso/security"
)

// RFC 8705 §3 — Mutual-TLS Client Certificate-Bound Access Tokens.
//
// The companion proof-of-possession mechanism to DPoP. Where DPoP
// binds to a JWK the client signs with, mTLS binds to the TLS
// client certificate the client presents during the connection
// handshake. Tokens minted while a client cert was on the wire
// carry an `x5t#S256` value in their `cnf` claim — the SHA-256
// thumbprint of the cert DER. Resource servers reject the token
// unless the SAME cert is on the wire when it's presented.
//
// Scope of THIS implementation (issuance side):
//   - Per-request cert extraction (default: direct TLS handshake
//     via r.TLS.PeerCertificates[0]).
//   - Pluggable ClientCertExtractor so reverse-proxy-terminated TLS
//     (envoy / nginx forwarding X-Forwarded-Client-Cert) works.
//   - SHA-256 thumbprint computation + stamping into the issued
//     access token's `cnf.x5t#S256` claim.
//   - Discovery: `tls_client_certificate_bound_access_tokens: true`
//     when an extractor is wired.
//
// Resource-side verification (a downstream service confirming the
// token's cnf.x5t#S256 matches the cert on the inbound connection)
// is left to the resource — same architectural separation as the
// DPoP commit.

// ClientCertExtractor pulls the client's TLS certificate out of an
// incoming request. The default implementation reads
// r.TLS.PeerCertificates[0] (direct TLS termination on the AS).
// Reverse-proxy-terminated deployments inject a custom extractor
// that parses the proxy's "X-Forwarded-Client-Cert" header
// (envoy / nginx convention).
//
// Returns nil + ok=false when the request had no client cert — the
// /token handler then mints an unbound bearer token (legacy path).
type ClientCertExtractor interface {
	ExtractClientCert(r *http.Request) (cert *x509.Certificate, ok bool)
}

// ClientCertExtractorFunc adapts a function to the
// [ClientCertExtractor] interface.
type ClientCertExtractorFunc func(r *http.Request) (*x509.Certificate, bool)

func (f ClientCertExtractorFunc) ExtractClientCert(r *http.Request) (*x509.Certificate, bool) {
	return f(r)
}

// DefaultTLSPeerCertExtractor reads r.TLS.PeerCertificates[0] —
// the conventional path for direct TLS-terminated AS deployments
// where the Go server itself handles the handshake.
var DefaultTLSPeerCertExtractor ClientCertExtractor = ClientCertExtractorFunc(func(r *http.Request) (*x509.Certificate, bool) {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, false
	}
	return r.TLS.PeerCertificates[0], true
})

// certificateThumbprintS256 computes RFC 8705 §3.1's
// `x5t#S256` — base64url-no-pad encoding of SHA-256(cert.Raw).
// cert MUST NOT be nil (callers gate on extractor's ok=false).
func certificateThumbprintS256(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// verifyMTLSBearer enforces the resource-side half of RFC 8705 §3.
// Mirror of verifyDPoPBearer: when the access token carries
// cnf.x5t#S256, the inbound request MUST be on a TLS connection
// whose client cert has the matching SHA-256 thumbprint.
//
// Returns nil when:
//   - the token isn't mTLS-bound (no cnf.x5t#S256), OR
//   - the inbound cert thumbprint equals the bound value.
//
// Returns an error mapped to invalid_token (same wire shape as
// "invalid bearer") on mismatch — oracle-resistance: probes can't
// distinguish unbound from bound-but-mismatched tokens.
//
// Skips the check when no ClientCertExtractor is wired: an
// operator that minted mTLS-bound tokens via one deployment and
// then disabled the extractor would otherwise lock every bound
// token out. Operators changing mTLS posture should revoke
// existing bound tokens explicitly.
func (s *Server) verifyMTLSBearer(ctx HandlerContext, claims *TokenClaims) error {
	if claims == nil || claims.ConfirmationX5TS256 == "" {
		return nil
	}
	if s.clientCertExtractor == nil {
		// No extractor wired — see method doc for the
		// trade-off. The cert is still required on the wire
		// for any HTTP framework that auto-populates r.TLS,
		// just not validated.
		return nil
	}
	cert, ok := s.clientCertExtractor.ExtractClientCert(ctx.Request())
	if !ok || cert == nil {
		return errCertRequired
	}
	got := certificateThumbprintS256(cert)
	if got != claims.ConfirmationX5TS256 {
		return errCertThumbprintMismatch
	}
	return nil
}

// Sentinel errors so logging can distinguish the failure modes
// even though the wire collapses them to invalid_token.
var (
	errCertRequired           = httpError("mtls: token bound but no client cert presented")
	errCertThumbprintMismatch = httpError("mtls: cert thumbprint does not match cnf.x5t#S256")
)

// httpError is a stdlib-free sentinel-error type kept local to
// this file (avoids importing errors just for two constants).
type httpError string

func (e httpError) Error() string { return string(e) }

// SubjectTypePublic and SubjectTypePairwise are the two values OIDC
// Core §8 defines for a Client's subject_type metadata. Public is
// the default — the `sub` claim is the user's local identifier and
// every client receives the same `sub` for the same end user.
// Pairwise produces a per-sector opaque `sub` so colluding clients
// can't correlate users across services by comparing `sub` values.
const (
	SubjectTypePublic   = "public"
	SubjectTypePairwise = "pairwise"
)

// PairwiseSubjectStore persists the mapping from a pairwise `sub`
// value (the opaque per-sector identifier the RP sees) back to the
// local subject identifier the AS knows the user by. Required for
// resource-side handlers (/userinfo, /token/revoke-all, /end_session)
// that need to load the local user record from a bearer token whose
// `sub` claim is pairwise.
//
// MapPairwise is called at issuance — idempotent upsert; calling
// twice for the same pairwise → local pair MUST succeed without
// error. LocalSubject is called at resource time; ErrPairwiseUnknown
// (or any non-nil error) means the AS cannot resolve the inbound sub
// to a local user and the handler MUST reject the request with the
// same wire shape it uses for unknown tokens (oracle resistance).
type PairwiseSubjectStore interface {
	MapPairwise(ctx context.Context, pairwiseSub, localSub string) error
	LocalSubject(ctx context.Context, pairwiseSub string) (string, error)
}

// ErrPairwiseUnknown is the sentinel a PairwiseSubjectStore returns
// when no mapping exists for the given pairwise sub. Wrapped by
// errors.Is so layered backends (cache + persistent) can surface it
// from any layer without losing the typed comparison.
var ErrPairwiseUnknown = errors.New("pairwise: subject not mapped")

// MemoryPairwiseSubjectStore is an in-process PairwiseSubjectStore.
// Suitable for single-replica deployments + tests. Multi-replica
// deployments MUST plug a shared backend — a user who gets issued a
// pairwise sub on replica A and presents it at /userinfo on
// replica B would otherwise see ErrPairwiseUnknown and fail
// authentication. Multi-second propagation delays via the YAML
// snapshot subsystem partially address this for setup-time mappings
// but don't solve the per-issuance race.
type MemoryPairwiseSubjectStore struct {
	mu      sync.RWMutex
	entries map[string]string
}

// NewMemoryPairwiseSubjectStore returns a ready-to-use instance with
// no eviction. The map grows linearly in active-pairwise count;
// production deployments serving large user bases under pairwise
// SHOULD plug a TTL-capable backend or a shared persistent store.
func NewMemoryPairwiseSubjectStore() *MemoryPairwiseSubjectStore {
	return &MemoryPairwiseSubjectStore{entries: make(map[string]string)}
}

// MapPairwise implements PairwiseSubjectStore.
func (m *MemoryPairwiseSubjectStore) MapPairwise(_ context.Context, pairwiseSub, localSub string) error {
	if pairwiseSub == "" || localSub == "" {
		return errors.New("pairwise: empty sub")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[pairwiseSub] = localSub
	return nil
}

// LocalSubject implements PairwiseSubjectStore.
func (m *MemoryPairwiseSubjectStore) LocalSubject(_ context.Context, pairwiseSub string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	local, ok := m.entries[pairwiseSub]
	if !ok {
		return "", ErrPairwiseUnknown
	}
	return local, nil
}

// DefaultPairwiseSalt is used when an operator wires
// [WithPairwiseSubjectStore] without [WithPairwiseSalt]. Stable across
// restarts so previously-issued pairwise subs continue to map to the
// same local subject in the wired store. Operators SHOULD set their
// own via [WithPairwiseSalt] — the default is fine for tests but
// publicly known.
const DefaultPairwiseSalt = "snaplink-default-pairwise-salt"

// sectorIdentifier returns the OIDC Core §8.1.1 sector identifier
// for client. Precedence:
//
//  1. If client.SectorIdentifierURI is set, the URL's host.
//  2. Otherwise, the host of the first redirect_uri.
//  3. Otherwise, the client.ID (defensive fallback so two clients
//     never accidentally share a sector via empty config).
//
// Sectors are about *grouping* clients (so colluding clients in one
// sector see the same pairwise sub for a user); not setting either
// field means the client stands alone in its sector.
func sectorIdentifier(client *Client) string {
	if client == nil {
		return ""
	}
	if client.SectorIdentifierURI != "" {
		if u, err := url.Parse(client.SectorIdentifierURI); err == nil && u.Host != "" {
			return u.Host
		}
	}
	for _, ru := range client.RedirectURIs {
		if u, err := url.Parse(ru); err == nil && u.Host != "" {
			return u.Host
		}
	}
	return client.ID
}

// computePairwiseSubject hashes sector + local + salt into a stable
// opaque identifier. Deterministic — same inputs always yield the
// same output, so the store mapping is idempotent across re-
// issuances for the same user-client pair. Base64-URL no-pad
// encoding keeps the value `sub`-claim safe (no equals signs, no
// JSON-escape requirements).
func computePairwiseSubject(sector, localSub, salt string) string {
	if sector == "" || localSub == "" {
		return ""
	}
	if salt == "" {
		salt = DefaultPairwiseSalt
	}
	h := sha256.New()
	h.Write([]byte(sector))
	h.Write([]byte{0}) // separator so "a"+"bc" and "ab"+"c" don't collide
	h.Write([]byte(localSub))
	h.Write([]byte{0})
	h.Write([]byte(salt))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// applyPairwiseSubject computes the pairwise sub for (client, localSub)
// and persists the reverse mapping in the wired store. Returns the
// pairwise sub when the client opted in AND the store is wired;
// returns localSub unchanged otherwise. Called at every issuance
// path that mints a token whose sub claim the RP will see.
//
// Fail-open: when the store's MapPairwise fails, the function still
// returns the computed pairwise sub but logs the error via the
// supplied error sink. The token MINTS with the pairwise sub —
// resource-side lookups will fail (`invalid_token`) until the next
// successful map. The alternative (fail-closed) would block
// issuance, which is worse than a token whose userinfo path
// temporarily fails.
func (s *Server) applyPairwiseSubject(ctx context.Context, client *Client, localSub string) string {
	if client == nil || s.pairwiseStore == nil {
		return localSub
	}
	if !strings.EqualFold(client.SubjectType, SubjectTypePairwise) {
		return localSub
	}
	sector := sectorIdentifier(client)
	pairwise := computePairwiseSubject(sector, localSub, s.pairwiseSalt)
	if pairwise == "" {
		return localSub
	}
	if err := s.pairwiseStore.MapPairwise(ctx, pairwise, localSub); err != nil {
		s.logger.Error("pairwise: map failed (continuing — resource lookups may fail)", "error", err, "client_id", client.ID)
	}
	return pairwise
}

// resolveLocalSubject reverses a pairwise sub on inbound resource
// requests. When pairwise is wired AND the sub looks like a pairwise
// value (not present in UserProvider as a local id), the store is
// consulted; ErrPairwiseUnknown surfaces to the caller which maps it
// to the standard invalid_token response.
//
// When pairwise is NOT wired or the sub is a known local id, the
// input is returned unchanged — pairwise opt-in is per-client, so
// non-pairwise clients keep their public sub semantics.
//
// The cheap-path optimization (looking up local first) means
// non-pairwise deployments pay nothing beyond what they already paid
// before this feature existed.
func (s *Server) resolveLocalSubject(ctx context.Context, sub string) (string, error) {
	if sub == "" {
		return sub, nil
	}
	if s.pairwiseStore == nil {
		return sub, nil
	}
	local, err := s.pairwiseStore.LocalSubject(ctx, sub)
	if err == nil {
		return local, nil
	}
	if errors.Is(err, ErrPairwiseUnknown) {
		// Not a pairwise sub — caller's claim is already local.
		return sub, nil
	}
	return sub, err
}

// WithPairwiseSubjectStore enables OIDC Core §8 pairwise subject
// identifiers. Per-client subject_type metadata gates use: clients
// with SubjectType="pairwise" get an opaque per-sector sub in their
// tokens; "public" (default) clients continue to receive the local
// subject identifier. Resource-side handlers (/userinfo, etc.) use
// the store's reverse map to recover the local sub for lookups.
//
// Discovery doc advertises both "public" and "pairwise" in
// subject_types_supported when this option is wired.
//
// Single-replica memory backend is provided
// (NewMemoryPairwiseSubjectStore); multi-replica deployments need a
// shared backend so pairwise subs issued on replica A resolve on
// replica B.
func WithPairwiseSubjectStore(store PairwiseSubjectStore) Option {
	return func(s *Server) { s.pairwiseStore = store }
}

// WithPairwiseSalt overrides the deterministic salt mixed into
// pairwise sub computation. Operators SHOULD set this to a
// deployment-stable secret distributed out-of-band — the default is
// publicly known and lets attackers pre-compute pairwise sub →
// local sub mappings if they ever see a local sub in some other
// channel. Empty value falls back to DefaultPairwiseSalt.
func WithPairwiseSalt(salt string) Option {
	return func(s *Server) { s.pairwiseSalt = salt }
}

// RFC 7521 + RFC 7523 — JWT Bearer client authentication.
//
// Lets confidential clients prove their identity to /token (and
// related endpoints) by signing a JWT instead of presenting a
// client_secret. The standard `private_key_jwt` mechanism in OIDC
// Core §9. Useful when:
//
//   - Client_secret distribution is a compliance pain (shared secret
//     storage / rotation across CI / multi-region deployments).
//   - The deployment already maintains a JWKS for the client (this
//     server's JAR support uses the same Client.JWKS field).
//   - High-security environments mandate asymmetric-key authentication.

// ClientAssertionTypeJWTBearer is the RFC 7521 §4.2 URN for
// JWT-shaped client assertions. The /token endpoint only accepts
// JWT bearer (the spec carves out a SAML 2.0 variant too;
// `urn:ietf:params:oauth:client-assertion-type:saml2-bearer` is
// not supported here today).
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// DefaultClientAssertionMaxLifetime caps how far into the future a
// client_assertion's `exp` claim can sit. RFC 7523 §3 requires the
// AS to reject overly-long-lived assertions; 5 minutes matches the
// common convention and the request-object lifetime ceilings.
const DefaultClientAssertionMaxLifetime = 5 * time.Minute

// verifyJWTClientAssertion validates an RFC 7523 §3 client
// assertion. Returns the asserted client_id on success — callers
// MUST use this return value (NOT the wire `client_id` form param)
// for subsequent lookups, since the JWT's `sub` claim is the
// authoritative identity binding.
//
// Validation gates per RFC 7523 §3:
//   - JWT MUST decode as 3 base64url segments
//   - Header `alg` MUST be in the EdDSA allowlist (matches JAR)
//   - Header `typ` MAY be present; if present MUST be "JWT" or
//     "client-authentication+jwt"
//   - Header `kid` selects the verification key from Client.JWKS
//   - Signature MUST verify against the matched public key
//   - iss + sub MUST be equal AND non-empty AND equal client_id
//     (when the request-form client_id was supplied — when not, sub
//     drives the lookup)
//   - aud MUST include the AS issuer (acceptable values: the
//     resolveIssuer string the server emits in discovery)
//   - exp MUST be in the future AND within DefaultClientAssertionMaxLifetime
//   - jti MUST be present when security.JTIReplayStore is wired; replay
//     rejects the duplicate
//
// Errors collapse to one wire shape on the caller side
// (invalid_client) so attacker probing can't distinguish "wrong
// signature" from "missing client" from "wrong audience".
func verifyJWTClientAssertion(
	ctx context.Context,
	assertion string,
	formClientID string,
	clientStore ClientStore,
	asIssuer string,
	replay security.JTIReplayStore,
) (string, error) {
	if clientStore == nil {
		return "", errors.New("jwt_client_assertion: client store required")
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return "", errors.New("jwt_client_assertion: malformed JWT")
	}
	hraw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("jwt_client_assertion: header decode: %w", err)
	}
	var h struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hraw, &h); err != nil {
		return "", fmt.Errorf("jwt_client_assertion: header parse: %w", err)
	}
	if h.Alg != "EdDSA" {
		return "", fmt.Errorf("jwt_client_assertion: alg %q not supported", h.Alg)
	}
	switch h.Typ {
	case "", "JWT", "client-authentication+jwt":
	default:
		return "", fmt.Errorf("jwt_client_assertion: typ %q not supported", h.Typ)
	}

	praw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("jwt_client_assertion: payload decode: %w", err)
	}
	var p struct {
		Iss string   `json:"iss"`
		Sub string   `json:"sub"`
		Aud audClaim `json:"aud"`
		Exp int64    `json:"exp"`
		Nbf int64    `json:"nbf"`
		Iat int64    `json:"iat"`
		JTI string   `json:"jti"`
	}
	if err := json.Unmarshal(praw, &p); err != nil {
		return "", fmt.Errorf("jwt_client_assertion: payload parse: %w", err)
	}
	if p.Sub == "" || p.Sub != p.Iss {
		return "", errors.New("jwt_client_assertion: iss/sub must be equal and non-empty")
	}
	if formClientID != "" && formClientID != p.Sub {
		return "", errors.New("jwt_client_assertion: form client_id does not match sub")
	}
	now := time.Now()
	if p.Exp == 0 || now.After(time.Unix(p.Exp, 0)) {
		return "", errors.New("jwt_client_assertion: expired or missing exp")
	}
	if time.Unix(p.Exp, 0).After(now.Add(DefaultClientAssertionMaxLifetime)) {
		return "", fmt.Errorf("jwt_client_assertion: exp too far in future (max %s)", DefaultClientAssertionMaxLifetime)
	}
	if p.Nbf != 0 && now.Before(time.Unix(p.Nbf, 0)) {
		return "", errors.New("jwt_client_assertion: nbf in future")
	}
	if asIssuer != "" && !slices.Contains([]string(p.Aud), asIssuer) {
		return "", fmt.Errorf("jwt_client_assertion: aud does not include %q", asIssuer)
	}

	client, err := clientStore.Get(ctx, p.Sub)
	if err != nil || client == nil {
		return "", errors.New("jwt_client_assertion: client not found")
	}
	if len(client.JWKS) == 0 {
		return "", errors.New("jwt_client_assertion: client has no registered JWKS")
	}
	pub, _ := jwkLookupEd25519(client.JWKS, h.Kid)
	if pub == nil {
		return "", errors.New("jwt_client_assertion: no JWK matches kid")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("jwt_client_assertion: signature decode: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return "", errors.New("jwt_client_assertion: signature invalid")
	}

	// Replay defense — when wired and the JWT carries a jti, refuse
	// any second sighting within its exp window. Same store + same
	// semantics JAR replay protection uses; one knob covers both.
	if replay != nil && p.JTI != "" {
		first, err := replay.MarkSeen(ctx, p.JTI, time.Unix(p.Exp, 0))
		if err == nil && !first {
			return "", errors.New("jwt_client_assertion: jti replay detected")
		}
	}

	return p.Sub, nil
}
