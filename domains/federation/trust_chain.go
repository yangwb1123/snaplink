package federation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
)

// OpenID Federation 1.0 §9 (Trust Chain) + §10 (Metadata Policy) — THE TRUST
// BOUNDARY of federation. ResolveTrustChain decides whether a remote entity
// (an RP) is a trusted member of the federation by resolving and
// CRYPTOGRAPHICALLY VALIDATING a chain of signed Entity Statements from the
// leaf up to an operator-CONFIGURED trust anchor.
//
// A Trust Chain is the ordered array (§9):
//
//	[ leaf Entity Configuration,                 // self-signed, iss==sub==leaf
//	  Subordinate Statement (superior1 about leaf),
//	  Subordinate Statement (superior2 about superior1),
//	  ...,
//	  Trust Anchor Entity Configuration ]         // self-signed, iss==sub==TA
//
// KEY PROVENANCE — the crux, and where a bug forges trust. Verification keys
// flow DOWN from the configured anchor, NOT from each statement's self-
// assertion:
//
//   - The Trust Anchor's Entity Configuration is verified against the
//     CONFIGURED anchor keys (TrustAnchor.Keys) — the root of trust. NEVER the
//     keys the fetched anchor statement carries about itself (a forged anchor
//     config carries forged keys).
//   - Each Subordinate Statement is verified against the keys published by its
//     ISSUER (the superior), which were established one link higher — the
//     superior's keys come from the Subordinate Statement ABOUT the superior
//     (or, for the topmost subordinate statement, from the trust anchor's
//     now-verified configuration).
//   - The leaf's Entity Configuration is verified against the keys the
//     IMMEDIATE SUPERIOR published FOR the leaf (the first Subordinate
//     Statement's jwks), NOT the leaf's self-asserted keys.
//
// FAIL-CLOSED: any fetch error, signature failure, expired/not-yet-valid
// statement, iss/sub mismatch, typ mismatch, a chain that never reaches a
// configured anchor, an over-long path, a cycle, a §6.2 constraint violation
// (max_path_length / naming_constraints / allowed_entity_types), or a
// metadata-policy violation/merge-conflict REJECTS the whole resolution with
// one coarse error (ErrTrustChainInvalid). Detail goes to the log seam, never
// the caller — no partial trust, no untrusted-anchor fallback.

// ErrTrustChainInvalid is the single coarse error every trust-chain resolution
// failure collapses into (a malformed/forged/expired/unanchored/policy-
// violating chain). It is oracle-reasonable: the caller (slice 3, registration)
// maps it to one rejection; the specific cause is logged, not returned, so a
// prober cannot distinguish "no such entity" from "bad signature" from "wrong
// anchor". This is a Go error sentinel, NOT a wire error code (slice 2 mounts
// no endpoint).
var ErrTrustChainInvalid = errors.New("federation: trust chain invalid")

// ErrFederationResolverDisabled is returned when ResolveTrustChain is called
// on a resolver with no configured trust anchors. With no root of trust there
// is nothing to validate against, so the resolver is inert (the default-off
// posture) rather than silently trusting an unanchored chain.
var ErrFederationResolverDisabled = errors.New("federation: resolver disabled (no trust anchors configured)")

// chainLink is one fetched, parsed (NOT yet trusted) statement in the chain
// under assembly. compact is the raw signed JWS (re-verified in the validate
// phase); claims is the parsed payload used to NAVIGATE the walk (read
// authority_hints / fetch endpoint / jwks). Parsing to navigate is safe; the
// trust decision is the signature re-verification against established keys.
type chainLink struct {
	compact string
	claims  EntityStatementClaims
}

// TrustChain is a VALIDATED trust chain: the leaf is a trusted federation
// member rooted in the configured anchor. It carries the leaf entity ID, the
// matched anchor's entity ID, the ordered statements (leaf-first), and the
// policy-APPLIED resolved RP metadata (the §10 metadata_policy merged
// top-down and applied to the leaf's openid_relying_party). Slice 3 consumes
// ResolvedRPMetadata + LeafEntityID to stand in for out-of-band client
// registration.
type TrustChain struct {
	// LeafEntityID is the resolved leaf's Entity Identifier (iss==sub of the
	// leaf Entity Configuration).
	LeafEntityID string
	// AnchorEntityID is the configured trust anchor the chain terminated at.
	AnchorEntityID string
	// Statements are the chain's signed Entity Statements, leaf-first
	// (Statements[0] is the leaf Entity Configuration; the last is the anchor
	// Entity Configuration). Verified.
	Statements []string
	// ResolvedRPMetadata is the leaf's openid_relying_party metadata AFTER the
	// merged metadata policy is applied (defaults/add filled, value pinned,
	// constraints enforced). nil if the leaf advertised no RP metadata and the
	// policy added none.
	ResolvedRPMetadata map[string]any
	// LeafTrustMarks is the §7 trust_marks array carried in the (now signature-
	// VALIDATED) leaf Entity Configuration. Surfaced here so slice-4b's
	// trust-mark requirement gate (trust_marks.go) can check it WITHOUT
	// re-parsing the leaf compact: the leaf's signature was already verified in
	// validate(), so reading its trust_marks off the parsed claims is sound (the
	// wrapper entries are still untrusted — each inner Trust Mark JWT is itself
	// cryptographically validated). nil when the leaf carries no trust_marks.
	LeafTrustMarks []TrustMarkEntry
	// AnchorTrustMarkIssuers is the §3.1.2 trust_mark_issuers claim carried in
	// the matched TRUST ANCHOR's (now signature-VALIDATED, against the CONFIGURED
	// root-of-trust keys) Entity Configuration: trust_mark_type URI → authorized
	// issuer Entity IDs. It is the AUTHORIZATION ROOT for the federation-resolved
	// trust-mark issuer path (slice 4c, trust_marks.go): when an issuer is itself
	// resolved as a federation entity, this map (read off the ANCHOR — the root
	// of trust the chain validated against, per spec IGNORED on any non-anchor)
	// decides whether that issuer is authorized for a given trust-mark type. Read
	// off the parsed anchor claims here so the gate need not re-parse the anchor
	// compact (the anchor config's signature was verified in validate()). nil
	// when the anchor publishes no trust_mark_issuers (then no resolved issuer is
	// authorized — fail-closed).
	AnchorTrustMarkIssuers map[string][]string
	// LeafKeys is the resolved leaf entity's OWN signing keys — the `jwks` of its
	// (now signature-VALIDATED) Entity Configuration (NOT the openid_relying_
	// party.jwks, which is the protocol/client key set in ResolvedRPMetadata).
	// These are the keys the chain VOUCHES FOR the leaf entity itself. The
	// federation-resolved trust-mark path (slice 4c) uses them when the resolved
	// leaf is a Trust Mark ISSUER (its marks are signed with its entity keys), so
	// the mark is verified against the issuer's chain-vouched keys rather than a
	// self-asserted set. The leaf config's signature was verified in validate(),
	// so reading its jwks off the parsed claims is sound. nil only for a
	// malformed/empty leaf jwks (which validate() never admits for a chain it
	// produces).
	LeafKeys []core.JWK
}

// Expiry returns the instant this validated chain ceases to be trustworthy:
// the EARLIEST exp across every statement in the chain (a chain is only as
// fresh as its soonest-expiring link — once any statement expires the chain
// must be re-resolved). Returns the zero Time when no statement carries a
// positive exp (which validate() never admits — every link's exp is checked
// and a zero exp is rejected — so a non-zero result is guaranteed for a chain
// produced by ResolveTrustChain). Slice-3's registration cache reads this as
// the cache TTL bound so a derived federation Client is NEVER served from an
// expired chain.
func (tc *TrustChain) Expiry() time.Time {
	if tc == nil {
		return time.Time{}
	}
	var min int64
	for _, compact := range tc.Statements {
		link, err := parseStatement(compact)
		if err != nil {
			// A statement that no longer parses cannot vouch for freshness;
			// treat the chain as already-expired (defensive — these are the
			// SAME compact strings validate() already parsed + verified, so
			// this path is unreachable for a ResolveTrustChain result).
			return time.Time{}
		}
		if link.claims.Exp <= 0 {
			return time.Time{}
		}
		if min == 0 || link.claims.Exp < min {
			min = link.claims.Exp
		}
	}
	if min == 0 {
		return time.Time{}
	}
	return time.Unix(min, 0)
}

// TrustChainResolver resolves + validates trust chains. Constructed once
// (NewTrustChainResolver) and shared; immutable + concurrency-safe (the
// fetcher's HTTP client is safe for concurrent use). A resolver with no
// configured anchors is inert.
type TrustChainResolver struct {
	cfg         *Config
	fetcher     EntityStatementFetcher
	now         func() time.Time
	allowedAlgs map[string]struct{}
	logError    func(msg string, args ...any)
}

// TrustChainResolverOption configures a TrustChainResolver.
type TrustChainResolverOption func(*TrustChainResolver)

// WithTrustChainFetcher injects a custom EntityStatementFetcher (the test seam
// for a FAKE federation, or an operator's proxy-aware client). Default is the
// hardened httpFetcher.
func WithTrustChainFetcher(f EntityStatementFetcher) TrustChainResolverOption {
	return func(r *TrustChainResolver) { r.fetcher = f }
}

// WithTrustChainClock injects the clock the validator reads exp/iat against.
// Injected (not a direct time.Now) so a test drives a fixed time through BOTH
// the synthesized statement exp AND the validator — no real-clock-vs-fixed
// date bomb. Default is time.Now.
func WithTrustChainClock(now func() time.Time) TrustChainResolverOption {
	return func(r *TrustChainResolver) {
		if now != nil {
			r.now = now
		}
	}
}

// WithTrustChainAllowedAlgs overrides the asymmetric signing-alg allowlist
// passed to security.VerifyCompactJWS at every hop. Default is the full
// asymmetric set (EdDSA/ES*/RS*/PS*); VerifyCompactJWS rejects any symmetric
// alg or alg=none regardless, so this only NARROWS the asymmetric set for a
// stricter deployment.
func WithTrustChainAllowedAlgs(algs map[string]struct{}) TrustChainResolverOption {
	return func(r *TrustChainResolver) {
		if len(algs) > 0 {
			r.allowedAlgs = algs
		}
	}
}

// WithTrustChainLogger injects the non-fatal error log seam (the SPECIFIC
// rejection cause goes here, never to the caller). Default is a no-op.
func WithTrustChainLogger(logError func(msg string, args ...any)) TrustChainResolverOption {
	return func(r *TrustChainResolver) {
		if logError != nil {
			r.logError = logError
		}
	}
}

// federationAsymmetricAlgs is the default per-hop alg allowlist: the full
// asymmetric set the security verifier supports. A federation's signing keys
// are asymmetric (the whole model is public-key trust), so admitting a
// symmetric alg would be the public-key-as-HMAC confusion attack — which
// VerifyCompactJWS refuses outright anyway. Listing the asymmetric set
// explicitly keeps the gate at THIS layer too (defense in depth).
func federationAsymmetricAlgs() map[string]struct{} {
	return map[string]struct{}{
		"EdDSA": {},
		"ES256": {}, "ES384": {}, "ES512": {},
		"RS256": {}, "RS384": {}, "RS512": {},
		"PS256": {}, "PS384": {}, "PS512": {},
	}
}

// NewTrustChainResolver builds a resolver from the federation config. A nil
// cfg or one with no TrustAnchors yields an inert resolver (ResolveTrustChain
// returns ErrFederationResolverDisabled) — the default-off posture.
func NewTrustChainResolver(cfg *Config, opts ...TrustChainResolverOption) *TrustChainResolver {
	r := &TrustChainResolver{
		cfg:         cfg,
		fetcher:     newHTTPFetcher(),
		now:         time.Now,
		allowedAlgs: federationAsymmetricAlgs(),
		logError:    func(string, ...any) {},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Enabled reports whether the resolver has at least one configured trust
// anchor (and is therefore live). A disabled resolver is inert.
func (r *TrustChainResolver) Enabled() bool {
	return r != nil && r.cfg != nil && len(r.cfg.TrustAnchors) > 0
}

// ResolveTrustChain resolves and validates the trust chain for leafEntityID,
// returning the VALIDATED chain + the policy-applied RP metadata, or
// ErrTrustChainInvalid on ANY failure (fail-closed). leafEntityID is the
// remote entity's Entity Identifier (an https URL); the leaf is trusted ONLY
// if a chain from it reaches a configured trust anchor and every link
// validates.
func (r *TrustChainResolver) ResolveTrustChain(ctx context.Context, leafEntityID string) (*TrustChain, error) {
	if !r.Enabled() {
		return nil, ErrFederationResolverDisabled
	}
	// The leaf identifier is itself a fetched URL — gate it (https, no internal
	// host) before any network work, same as the fetcher does internally.
	if err := validateFederationURL(leafEntityID); err != nil {
		r.logError("federation: leaf entity id rejected", "entity_id", leafEntityID, "error", err)
		return nil, ErrTrustChainInvalid
	}

	// Phase 1 — ASSEMBLE (fetch + parse-to-navigate, bottom-up). Produces the
	// ordered link list [leaf, sub1, sub2, ..., anchor-config] and the matched
	// anchor. No trust is granted here; parsing only drives the walk.
	links, anchor, err := r.assemble(ctx, leafEntityID)
	if err != nil {
		// assemble already logged the specific cause.
		return nil, ErrTrustChainInvalid
	}

	// Phase 2 — VALIDATE (top-down, against the configured anchor keys). This
	// is the trust decision: every signature is re-verified against keys
	// established higher in the chain, exp/iat/iss/sub/typ are checked per hop.
	if err := r.validate(links, anchor); err != nil {
		r.logError("federation: trust chain validation failed", "leaf", leafEntityID, "anchor", anchor.EntityID, "error", err)
		return nil, ErrTrustChainInvalid
	}

	// Phase 3 — APPLY METADATA POLICY (§10), merged top-down, to the leaf RP
	// metadata. A violation or merge conflict rejects.
	resolvedRP, err := r.applyPolicy(links)
	if err != nil {
		r.logError("federation: metadata policy rejected the leaf", "leaf", leafEntityID, "error", err)
		return nil, ErrTrustChainInvalid
	}

	return buildTrustChain(leafEntityID, anchor, links, resolvedRP), nil
}

// buildTrustChain assembles the VALIDATED TrustChain result from the verified
// links + the policy-applied RP metadata. Every field is sourced from a
// signature-validated statement (the leaf's trust_marks/jwks off links[0], the
// anchor's trust_mark_issuers off the terminus) — see the field docs on
// TrustChain for the per-field provenance.
func buildTrustChain(leafEntityID string, anchor TrustAnchor, links []chainLink, resolvedRP map[string]any) *TrustChain {
	statements := make([]string, len(links))
	for i, l := range links {
		statements[i] = l.compact
	}
	return &TrustChain{
		LeafEntityID:   leafEntityID,
		AnchorEntityID: anchor.EntityID,
		Statements:     statements,
		// The leaf (links[0]) is the validated leaf Entity Configuration; its
		// trust_marks ride along for the slice-4b requirement gate. The signature
		// was verified in validate(), so these wrapper entries come from the
		// authenticated leaf — but each inner Trust Mark JWT is STILL verified
		// independently (the wrapper's self-asserted type is not trusted).
		LeafTrustMarks: links[0].claims.TrustMarks,
		// The ANCHOR (links[len-1]) is the chain terminus, its config verified
		// against the CONFIGURED root-of-trust keys in validate(). Its
		// trust_mark_issuers is the AUTHORIZATION ROOT for the federation-resolved
		// trust-mark path — surfaced from the now-validated anchor claims (the
		// spec mandates this claim be IGNORED on any non-anchor, so it is sourced
		// ONLY from the anchor terminus, never an intermediate or the leaf).
		AnchorTrustMarkIssuers: anchorTrustMarkIssuers(links[len(links)-1].claims),
		// The resolved leaf entity's own (chain-vouched) signing keys, for the
		// slice-4c path when the leaf is itself a Trust Mark Issuer.
		LeafKeys:           links[0].claims.JWKS.Keys,
		ResolvedRPMetadata: resolvedRP,
	}
}

// anchorTrustMarkIssuers extracts the §3.1.2 trust_mark_issuers map from a
// (validated) anchor Entity Configuration's federation_entity metadata, or nil
// when absent. The claim lives in metadata.federation_entity per spec; reading
// it from the validated anchor claims is sound (the anchor config's signature
// was verified against the configured root-of-trust keys).
func anchorTrustMarkIssuers(claims EntityStatementClaims) map[string][]string {
	if claims.Metadata == nil || claims.Metadata.FederationEntity == nil {
		return nil
	}
	return claims.Metadata.FederationEntity.TrustMarkIssuers
}

// validate is the TRUST decision: it re-verifies every signature in the
// assembled chain against the keys established higher in the chain (rooted in
// the CONFIGURED anchor keys), checks iss/sub/typ/exp/iat at every hop, and
// finally enforces the §6.2 trust-chain constraints (from the now-verified
// statements). Returns the FIRST failure (fail-closed).
//
// Canonical chain shape produced by assemble (leaf-first):
//
//	[ leafConfig, SS_1, SS_2, ..., SS_n, anchorConfig ]
//
// leafConfig + anchorConfig are self-signed Entity Configurations (the ends);
// SS_i are Subordinate Statements, SS_i issued by the entity above SS_{i-1}'s
// subject about the entity below (SS_n is the anchor's statement about the
// topmost intermediate; SS_1 is the immediate superior's statement about the
// leaf). The intermediates' OWN Entity Configurations are NOT in the chain —
// their keys enter trust ONLY via the SS above them. (Degenerate "leaf IS the
// configured anchor": chain is just [anchorConfig].)
//
// Key provenance, established TOP-DOWN:
//   - anchorConfig verified against the CONFIGURED anchor keys (the root of
//     trust; NEVER the keys the fetched statement self-asserts).
//   - each SS verified against the jwks the statement ABOVE it vouched for its
//     issuer (SS_n against anchorConfig.jwks; SS_i against SS_{i+1}.jwks).
//   - leafConfig verified against SS_1.jwks (the keys the immediate superior
//     published FOR the leaf — NOT the leaf's self-asserted keys).
func (r *TrustChainResolver) validate(links []chainLink, anchor TrustAnchor) error {
	if len(links) == 0 {
		return errors.New("empty chain")
	}
	now := r.now()
	skew := r.cfg.maxClockSkew()

	last := links[len(links)-1]

	// 1) Anchor Entity Configuration (last link) verified against the CONFIGURED
	//    anchor keys — the root of trust. Self-signed: iss==sub==anchor id.
	if err := r.verifyAnchorConfig(last, anchor, now, skew); err != nil {
		return err
	}

	// Degenerate single-link chain: leaf IS the configured anchor. Done.
	if len(links) == 1 {
		return nil
	}

	// 2) Walk DOWN, establishing each link's verification keys from the link
	//    above (seeded with the now-trusted anchor config's own keys), then verify
	//    the leaf against the keys SS_1 vouched for it.
	if err := r.verifyChainLinks(links, last, now, skew); err != nil {
		return err
	}

	// 3) §6.2 trust-chain CONSTRAINTS. Enforced HERE — at the tail of validate,
	//    after EVERY link's signature is re-verified — so the constraints are
	//    read only from signature-validated statements (an attacker cannot forge
	//    a relaxing constraint). ADDITIVE + fail-closed: this can only ADD a
	//    rejection; a chain with no constraints makes it a no-op (slice-2
	//    behavior byte-identical). See constraints.go.
	if err := enforceConstraints(links); err != nil {
		return fmt.Errorf("trust chain constraints: %w", err)
	}
	return nil
}

// verifyStatement verifies a compact Entity Statement JWS against keys and
// asserts the JOSE typ is entity-statement+jwt (so a plain access/id token
// signed by the same key can never masquerade as a federation statement —
// the typ gate, mirroring the issuers' at+jwt discipline). Signature check is
// the shared security.VerifyCompactJWS (asymmetric-only, alg=none-blocked,
// kid-bound).
func (r *TrustChainResolver) verifyStatement(compact string, keys []core.JWK) error {
	if len(keys) == 0 {
		return errors.New("no verification keys")
	}
	if err := requireEntityStatementTyp(compact); err != nil {
		return err
	}
	if _, err := security.VerifyCompactJWS(compact, keys, r.allowedAlgs); err != nil {
		return err
	}
	return nil
}

// checkSelfSigned asserts a self-signed Entity Configuration's iss==sub==want.
func checkSelfSigned(claims EntityStatementClaims, want string) error {
	if claims.Iss != want || claims.Sub != want {
		return fmt.Errorf("iss/sub %q/%q != expected self-signed identity %q", claims.Iss, claims.Sub, want)
	}
	return nil
}

// checkFresh enforces the per-hop exp/iat window with a small skew allowance.
// A statement is rejected if it is expired (now > exp+skew) or not yet valid
// (now < iat-skew). Both bounds are deliberately tight (federation statements
// are long-lived; the skew only absorbs clock drift). exp MUST be present
// (a zero exp is rejected — a statement with no expiry is never accepted).
func checkFresh(claims EntityStatementClaims, now time.Time, skew time.Duration) error {
	if claims.Exp <= 0 {
		return errors.New("statement has no exp")
	}
	exp := time.Unix(claims.Exp, 0)
	if now.After(exp.Add(skew)) {
		return fmt.Errorf("statement expired at %d (now %d)", claims.Exp, now.Unix())
	}
	if claims.Iat > 0 {
		iat := time.Unix(claims.Iat, 0)
		if now.Before(iat.Add(-skew)) {
			return fmt.Errorf("statement not yet valid (iat %d, now %d)", claims.Iat, now.Unix())
		}
	}
	return nil
}
