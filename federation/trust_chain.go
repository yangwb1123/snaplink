package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/security"
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
// configured anchor, an over-long path, a cycle, or a metadata-policy
// violation/merge-conflict REJECTS the whole resolution with one coarse error
// (ErrTrustChainInvalid). Detail goes to the log seam, never the caller —
// no partial trust, no untrusted-anchor fallback.

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

	statements := make([]string, len(links))
	for i, l := range links {
		statements[i] = l.compact
	}
	return &TrustChain{
		LeafEntityID:       leafEntityID,
		AnchorEntityID:     anchor.EntityID,
		Statements:         statements,
		ResolvedRPMetadata: resolvedRP,
	}, nil
}

// assemble fetches + parses the chain bottom-up: the leaf's Entity
// Configuration, then for each authority hint the superior's Entity
// Configuration + the Subordinate Statement it issues about the current
// entity, climbing until an entity matching a configured trust anchor is
// reached. BOUNDED by max depth + a visited-set cycle guard (an unbounded or
// cyclic authority_hints can neither hang nor blow the stack). Returns the
// ordered links [leaf, sub1, ..., anchorConfig] (leaf-first) + the matched
// configured anchor.
//
// The walk PARSES statements to read authority_hints / federation_fetch_
// endpoint / jwks — navigation, not trust. The signatures are re-verified in
// validate(); a forged statement that lies about its superiors only steers the
// walk somewhere that will fail validation.
func (r *TrustChainResolver) assemble(ctx context.Context, leafEntityID string) ([]chainLink, TrustAnchor, error) {
	maxDepth := r.cfg.maxTrustChainDepth()

	// Per-resolution mutable walk state (NOT on the resolver, which must stay
	// concurrency-safe + immutable for shared use). It carries a TOTAL fetch
	// budget so a hostile federation with high authority_hints FAN-OUT (each
	// node listing many superiors, each branch fetched) cannot explode into an
	// exponential number of requests even within the depth bound — the depth
	// bound alone caps PATH length, the budget caps TOTAL work.
	state := &walkState{remainingFetches: maxTotalFetches(maxDepth)}

	// Fetch + parse the leaf Entity Configuration (self-signed). iss==sub is
	// checked in validate; here we only need it parsed to read its hints/keys.
	leafConfig, err := r.fetchEntityConfig(ctx, state, leafEntityID)
	if err != nil {
		r.logError("federation: fetch leaf entity configuration", "entity_id", leafEntityID, "error", err)
		return nil, TrustAnchor{}, err
	}

	// Is the leaf ITSELF a configured anchor? Then the chain is just [anchor]
	// (a configured anchor resolving itself). A leaf that merely CLAIMS to be
	// its own anchor but is not configured does NOT match here — it must reach
	// a configured anchor via its hints like anyone else, and a self-signed
	// non-configured leaf with no hints simply never anchors (rejected).
	if anchor, ok := r.matchConfiguredAnchor(leafEntityID); ok {
		return []chainLink{leafConfig}, anchor, nil
	}

	hints := leafConfig.claims.AuthorityHints
	if len(hints) == 0 {
		return nil, TrustAnchor{}, fmt.Errorf("no configured trust anchor reached from leaf %q (no authority_hints)", leafEntityID)
	}

	// Climb (recursive, bounded by maxDepth + the visited-set cycle guard + the
	// total fetch budget). climbToAnchor returns the upward links [sub_1,
	// supConfig_1, ..., sub_k, anchorConfig] on the first authority hint that
	// reaches a configured anchor within the bounds.
	visited := map[string]struct{}{leafEntityID: {}}
	res, ok := r.climbToAnchor(ctx, state, leafConfig, hints, visited, maxDepth)
	if !ok {
		return nil, TrustAnchor{}, fmt.Errorf("no configured trust anchor reachable from leaf %q within bounds (depth %d)", leafEntityID, maxDepth)
	}
	links := append([]chainLink{leafConfig}, res.links...)
	return links, res.anchor, nil
}

// walkState is the per-resolution mutable state threaded through the climb. It
// holds the TOTAL remaining fetch budget (a DoS guard against fan-out, see
// assemble). A separate value per ResolveTrustChain call keeps the resolver
// itself immutable/concurrency-safe.
type walkState struct {
	remainingFetches int
}

// spendFetch decrements the budget, returning false when exhausted (the caller
// then fails the branch). Each network fetch (config or subordinate) spends one.
func (s *walkState) spendFetch() bool {
	if s.remainingFetches <= 0 {
		return false
	}
	s.remainingFetches--
	return true
}

// maxTotalFetches derives the absolute fetch ceiling for a resolution from the
// depth bound. Each legitimate hop costs at most 2 fetches (the superior's
// Entity Configuration + the Subordinate Statement); a generous per-level
// fan-out allowance keeps real (small-fan-out) federations well clear while a
// hostile high-fan-out federation hits the wall. The +2 covers the leaf
// configuration + the degenerate direct-anchor fetch.
func maxTotalFetches(maxDepth int) int {
	return (maxDepth+1)*maxFanoutFetchAllowance + 2
}

// maxFanoutFetchAllowance bounds the fetches charged per chain level (a level's
// alternative authority-hint branches). 16 tolerates a realistically-branchy
// federation level while capping a hostile fan-out.
const maxFanoutFetchAllowance = 16

// climbResult carries the upward links discovered above the current entity and
// the matched anchor. Per the OpenID Federation §9 Trust Chain model the
// VALIDATED chain is [leaf Entity Configuration, SS_1, SS_2, ..., SS_n, Trust
// Anchor Entity Configuration]: the leaf + TA self-configs at the ends, and a
// run of Subordinate Statements between (SS_i issued by the entity above about
// the entity below). The INTERMEDIATE entities' own Entity Configurations are
// fetched during the walk (to read their fetch endpoint + authority_hints) but
// are DELIBERATELY NOT validated links: the key that verifies SS_i is the jwks
// the statement ABOVE it (SS_{i+1}) vouches for SS_i's issuer — NEVER the
// intermediate's self-asserted config jwks (which could be a superset). So
// links holds [SS_1, ..., SS_n, anchorConfig] (the anchor's self-config is the
// terminal, verified against the CONFIGURED keys).
type climbResult struct {
	links  []chainLink
	anchor TrustAnchor
}

// climbToAnchor tries to extend the chain from `current` (whose Entity
// Configuration is the link below) up to a configured trust anchor by trying
// each authority hint, recursively. BOUNDED two ways: remainingDepth caps how
// many MORE superior hops may be taken (a deep/slow federation cannot hang or
// recurse without limit), and the per-branch visited set rejects a CYCLE in
// authority_hints (A→B→A, or a self-hint) so a hostile cyclic federation can
// neither loop forever nor stack-overflow. Returns the discovered upward links
// + the matched anchor on the FIRST hint that reaches a configured anchor
// within the bound.
//
// For each hint H (a superior):
//  1. fetch H's Entity Configuration (for its fetch endpoint + hints; NOT a
//     validated link unless H is the anchor);
//  2. fetch the Subordinate Statement H issues about `current`
//     (iss=H, sub=current) from H's federation_fetch_endpoint — this IS a
//     validated link (SS);
//  3. if H is a configured anchor → links = [SS, anchorConfig], done;
//  4. else recurse from H, prepending [SS] (H's own config is discarded).
func (r *TrustChainResolver) climbToAnchor(ctx context.Context, state *walkState, current chainLink, hints []string, visited map[string]struct{}, remainingDepth int) (climbResult, bool) {
	if remainingDepth <= 0 {
		// No more superior hops permitted (depth bound). A leaf->anchor that
		// needs one hop requires remainingDepth >= 1.
		r.logError("federation: depth bound reached before a configured anchor", "from", current.claims.Sub)
		return climbResult{}, false
	}
	currentID := current.claims.Sub
	for _, sup := range hints {
		if _, seen := visited[sup]; seen {
			// Cycle in authority_hints (A hints B hints A, or a self-hint).
			r.logError("federation: authority_hints cycle detected", "superior", sup, "from", currentID)
			continue
		}
		if err := validateFederationURL(sup); err != nil {
			r.logError("federation: authority hint rejected", "superior", sup, "error", err)
			continue
		}

		supConfig, err := r.fetchEntityConfig(ctx, state, sup)
		if err != nil {
			r.logError("federation: fetch superior entity configuration", "superior", sup, "error", err)
			// A fetch-budget exhaustion (vs a transport error) is terminal for the
			// whole resolution, not just this branch — bail out rather than try
			// more fan-out.
			if state.remainingFetches <= 0 {
				return climbResult{}, false
			}
			continue
		}
		fetchEndpoint := superiorFetchEndpoint(supConfig.claims)
		if fetchEndpoint == "" {
			r.logError("federation: superior has no federation_fetch_endpoint", "superior", sup)
			continue
		}
		subStmt, err := r.fetchSubordinate(ctx, state, fetchEndpoint, sup, currentID)
		if err != nil {
			r.logError("federation: fetch subordinate statement", "superior", sup, "subject", currentID, "error", err)
			if state.remainingFetches <= 0 {
				return climbResult{}, false
			}
			continue
		}

		if anchor, ok := r.matchConfiguredAnchor(sup); ok {
			// Reached a configured anchor: the upward links are the Subordinate
			// Statement (anchor about current) + the anchor's own Entity
			// Configuration (the terminal, verified against the CONFIGURED keys).
			return climbResult{
				links:  []chainLink{subStmt, supConfig},
				anchor: anchor,
			}, true
		}

		supHints := supConfig.claims.AuthorityHints
		if len(supHints) == 0 {
			r.logError("federation: superior is not a configured anchor and has no authority_hints", "superior", sup)
			continue
		}
		// Descend through this superior. Mark it visited in a COPY scoped to this
		// branch so a failed branch does not poison a sibling hint (correct cycle
		// detection across alternatives). remainingDepth-1 consumes this hop.
		childVisited := cloneVisited(visited)
		childVisited[sup] = struct{}{}
		upper, ok := r.climbToAnchor(ctx, state, supConfig, supHints, childVisited, remainingDepth-1)
		if !ok {
			if state.remainingFetches <= 0 {
				return climbResult{}, false
			}
			continue
		}
		// Prepend ONLY this hop's Subordinate Statement below the upper links.
		// The intermediate's own config (supConfig) is NOT a validated link — its
		// keys enter trust solely via the upper SS that vouches for them.
		combined := make([]chainLink, 0, 1+len(upper.links))
		combined = append(combined, subStmt)
		combined = append(combined, upper.links...)
		return climbResult{links: combined, anchor: upper.anchor}, true
	}
	return climbResult{}, false
}

// validate is the TRUST decision: it re-verifies every signature in the
// assembled chain against the keys established higher in the chain (rooted in
// the CONFIGURED anchor keys), and checks iss/sub/typ/exp/iat at every hop.
// Returns the FIRST failure (fail-closed).
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
	if len(anchor.Keys) == 0 {
		return fmt.Errorf("configured anchor %q has no keys", anchor.EntityID)
	}
	if err := r.verifyStatement(last.compact, anchor.Keys); err != nil {
		return fmt.Errorf("anchor entity configuration signature: %w", err)
	}
	if err := checkSelfSigned(last.claims, anchor.EntityID); err != nil {
		return fmt.Errorf("anchor entity configuration: %w", err)
	}
	if err := checkFresh(last.claims, now, skew); err != nil {
		return fmt.Errorf("anchor entity configuration: %w", err)
	}

	// Degenerate single-link chain: leaf IS the configured anchor. Done.
	if len(links) == 1 {
		return nil
	}

	// 2) Walk DOWN. issuerKeys/issuerID are the keys + identity the link just
	//    verified vouches for the NEXT link down. Seed with the (now-trusted)
	//    anchor config's own keys.
	issuerKeys := last.claims.JWKS.Keys
	issuerID := last.claims.Sub

	// 2a) The Subordinate Statements SS_n .. SS_1 (indices len-2 down to 1). Each
	//     is verified against the keys vouched for its issuer by the link above.
	for i := len(links) - 2; i >= 1; i-- {
		ss := links[i]
		if err := r.verifyStatement(ss.compact, issuerKeys); err != nil {
			return fmt.Errorf("subordinate statement at %d signature: %w", i, err)
		}
		if err := checkFresh(ss.claims, now, skew); err != nil {
			return fmt.Errorf("subordinate statement at %d: %w", i, err)
		}
		// iss MUST be the entity the link above vouched for (issuerID); sub is the
		// entity below; iss != sub (a real subordinate relationship).
		if ss.claims.Iss != issuerID {
			return fmt.Errorf("subordinate statement at %d: iss %q != expected issuer %q", i, ss.claims.Iss, issuerID)
		}
		if ss.claims.Sub == "" || ss.claims.Sub == ss.claims.Iss {
			return fmt.Errorf("subordinate statement at %d: bad sub %q (empty or == iss)", i, ss.claims.Sub)
		}
		if len(ss.claims.JWKS.Keys) == 0 {
			return fmt.Errorf("subordinate statement at %d: empty subject jwks", i)
		}
		// The keys this SS vouches for its SUBJECT become the issuer keys for the
		// next link down (the next SS, or the leaf config at index 0).
		issuerKeys = ss.claims.JWKS.Keys
		issuerID = ss.claims.Sub
	}

	// 2b) The leaf Entity Configuration (index 0): verified against the keys
	//     SS_1 vouched for the leaf (issuerKeys), NOT its self-asserted keys.
	//     Self-signed: iss==sub==leaf, and that identity MUST equal the subject
	//     SS_1 vouched for (issuerID).
	leaf := links[0]
	if err := r.verifyStatement(leaf.compact, issuerKeys); err != nil {
		return fmt.Errorf("leaf entity configuration signature: %w", err)
	}
	if err := checkFresh(leaf.claims, now, skew); err != nil {
		return fmt.Errorf("leaf entity configuration: %w", err)
	}
	if err := checkSelfSigned(leaf.claims, issuerID); err != nil {
		return fmt.Errorf("leaf entity configuration: %w", err)
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

// fetchEntityConfig fetches + parses an entity's self-signed Entity
// Configuration into a chainLink (compact + parsed claims). Parse failure
// (not a JWS, bad payload JSON) is an error; the SIGNATURE is verified later
// in validate against the established keys. Spends one fetch-budget unit
// (exhaustion is a hard stop, the fan-out DoS guard).
func (r *TrustChainResolver) fetchEntityConfig(ctx context.Context, state *walkState, entityID string) (chainLink, error) {
	if !state.spendFetch() {
		return chainLink{}, errors.New("federation: fetch budget exhausted")
	}
	raw, err := r.fetcher.FetchEntityConfiguration(ctx, entityID)
	if err != nil {
		return chainLink{}, err
	}
	return parseStatement(string(raw))
}

// fetchSubordinate fetches + parses a Subordinate Statement into a chainLink.
// Spends one fetch-budget unit.
func (r *TrustChainResolver) fetchSubordinate(ctx context.Context, state *walkState, fetchEndpoint, issuer, subject string) (chainLink, error) {
	if !state.spendFetch() {
		return chainLink{}, errors.New("federation: fetch budget exhausted")
	}
	raw, err := r.fetcher.FetchSubordinateStatement(ctx, fetchEndpoint, issuer, subject)
	if err != nil {
		return chainLink{}, err
	}
	return parseStatement(string(raw))
}

// matchConfiguredAnchor returns the configured TrustAnchor whose EntityID
// equals entityID, if any. This is the ONLY way a chain terminates: ONLY a
// configured anchor is a valid root. A self-signed entity claiming to be its
// own anchor that is NOT in this set never matches.
func (r *TrustChainResolver) matchConfiguredAnchor(entityID string) (TrustAnchor, bool) {
	for _, ta := range r.cfg.TrustAnchors {
		if ta.EntityID == entityID {
			return ta, true
		}
	}
	return TrustAnchor{}, false
}

// parseStatement splits + base64url-decodes the payload of a compact JWS into
// EntityStatementClaims WITHOUT verifying the signature (verification happens
// in validate against established keys). It exists so the walk can read
// authority_hints / jwks / fetch endpoint to navigate. A non-3-segment JWS or
// bad payload JSON is an error.
func parseStatement(compact string) (chainLink, error) {
	payload, err := unverifiedPayload(compact)
	if err != nil {
		return chainLink{}, err
	}
	var claims EntityStatementClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return chainLink{}, fmt.Errorf("federation: parse entity statement payload: %w", err)
	}
	return chainLink{compact: compact, claims: claims}, nil
}

// superiorFetchEndpoint extracts the federation_fetch_endpoint from a
// superior's parsed Entity Configuration (metadata.federation_entity), or ""
// when absent.
func superiorFetchEndpoint(claims EntityStatementClaims) string {
	if claims.Metadata == nil || claims.Metadata.FederationEntity == nil {
		return ""
	}
	return claims.Metadata.FederationEntity.FederationFetchEndpoint
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

// cloneVisited copies a visited-set so a descent branch's additions do not
// leak into a sibling branch (keeps the cycle guard correct under the
// per-hint alternatives).
func cloneVisited(in map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(in)+1)
	for k := range in {
		out[k] = struct{}{}
	}
	return out
}
