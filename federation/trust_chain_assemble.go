package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

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
