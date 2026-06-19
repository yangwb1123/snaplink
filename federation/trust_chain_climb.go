package federation

import "context"

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
		res, found, fatal := r.climbViaHint(ctx, state, sup, currentID, visited, remainingDepth)
		if found {
			return res, true
		}
		if fatal {
			// Fetch-budget exhaustion is terminal for the whole resolution, not
			// just this branch — stop rather than try more fan-out.
			return climbResult{}, false
		}
	}
	return climbResult{}, false
}

// climbViaHint attempts to reach a configured anchor via ONE authority hint
// `sup` (a superior of currentID). It returns:
//
//   - (res, true, false) when this hint reaches a configured anchor (directly
//     or via recursion) — res holds the discovered upward links;
//   - ({}, false, true) when the fetch budget is exhausted — a TERMINAL
//     condition the caller must propagate (no more fan-out anywhere);
//   - ({}, false, false) when this hint is a dead end (cycle, bad URL,
//     unreachable, no fetch endpoint, no anchor) — the caller tries the next.
func (r *TrustChainResolver) climbViaHint(ctx context.Context, state *walkState, sup, currentID string, visited map[string]struct{}, remainingDepth int) (climbResult, bool, bool) {
	if _, seen := visited[sup]; seen {
		// Cycle in authority_hints (A hints B hints A, or a self-hint).
		r.logError("federation: authority_hints cycle detected", "superior", sup, "from", currentID)
		return climbResult{}, false, false
	}
	if err := validateFederationURL(sup); err != nil {
		r.logError("federation: authority hint rejected", "superior", sup, "error", err)
		return climbResult{}, false, false
	}
	supConfig, err := r.fetchEntityConfig(ctx, state, sup)
	if err != nil {
		r.logError("federation: fetch superior entity configuration", "superior", sup, "error", err)
		return climbResult{}, false, state.remainingFetches <= 0
	}
	fetchEndpoint := superiorFetchEndpoint(supConfig.claims)
	if fetchEndpoint == "" {
		r.logError("federation: superior has no federation_fetch_endpoint", "superior", sup)
		return climbResult{}, false, false
	}
	subStmt, err := r.fetchSubordinate(ctx, state, fetchEndpoint, sup, currentID)
	if err != nil {
		r.logError("federation: fetch subordinate statement", "superior", sup, "subject", currentID, "error", err)
		return climbResult{}, false, state.remainingFetches <= 0
	}
	if anchor, ok := r.matchConfiguredAnchor(sup); ok {
		// Reached a configured anchor: the upward links are the Subordinate
		// Statement (anchor about current) + the anchor's own Entity Configuration
		// (the terminal, verified against the CONFIGURED keys).
		return climbResult{links: []chainLink{subStmt, supConfig}, anchor: anchor}, true, false
	}
	return r.descendThroughSuperior(ctx, state, sup, supConfig, subStmt, visited, remainingDepth)
}

// descendThroughSuperior continues the climb through a non-anchor superior:
// it recurses from supConfig over the superior's own authority_hints (visited
// COPIED + extended so a failed branch can't poison a sibling, remainingDepth-1
// consuming this hop) and, on success, prepends ONLY this hop's Subordinate
// Statement below the upper links. The intermediate's own config is NOT a
// validated link — its keys enter trust solely via the upper SS that vouches for
// them. Returns the same (result, found, fatal) triple as climbViaHint.
func (r *TrustChainResolver) descendThroughSuperior(ctx context.Context, state *walkState, sup string, supConfig, subStmt chainLink, visited map[string]struct{}, remainingDepth int) (climbResult, bool, bool) {
	supHints := supConfig.claims.AuthorityHints
	if len(supHints) == 0 {
		r.logError("federation: superior is not a configured anchor and has no authority_hints", "superior", sup)
		return climbResult{}, false, false
	}
	childVisited := cloneVisited(visited)
	childVisited[sup] = struct{}{}
	upper, ok := r.climbToAnchor(ctx, state, supConfig, supHints, childVisited, remainingDepth-1)
	if !ok {
		return climbResult{}, false, state.remainingFetches <= 0
	}
	combined := make([]chainLink, 0, 1+len(upper.links))
	combined = append(combined, subStmt)
	combined = append(combined, upper.links...)
	return climbResult{links: combined, anchor: upper.anchor}, true, false
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
