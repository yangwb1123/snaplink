package federation

import (
	"fmt"
	"net/url"
	"strings"
)

// OpenID Federation 1.0 §6.2 (anchor chain_constraints) — Trust Chain
// CONSTRAINTS. A Trust Anchor or Intermediate MAY impose delegation limits on
// the subtree of subordinates BELOW it, carried in the `constraints` Claim of a
// Subordinate Statement (§3.1.3): max_path_length, naming_constraints,
// allowed_entity_types.
//
// WHY this is enforced AFTER signature validation: the constraints come from a
// SIGNATURE-VALIDATED statement (the trust decision in validate() has already
// re-verified every link against the keys established higher in the chain,
// rooted in the CONFIGURED anchor keys). Enforcing them earlier — on a
// parsed-but-unverified statement — would let an attacker forge a RELAXING
// constraint. By construction enforceConstraints runs as the TAIL of validate()
// so it can never see an unverified constraint.
//
// WHY this is ADDITIVE + FAIL-SAFE: a constraint only ADDS a rejection
// condition — it can make validation STRICTER, never admit a chain validate()
// would otherwise reject. A chain carrying NO `constraints` anywhere is a no-op
// here (byte-identical to slice-2 behavior). A constraint bug therefore
// over-rejects (safe) rather than under-rejects.
//
// WHY "independently applied" (the spec's accumulation model, §6.2): the spec
// mandates that the `constraints` Claim in EACH Subordinate Statement be applied
// INDEPENDENTLY, and ANY failed check invalidates the whole chain. We do exactly
// that — each statement's constraints are checked against the subtree below ITS
// issuer. This is equivalent to (and strictly safer than) computing a single
// "effective" most-restrictive constraint: applying each independently means a
// deeper statement can never RELAX a higher one (a higher statement's check is
// still enforced regardless of what a lower statement says), and the
// most-restrictive bound necessarily wins because every statement's bound must
// independently hold. There is no merged-constraint state to get wrong.

// enforceConstraints applies the §6.2 trust-chain constraints carried on every
// Subordinate Statement in the (already signature-validated) chain. Returns the
// FIRST violation (fail-closed); the caller (validate → ResolveTrustChain) maps
// it to ErrTrustChainInvalid, so a violation yields the SAME coarse rejection as
// any other chain failure (oracle-consistent with slice 2 — no constraint-
// specific signal on the wire; the cause goes to the log seam only).
//
// links is the canonical leaf-first chain produced + verified by validate():
//
//	[ leafConfig(0), SS_1(1), SS_2(2), ..., SS_n(n), anchorConfig(n+1) ]
//
// leafConfig and anchorConfig are self-signed Entity Configurations (the ends)
// and carry NO `constraints` (a self-signed configuration is not a superior's
// statement about a subordinate). The Subordinate Statements SS_1..SS_n occupy
// indices 1..len-2; SS_i is issued by the entity one level above SS_{i-1} about
// the entity below, so SS_1 is the immediate superior's statement about the leaf
// and SS_n is the anchor's statement about the topmost intermediate.
//
// For a Subordinate Statement at index i (1 <= i <= n):
//   - The number of Intermediate Entities between its ISSUER and the Trust Chain
//     subject (the leaf) is i-1 (SS_1 → 0 intermediates below it; SS_2 → 1; …;
//     SS_n → n-1). This is what max_path_length bounds.
//   - The set of subordinate Entity Identifiers it constrains (its subject "as
//     well as all Entities Subordinate to it", §3.1.3) is { links[j].Sub : 1 <=
//     j <= i } — every subject from the leaf (SS_1.sub) up to SS_i.sub. This is
//     what naming_constraints restricts.
//   - allowed_entity_types restricts the Entity Types of the subordinates; the
//     trust boundary admits the LEAF, so the meaningful check is the leaf's
//     entity type(s) (the keys of its metadata Claim). federation_entity is
//     ALWAYS allowed (§6.2.3).
func enforceConstraints(links []chainLink) error {
	n := len(links)
	if n < 2 {
		// A single-link chain is the degenerate "leaf IS the configured anchor"
		// (just [anchorConfig]); there are no Subordinate Statements, hence no
		// constraints to apply. (n==0 cannot occur — validate rejects it.)
		return nil
	}

	// The leaf's Entity Types (metadata keys) — computed once, used by every
	// statement's allowed_entity_types check.
	leafTypes := leafEntityTypes(links[0])

	// Walk the Subordinate Statements SS_1..SS_n (indices 1..n-2). Each is
	// applied INDEPENDENTLY against the subtree below its issuer.
	for i := 1; i <= n-2; i++ {
		c := links[i].claims.Constraints
		if c == nil {
			continue // statement carries no constraints — nothing to enforce here.
		}
		if err := enforceStatementConstraints(c, i, links, leafTypes); err != nil {
			return err
		}
	}
	return nil
}

// enforceStatementConstraints applies the §6.2 constraints carried on the
// Subordinate Statement at index i, INDEPENDENTLY against the subtree below its
// issuer (the spec's accumulation model). Returns the first violation.
func enforceStatementConstraints(c *EntityConstraints, i int, links []chainLink, leafTypes map[string]struct{}) error {
	if err := enforceMaxPathLength(c, i); err != nil {
		return err
	}
	if err := enforceNamingConstraints(c, i, links); err != nil {
		return err
	}
	return enforceAllowedEntityTypes(c, i, leafTypes)
}

// enforceMaxPathLength applies max_path_length: the count of Intermediates
// between THIS statement's issuer and the leaf is i-1; it MUST NOT exceed the
// bound. A bound of 0 requires the subject to be the leaf directly (SS_1).
func enforceMaxPathLength(c *EntityConstraints, i int) error {
	if c.MaxPathLength == nil {
		return nil
	}
	limit := *c.MaxPathLength
	if limit < 0 {
		// §6.2.1: max_path_length MUST be >= 0. A malformed (negative) value is
		// fail-closed rejected, never silently treated as unlimited.
		return fmt.Errorf("constraints at %d: max_path_length %d is negative (malformed)", i, limit)
	}
	intermediatesBelow := i - 1
	if intermediatesBelow > limit {
		return fmt.Errorf("constraints at %d: %d intermediate(s) below exceed max_path_length %d", i, intermediatesBelow, limit)
	}
	return nil
}

// enforceNamingConstraints applies naming_constraints: every subordinate Entity
// Identifier below this statement's issuer (its subject and all entities
// subordinate to it, i.e. links[1..i].Sub) MUST satisfy the permitted/excluded
// host subtrees (RFC 5280 §4.2.1.10, host component).
func enforceNamingConstraints(c *EntityConstraints, i int, links []chainLink) error {
	if c.NamingConstraints == nil {
		return nil
	}
	for j := 1; j <= i; j++ {
		subID := links[j].claims.Sub
		if err := checkNamingConstraint(subID, c.NamingConstraints); err != nil {
			return fmt.Errorf("constraints at %d: subordinate %q: %w", i, subID, err)
		}
	}
	return nil
}

// enforceAllowedEntityTypes applies allowed_entity_types: the leaf's Entity
// Types MUST all be within the allowed set (federation_entity is always
// implicitly allowed). Absent (nil pointer) ⇒ any type allowed; a present
// (even empty) array ⇒ only the listed types (+ federation_entity).
func enforceAllowedEntityTypes(c *EntityConstraints, i int, leafTypes map[string]struct{}) error {
	if c.AllowedEntityTypes == nil {
		return nil
	}
	if err := checkAllowedEntityTypes(leafTypes, *c.AllowedEntityTypes); err != nil {
		return fmt.Errorf("constraints at %d: %w", i, err)
	}
	return nil
}

// federationEntityType is the §6.2.3 Entity Type Identifier that is ALWAYS
// allowed and MUST NOT appear in an allowed_entity_types constraint. The
// matcher treats it as implicitly permitted regardless of the constraint.
const federationEntityType = "federation_entity"

// leafEntityTypes returns the leaf Entity Configuration's Entity Types — the
// keys of its `metadata` Claim (§4: each metadata key IS an Entity Type
// Identifier, e.g. openid_relying_party / openid_provider / federation_entity).
// The federation surface here resolves RPs, so a leaf typically carries
// openid_relying_party (+ optionally federation_entity). Returned as a set.
//
// We read the keys off the TYPED EntityMetadata fields the model exposes (RP /
// OP / FederationEntity) rather than a raw map, since that is the parsed shape;
// a future metadata type would extend EntityMetadata and this function.
func leafEntityTypes(leaf chainLink) map[string]struct{} {
	types := map[string]struct{}{}
	m := leaf.claims.Metadata
	if m == nil {
		return types
	}
	if m.RP != nil {
		types[rpMetadataType] = struct{}{} // "openid_relying_party"
	}
	if m.OP != nil {
		types["openid_provider"] = struct{}{}
	}
	if m.FederationEntity != nil {
		types[federationEntityType] = struct{}{}
	}
	return types
}

// checkAllowedEntityTypes verifies every leaf Entity Type is within the allowed
// set per §6.2.3. federation_entity is always allowed (and the spec forbids it
// in the constraint, but tolerating it if present is harmless). An empty allowed
// list means ONLY federation_entity is permitted, so any protocol type on the
// leaf is rejected. A leaf advertising NO recognized type is permitted (there is
// nothing to disallow) — the constraint can only narrow, and an unrecognized/
// empty leaf is handled by the downstream metadata-to-client mapping.
func checkAllowedEntityTypes(leafTypes map[string]struct{}, allowed []string) error {
	allowSet := map[string]struct{}{federationEntityType: {}}
	for _, t := range allowed {
		allowSet[t] = struct{}{}
	}
	for t := range leafTypes {
		if _, ok := allowSet[t]; !ok {
			return fmt.Errorf("leaf entity type %q not in allowed_entity_types %v", t, allowed)
		}
	}
	return nil
}

// checkNamingConstraint applies the §6.2.2 naming_constraints (RFC 5280
// §4.2.1.10 domain-name constraints, host component) to one subordinate Entity
// Identifier. The Entity Identifier is an https URL; the constraint matches its
// HOST. Excluded beats permitted: a host matching ANY excluded entry is invalid
// regardless of the permitted list (§6.2.2). If a permitted list is present, the
// host MUST match at least one permitted entry.
//
// FAIL-CLOSED on ambiguity: an Entity Identifier that does not parse to an https
// host, or a constraint entry that is malformed, is rejected — an unparseable
// subordinate id cannot be proven to satisfy the namespace, and an ambiguous
// constraint must not be silently waved through (over-rejection is the safe
// direction, §2).
func checkNamingConstraint(entityID string, nc *NamingConstraints) error {
	host, err := entityHost(entityID)
	if err != nil {
		return fmt.Errorf("naming_constraints: %w", err)
	}

	// Excluded first — a match here is fatal regardless of permitted.
	for _, ex := range nc.Excluded {
		match, err := hostMatchesDomainConstraint(host, ex)
		if err != nil {
			return fmt.Errorf("naming_constraints: malformed excluded entry %q: %w", ex, err)
		}
		if match {
			return fmt.Errorf("host %q matches excluded subtree %q", host, ex)
		}
	}

	// Permitted, when present, must admit the host (match at least one entry).
	if len(nc.Permitted) > 0 {
		permitted := false
		for _, p := range nc.Permitted {
			match, err := hostMatchesDomainConstraint(host, p)
			if err != nil {
				return fmt.Errorf("naming_constraints: malformed permitted entry %q: %w", p, err)
			}
			if match {
				permitted = true
				break
			}
		}
		if !permitted {
			return fmt.Errorf("host %q not within any permitted subtree %v", host, nc.Permitted)
		}
	}
	return nil
}

// entityHost extracts the lowercased host (no port) from an Entity Identifier
// (an https URL). Mirrors the fetcher's URL gate: https-only with a host.
// Returns an error (→ fail-closed reject) for a malformed/non-https/empty-host
// id, since a subordinate whose namespace cannot be determined cannot be proven
// to satisfy the constraint.
func entityHost(entityID string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(entityID))
	if err != nil {
		return "", fmt.Errorf("malformed entity id %q: %w", entityID, err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("entity id %q is not https", entityID)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("entity id %q has no host", entityID)
	}
	return strings.ToLower(host), nil
}

// hostMatchesDomainConstraint implements the RFC 5280 §4.2.1.10 domain-name
// constraint match for a host, as §6.2.2 mandates:
//
//   - A constraint NOT beginning with a period specifies a single host: it
//     matches IFF the host equals it exactly (case-insensitive).
//   - A constraint beginning with a period specifies a domain subtree: it
//     matches a host that ENDS WITH the constraint and has at least one extra
//     label in front. ".example.com" matches "host.example.com" and
//     "my.host.example.com" but NOT "example.com" (the bare domain) and NOT a
//     foreign suffix like "notexample.com".
//
// Both sides are compared case-insensitively (DNS labels are case-insensitive).
// An empty constraint after trimming is malformed (would match everything or
// nothing ambiguously) → error, fail-closed.
func hostMatchesDomainConstraint(host, constraint string) (bool, error) {
	c := strings.ToLower(strings.TrimSpace(constraint))
	if c == "" {
		return false, fmt.Errorf("empty domain constraint")
	}
	if strings.HasPrefix(c, ".") {
		// Domain subtree: the host must end with the dotted constraint, which
		// (because the constraint starts with ".") guarantees a label boundary
		// AND at least one extra label in front. "host.example.com" ends with
		// ".example.com"; "example.com" does NOT (it lacks the leading label);
		// "notexample.com" does NOT (no "." boundary before "example.com").
		if c == "." {
			return false, fmt.Errorf("domain constraint %q is just a dot", constraint)
		}
		return strings.HasSuffix(host, c), nil
	}
	// Single host: exact match.
	return host == c, nil
}
