package federation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/federation"
)

// ===========================================================================
// OpenID Federation 1.0 §6.2 (chain_constraints) — TRUST-CHAIN CONSTRAINTS.
// These extend the slice-2 fake-federation harness (trust_chain_test.go): the
// same real-Ed25519 entities + fakeFetcher + fixed clock, now with a
// `constraints` Claim minted onto Subordinate Statements. Every test asserts
// the constraint can only make validation STRICTER (additive, fail-closed):
// a violation collapses to the SAME federation.ErrTrustChainInvalid as any
// other chain failure (oracle-safe), and a chain with NO constraints validates
// EXACTLY as slice 2 (the no-op proof).
// ===========================================================================

// intPtr is a small helper for the *int max_path_length operand (0 is
// meaningful, so the pointer distinguishes "0" from "absent").
func intPtr(i int) *int { return &i }

// strsPtr is a helper for the *[]string allowed_entity_types operand (the empty
// slice is meaningful — "only federation_entity" — so the pointer distinguishes
// "[]" from "absent"). A genuinely-empty (non-nil) slice is used so it marshals
// to a JSON [] (not null) and survives the sign/parse round-trip as PRESENT.
func strsPtr(s ...string) *[]string {
	out := make([]string, 0, len(s))
	out = append(out, s...)
	return &out
}

// subStmtC builds + signs the Subordinate Statement `e` (a superior) issues
// ABOUT subject, carrying a §6.2 `constraints` Claim (and no metadata_policy).
// It mirrors the harness's subordinateStatement but sets Constraints so the
// constraint-enforcement path is exercised. iss=e, sub=subject, jwks=subject's
// keys (the keys `e` vouches for subject).
func subStmtC(t *testing.T, e *fedEntity, subject *fedEntity, c *federation.EntityConstraints) string {
	t.Helper()
	claims := federation.EntityStatementClaims{
		Iss:         e.id,
		Sub:         subject.id,
		Iat:         fedClock.Unix(),
		Exp:         fedClock.Add(24 * time.Hour).Unix(),
		JWKS:        federation.EntityJWKS{Keys: subject.keys(t)},
		Constraints: c,
	}
	return e.signStatement(t, claims)
}

// ---------------------------------------------------------------------------
// max_path_length
// ---------------------------------------------------------------------------

// TestConstraints_MaxPathLengthZeroRejectsIntermediate: an anchor whose
// Subordinate Statement (about the intermediate) sets max_path_length=0 forbids
// ANY intermediate between the anchor and the leaf. The linear chain anchor ->
// intermediate -> leaf has one intermediate below the anchor → REJECTED.
func TestConstraints_MaxPathLengthZeroRejectsIntermediate(t *testing.T) {
	// anchorPolicy is carried via the constraints on the anchor->inter SS. Build
	// the linear federation but override that SS to carry max_path_length=0.
	f, anchor, inter, leaf := buildLinearFederation(t, map[string]any{"client_name": "X"}, nil, nil)
	// Replace the anchor->inter Subordinate Statement with one carrying
	// constraints {max_path_length: 0}. The anchor sits 1 intermediate (inter)
	// above the leaf, so a bound of 0 is violated.
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = subStmtC(t, anchor, inter,
		&federation.EntityConstraints{MaxPathLength: intPtr(0)})

	r := resolverFor(t, f, anchor)
	_, err := r.ResolveTrustChain(context.Background(), leaf.id)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("max_path_length=0 with an intermediate: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestConstraints_MaxPathLengthZeroAllowsDirectLeaf: max_path_length=0 on the
// anchor's statement ABOUT the leaf (a direct anchor child, no intermediate) is
// SATISFIED (0 intermediates below the anchor) → accepted.
func TestConstraints_MaxPathLengthZeroAllowsDirectLeaf(t *testing.T) {
	anchor := newFedEntity(t, tcAnchorID)
	leaf := newFedEntity(t, tcLeafID)
	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)
	f.configs[leaf.id] = leaf.entityConfig(t, []string{anchor.id}, "", map[string]any{"client_name": "Direct"})
	// Anchor -> leaf directly, max_path_length=0 (no intermediates) → OK.
	f.subs[subKey(tcFetchURL, anchor.id, leaf.id)] = subStmtC(t, anchor, leaf,
		&federation.EntityConstraints{MaxPathLength: intPtr(0)})

	r := resolverFor(t, f, anchor)
	if _, err := r.ResolveTrustChain(context.Background(), leaf.id); err != nil {
		t.Fatalf("max_path_length=0 on a direct leaf should be accepted: %v", err)
	}
}

// TestConstraints_MaxPathLengthOne: a 2-intermediate chain
// anchor -> i2 -> i1 -> leaf. max_path_length on the ANCHOR's statement:
//   - =2 → accepted (2 intermediates below the anchor: i1, i2);
//   - =1 → rejected (2 > 1).
func TestConstraints_MaxPathLengthOne(t *testing.T) {
	build := func(anchorLimit int) (*fakeFetcher, *fedEntity, *fedEntity) {
		anchor := newFedEntity(t, tcAnchorID)
		i2 := newFedEntity(t, "https://i2.test")
		i1 := newFedEntity(t, "https://i1.test")
		leaf := newFedEntity(t, tcLeafID)

		f := newFakeFetcher()
		f.configs[anchor.id] = anchor.entityConfig(t, nil, "https://anchor.test/fetch", nil)
		f.configs[i2.id] = i2.entityConfig(t, []string{anchor.id}, "https://i2.test/fetch", nil)
		f.configs[i1.id] = i1.entityConfig(t, []string{i2.id}, "https://i1.test/fetch", nil)
		f.configs[leaf.id] = leaf.entityConfig(t, []string{i1.id}, "", map[string]any{"client_name": "X"})
		// anchor about i2 carries the max_path_length constraint.
		f.subs[subKey("https://anchor.test/fetch", anchor.id, i2.id)] = subStmtC(t, anchor, i2,
			&federation.EntityConstraints{MaxPathLength: intPtr(anchorLimit)})
		f.subs[subKey("https://i2.test/fetch", i2.id, i1.id)] = i2.subordinateStatement(t, i1, nil)
		f.subs[subKey("https://i1.test/fetch", i1.id, leaf.id)] = i1.subordinateStatement(t, leaf, nil)
		return f, anchor, leaf
	}

	// limit 2 → the 2 intermediates fit → accepted.
	f2, anchor2, leaf2 := build(2)
	if _, err := resolverFor(t, f2, anchor2).ResolveTrustChain(context.Background(), leaf2.id); err != nil {
		t.Fatalf("max_path_length=2 with 2 intermediates should be accepted: %v", err)
	}

	// limit 1 → 2 intermediates exceed it → rejected.
	f1, anchor1, leaf1 := build(1)
	if _, err := resolverFor(t, f1, anchor1).ResolveTrustChain(context.Background(), leaf1.id); !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("max_path_length=1 with 2 intermediates: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestConstraints_DeeperStatementTighterWins: a deeper statement (closer to the
// leaf) imposing a TIGHTER bound is enforced even when a higher statement allows
// more — the INTERMEDIATE i2's statement about i1 sets max_path_length=0, which
// (i2 sits 1 intermediate i1 above the leaf) forbids any intermediate below i2,
// but i1 IS below i2 → rejected, regardless of the anchor's looser bound.
func TestConstraints_DeeperStatementTighterWins(t *testing.T) {
	anchor := newFedEntity(t, tcAnchorID)
	i2 := newFedEntity(t, "https://i2.test")
	i1 := newFedEntity(t, "https://i1.test")
	leaf := newFedEntity(t, tcLeafID)

	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, "https://anchor.test/fetch", nil)
	f.configs[i2.id] = i2.entityConfig(t, []string{anchor.id}, "https://i2.test/fetch", nil)
	f.configs[i1.id] = i1.entityConfig(t, []string{i2.id}, "https://i1.test/fetch", nil)
	f.configs[leaf.id] = leaf.entityConfig(t, []string{i1.id}, "", map[string]any{"client_name": "X"})
	// Anchor allows plenty (max_path_length=5).
	f.subs[subKey("https://anchor.test/fetch", anchor.id, i2.id)] = subStmtC(t, anchor, i2,
		&federation.EntityConstraints{MaxPathLength: intPtr(5)})
	// i2's statement about i1 sets a TIGHT max_path_length=0 — but i1 (below i2)
	// is itself an intermediate above the leaf, so 1 > 0 → violation.
	f.subs[subKey("https://i2.test/fetch", i2.id, i1.id)] = subStmtC(t, i2, i1,
		&federation.EntityConstraints{MaxPathLength: intPtr(0)})
	f.subs[subKey("https://i1.test/fetch", i1.id, leaf.id)] = i1.subordinateStatement(t, leaf, nil)

	r := resolverFor(t, f, anchor)
	if _, err := r.ResolveTrustChain(context.Background(), leaf.id); !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("a deeper tighter max_path_length must win: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestConstraints_DeeperStatementCannotRelax: a deeper statement setting a LOOSE
// bound CANNOT relax a tight bound a higher statement set. The anchor's
// statement (about i2) sets max_path_length=1, which the 2-intermediate chain
// (i1, i2 below the anchor) violates; i2's statement about i1 sets a loose
// max_path_length=5. The chain must STILL be rejected — independent application
// means the anchor's tight bound is enforced no matter what i2 says.
func TestConstraints_DeeperStatementCannotRelax(t *testing.T) {
	anchor := newFedEntity(t, tcAnchorID)
	i2 := newFedEntity(t, "https://i2.test")
	i1 := newFedEntity(t, "https://i1.test")
	leaf := newFedEntity(t, tcLeafID)

	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, "https://anchor.test/fetch", nil)
	f.configs[i2.id] = i2.entityConfig(t, []string{anchor.id}, "https://i2.test/fetch", nil)
	f.configs[i1.id] = i1.entityConfig(t, []string{i2.id}, "https://i1.test/fetch", nil)
	f.configs[leaf.id] = leaf.entityConfig(t, []string{i1.id}, "", map[string]any{"client_name": "X"})
	// Anchor sets a TIGHT bound (1) violated by the 2 intermediates.
	f.subs[subKey("https://anchor.test/fetch", anchor.id, i2.id)] = subStmtC(t, anchor, i2,
		&federation.EntityConstraints{MaxPathLength: intPtr(1)})
	// A deeper LOOSE bound (5) cannot rescue the chain.
	f.subs[subKey("https://i2.test/fetch", i2.id, i1.id)] = subStmtC(t, i2, i1,
		&federation.EntityConstraints{MaxPathLength: intPtr(5)})
	f.subs[subKey("https://i1.test/fetch", i1.id, leaf.id)] = i1.subordinateStatement(t, leaf, nil)

	r := resolverFor(t, f, anchor)
	if _, err := r.ResolveTrustChain(context.Background(), leaf.id); !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("a deeper loose bound must not relax a higher tight one: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestConstraints_NegativeMaxPathLengthRejected: a malformed negative
// max_path_length (§6.2.1 requires >= 0) is fail-closed rejected, NOT silently
// treated as unlimited.
func TestConstraints_NegativeMaxPathLengthRejected(t *testing.T) {
	f, anchor, inter, leaf := buildLinearFederation(t, map[string]any{"client_name": "X"}, nil, nil)
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = subStmtC(t, anchor, inter,
		&federation.EntityConstraints{MaxPathLength: intPtr(-1)})

	r := resolverFor(t, f, anchor)
	if _, err := r.ResolveTrustChain(context.Background(), leaf.id); !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("negative max_path_length: err = %v, want ErrTrustChainInvalid", err)
	}
}

// ---------------------------------------------------------------------------
// naming_constraints (RFC 5280 §4.2.1.10, host component)
// ---------------------------------------------------------------------------

// TestConstraints_NamingPermittedSubtreeAccepted: a permitted subtree
// ".federation.test" admits the leaf host rp.federation.test (and the
// intermediate intermediate.federation.test) → accepted.
func TestConstraints_NamingPermittedSubtreeAccepted(t *testing.T) {
	f, anchor, inter, leaf := buildLinearFederation(t, map[string]any{"client_name": "X"}, nil, nil)
	// Anchor's statement about the intermediate constrains the whole subtree to
	// ".federation.test". Both inter (intermediate.federation.test) and the leaf
	// (rp.federation.test) are within it.
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = subStmtC(t, anchor, inter,
		&federation.EntityConstraints{NamingConstraints: &federation.NamingConstraints{
			Permitted: []string{".federation.test"},
		}})

	r := resolverFor(t, f, anchor)
	if _, err := r.ResolveTrustChain(context.Background(), leaf.id); err != nil {
		t.Fatalf("permitted subtree covering all subordinates should be accepted: %v", err)
	}
}

// TestConstraints_NamingPermittedExcludesForeignHost: a permitted subtree that
// does NOT cover the leaf host rejects the chain. ".example.com" does not admit
// rp.federation.test → rejected.
func TestConstraints_NamingPermittedExcludesForeignHost(t *testing.T) {
	f, anchor, inter, leaf := buildLinearFederation(t, map[string]any{"client_name": "X"}, nil, nil)
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = subStmtC(t, anchor, inter,
		&federation.EntityConstraints{NamingConstraints: &federation.NamingConstraints{
			Permitted: []string{".example.com"},
		}})

	r := resolverFor(t, f, anchor)
	if _, err := r.ResolveTrustChain(context.Background(), leaf.id); !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("leaf host outside the permitted subtree: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestConstraints_NamingExcludedBeatsPermitted: an excluded entry matching the
// leaf host rejects the chain even when a permitted entry would admit it
// (excluded beats permitted, §6.2.2). Permitted ".federation.test" admits the
// leaf, but excluded "rp.federation.test" (the exact leaf host) forbids it.
func TestConstraints_NamingExcludedBeatsPermitted(t *testing.T) {
	f, anchor, inter, leaf := buildLinearFederation(t, map[string]any{"client_name": "X"}, nil, nil)
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = subStmtC(t, anchor, inter,
		&federation.EntityConstraints{NamingConstraints: &federation.NamingConstraints{
			Permitted: []string{".federation.test"},
			Excluded:  []string{"rp.federation.test"},
		}})

	r := resolverFor(t, f, anchor)
	if _, err := r.ResolveTrustChain(context.Background(), leaf.id); !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("excluded host must reject despite permitted: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestConstraints_NamingSingleHostExactMatch: a permitted entry WITHOUT a
// leading dot is a single-host match. "rp.federation.test" admits the leaf
// exactly. The intermediate host (intermediate.federation.test) must ALSO be
// permitted, so we list both — proving the exact-host rule + multi-entry OR.
func TestConstraints_NamingSingleHostExactMatch(t *testing.T) {
	f, anchor, inter, leaf := buildLinearFederation(t, map[string]any{"client_name": "X"}, nil, nil)
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = subStmtC(t, anchor, inter,
		&federation.EntityConstraints{NamingConstraints: &federation.NamingConstraints{
			Permitted: []string{"rp.federation.test", "intermediate.federation.test"},
		}})

	r := resolverFor(t, f, anchor)
	if _, err := r.ResolveTrustChain(context.Background(), leaf.id); err != nil {
		t.Fatalf("exact single-host permitted entries should be accepted: %v", err)
	}
}

// TestConstraints_NamingBareDomainNotMatchedByDottedSubtree: the RFC 5280 rule
// that ".example.com" does NOT match the bare "example.com". A leaf whose host
// is exactly the bare domain "federation.test", under a permitted
// ".federation.test", is REJECTED (the dotted subtree requires at least one
// extra label in front).
func TestConstraints_NamingBareDomainNotMatchedByDottedSubtree(t *testing.T) {
	// A leaf whose host is the BARE domain federation.test.
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)
	leaf := newFedEntity(t, "https://federation.test") // bare domain host
	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)
	f.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, tcInterFch, nil)
	f.configs[leaf.id] = leaf.entityConfig(t, []string{inter.id}, "", map[string]any{"client_name": "X"})
	// Permit ".federation.test" (a dotted subtree) AND the intermediate's exact
	// host, so the ONLY failure is the bare-domain leaf not matching the subtree.
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = subStmtC(t, anchor, inter,
		&federation.EntityConstraints{NamingConstraints: &federation.NamingConstraints{
			Permitted: []string{".federation.test", "intermediate.federation.test"},
		}})
	f.subs[subKey(tcInterFch, inter.id, leaf.id)] = inter.subordinateStatement(t, leaf, nil)

	r := resolverFor(t, f, anchor)
	if _, err := r.ResolveTrustChain(context.Background(), leaf.id); !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("bare domain must NOT match a dotted subtree: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestConstraints_NamingSuffixIsNotSubstring: the RFC 5280 rule that the dotted
// subtree is a LABEL-boundary suffix, not a substring. ".example.com" must NOT
// admit "evil-example.com" (a different domain that merely ends in the same
// characters). A permitted ".rp.test" must NOT admit "evilrp.test".
func TestConstraints_NamingSuffixIsNotSubstring(t *testing.T) {
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, tcInterID)
	leaf := newFedEntity(t, "https://evilrp.test") // ends with "rp.test" but a different label
	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)
	f.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, tcInterFch, nil)
	f.configs[leaf.id] = leaf.entityConfig(t, []string{inter.id}, "", map[string]any{"client_name": "X"})
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = subStmtC(t, anchor, inter,
		&federation.EntityConstraints{NamingConstraints: &federation.NamingConstraints{
			Permitted: []string{".rp.test", "intermediate.federation.test"},
		}})
	f.subs[subKey(tcInterFch, inter.id, leaf.id)] = inter.subordinateStatement(t, leaf, nil)

	r := resolverFor(t, f, anchor)
	if _, err := r.ResolveTrustChain(context.Background(), leaf.id); !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("a non-label-boundary suffix must NOT match: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestConstraints_NamingAppliesToIntermediateNotJustLeaf: naming_constraints
// constrain the subject AND all entities subordinate to it (§3.1.3) — including
// intermediates, not just the leaf. An anchor's statement about i2 that permits
// only the leaf's host (excluding the intermediate hosts) is violated because
// the intermediate i1 below it is outside the permitted subtree → rejected.
func TestConstraints_NamingAppliesToIntermediateNotJustLeaf(t *testing.T) {
	anchor := newFedEntity(t, tcAnchorID)
	i2 := newFedEntity(t, "https://i2.elsewhere.test")
	i1 := newFedEntity(t, "https://i1.elsewhere.test")
	leaf := newFedEntity(t, tcLeafID) // rp.federation.test

	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, "https://anchor.test/fetch", nil)
	f.configs[i2.id] = i2.entityConfig(t, []string{anchor.id}, "https://i2.elsewhere.test/fetch", nil)
	f.configs[i1.id] = i1.entityConfig(t, []string{i2.id}, "https://i1.elsewhere.test/fetch", nil)
	f.configs[leaf.id] = leaf.entityConfig(t, []string{i1.id}, "", map[string]any{"client_name": "X"})
	// The anchor permits ONLY ".federation.test" — the leaf is within it, but the
	// intermediates i1/i2 (*.elsewhere.test) are NOT, and the constraint applies
	// to the whole subtree → rejected.
	f.subs[subKey("https://anchor.test/fetch", anchor.id, i2.id)] = subStmtC(t, anchor, i2,
		&federation.EntityConstraints{NamingConstraints: &federation.NamingConstraints{
			Permitted: []string{".federation.test"},
		}})
	f.subs[subKey("https://i2.elsewhere.test/fetch", i2.id, i1.id)] = i2.subordinateStatement(t, i1, nil)
	f.subs[subKey("https://i1.elsewhere.test/fetch", i1.id, leaf.id)] = i1.subordinateStatement(t, leaf, nil)

	r := resolverFor(t, f, anchor)
	if _, err := r.ResolveTrustChain(context.Background(), leaf.id); !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("naming_constraints must apply to intermediates too: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestConstraints_NamingDeeperCannotWidenHigher: a deeper statement's permitted
// list cannot WIDEN a higher statement's. The anchor permits only
// ".federation.test" (which the leaf rp.federation.test satisfies, but a foreign
// leaf would not); the intermediate's statement permits ".evil.test" too. With a
// leaf in evil.test, the anchor's narrower permit still rejects (independent
// application = intersection-equivalent).
func TestConstraints_NamingDeeperCannotWidenHigher(t *testing.T) {
	anchor := newFedEntity(t, tcAnchorID)
	inter := newFedEntity(t, "https://intermediate.federation.test")
	leaf := newFedEntity(t, "https://rp.evil.test") // in evil.test, NOT federation.test

	f := newFakeFetcher()
	f.configs[anchor.id] = anchor.entityConfig(t, nil, tcFetchURL, nil)
	f.configs[inter.id] = inter.entityConfig(t, []string{anchor.id}, tcInterFch, nil)
	f.configs[leaf.id] = leaf.entityConfig(t, []string{inter.id}, "", map[string]any{"client_name": "X"})
	// Anchor permits ONLY .federation.test (covers the intermediate, not the leaf).
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = subStmtC(t, anchor, inter,
		&federation.EntityConstraints{NamingConstraints: &federation.NamingConstraints{
			Permitted: []string{".federation.test"},
		}})
	// The intermediate tries to ALSO permit .evil.test (the leaf's domain) — but
	// the anchor's narrower constraint is independently enforced on the leaf.
	f.subs[subKey(tcInterFch, inter.id, leaf.id)] = subStmtC(t, inter, leaf,
		&federation.EntityConstraints{NamingConstraints: &federation.NamingConstraints{
			Permitted: []string{".federation.test", ".evil.test"},
		}})

	r := resolverFor(t, f, anchor)
	if _, err := r.ResolveTrustChain(context.Background(), leaf.id); !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("a deeper permitted list must not widen a higher one: err = %v, want ErrTrustChainInvalid", err)
	}
}

// ---------------------------------------------------------------------------
// allowed_entity_types
// ---------------------------------------------------------------------------

// TestConstraints_AllowedEntityTypesAdmitsRP: an allowed_entity_types listing
// openid_relying_party admits a leaf RP → accepted.
func TestConstraints_AllowedEntityTypesAdmitsRP(t *testing.T) {
	f, anchor, inter, leaf := buildLinearFederation(t, map[string]any{"client_name": "X"}, nil, nil)
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = subStmtC(t, anchor, inter,
		&federation.EntityConstraints{AllowedEntityTypes: strsPtr("openid_relying_party")})

	r := resolverFor(t, f, anchor)
	if _, err := r.ResolveTrustChain(context.Background(), leaf.id); err != nil {
		t.Fatalf("allowed_entity_types including openid_relying_party should admit an RP: %v", err)
	}
}

// TestConstraints_AllowedEntityTypesRejectsRP: an allowed_entity_types of only
// openid_provider (NOT openid_relying_party) rejects a leaf RP → rejected.
func TestConstraints_AllowedEntityTypesRejectsRP(t *testing.T) {
	f, anchor, inter, leaf := buildLinearFederation(t, map[string]any{"client_name": "X"}, nil, nil)
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = subStmtC(t, anchor, inter,
		&federation.EntityConstraints{AllowedEntityTypes: strsPtr("openid_provider")})

	r := resolverFor(t, f, anchor)
	if _, err := r.ResolveTrustChain(context.Background(), leaf.id); !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("an RP not in allowed_entity_types: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestConstraints_AllowedEntityTypesEmptyRejectsRP: an EMPTY allowed_entity_types
// array means ONLY federation_entity is allowed (§6.2.3), so a leaf RP is
// rejected. This is the pointer-distinguishes-[]-from-absent proof.
func TestConstraints_AllowedEntityTypesEmptyRejectsRP(t *testing.T) {
	f, anchor, inter, leaf := buildLinearFederation(t, map[string]any{"client_name": "X"}, nil, nil)
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = subStmtC(t, anchor, inter,
		&federation.EntityConstraints{AllowedEntityTypes: strsPtr()}) // present, empty

	r := resolverFor(t, f, anchor)
	if _, err := r.ResolveTrustChain(context.Background(), leaf.id); !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("empty allowed_entity_types ([] = only federation_entity) must reject an RP: err = %v, want ErrTrustChainInvalid", err)
	}
}

// TestConstraints_AllowedEntityTypesIntersection: independent application across
// two statements is intersection-equivalent. The anchor allows {RP, OP}; the
// intermediate allows only {OP}. The leaf RP must be rejected — the
// intermediate's narrower set is independently enforced and openid_relying_party
// is not in it.
func TestConstraints_AllowedEntityTypesIntersection(t *testing.T) {
	f, anchor, inter, leaf := buildLinearFederation(t, map[string]any{"client_name": "X"}, nil, nil)
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = subStmtC(t, anchor, inter,
		&federation.EntityConstraints{AllowedEntityTypes: strsPtr("openid_relying_party", "openid_provider")})
	// The intermediate's statement about the leaf narrows to OP only.
	f.subs[subKey(tcInterFch, inter.id, leaf.id)] = subStmtC(t, inter, leaf,
		&federation.EntityConstraints{AllowedEntityTypes: strsPtr("openid_provider")})

	r := resolverFor(t, f, anchor)
	if _, err := r.ResolveTrustChain(context.Background(), leaf.id); !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("a deeper narrower allowed_entity_types must win: err = %v, want ErrTrustChainInvalid", err)
	}
}

// ---------------------------------------------------------------------------
// COMBINED + NO-OP (the byte-identical-to-slice-2 proof)
// ---------------------------------------------------------------------------

// TestConstraints_AllSatisfiedAccepted: a chain whose statements carry ALL three
// constraints, all satisfied, validates AND still applies the metadata policy
// (proves the constraint step runs alongside, not instead of, the §10 policy).
func TestConstraints_AllSatisfiedAccepted(t *testing.T) {
	f, anchor, inter, leaf := buildLinearFederation(t, map[string]any{
		"client_name":   "Good RP",
		"redirect_uris": []any{"https://rp.federation.test/cb"},
	}, nil, nil)
	// Anchor->inter constraints: path<=2, subtree .federation.test, types {RP}.
	f.subs[subKey(tcFetchURL, anchor.id, inter.id)] = subStmtC(t, anchor, inter,
		&federation.EntityConstraints{
			MaxPathLength:      intPtr(2),
			NamingConstraints:  &federation.NamingConstraints{Permitted: []string{".federation.test"}},
			AllowedEntityTypes: strsPtr("openid_relying_party"),
		})

	r := resolverFor(t, f, anchor)
	chain, err := r.ResolveTrustChain(context.Background(), leaf.id)
	if err != nil {
		t.Fatalf("all-satisfied constraints should accept: %v", err)
	}
	if chain.ResolvedRPMetadata["client_name"] != "Good RP" {
		t.Errorf("resolved RP client_name = %v, want Good RP", chain.ResolvedRPMetadata["client_name"])
	}
	if len(chain.Statements) != 4 {
		t.Errorf("chain length = %d, want 4", len(chain.Statements))
	}
}

// TestConstraints_NoConstraintsNoOp: a chain carrying NO `constraints` anywhere
// validates EXACTLY as slice 2 — the constraint step is a no-op. This is the
// byte-identical proof (it mirrors the slice-2 happy path with no constraints).
func TestConstraints_NoConstraintsNoOp(t *testing.T) {
	f, anchor, _, leaf := buildLinearFederation(t, map[string]any{
		"client_name":   "Test RP",
		"redirect_uris": []any{"https://rp.federation.test/cb"},
	}, nil, nil)

	r := resolverFor(t, f, anchor)
	chain, err := r.ResolveTrustChain(context.Background(), leaf.id)
	if err != nil {
		t.Fatalf("no-constraints chain must validate as slice 2: %v", err)
	}
	if chain.LeafEntityID != leaf.id || chain.AnchorEntityID != anchor.id {
		t.Errorf("leaf/anchor = %q/%q, want %q/%q", chain.LeafEntityID, chain.AnchorEntityID, leaf.id, anchor.id)
	}
	if len(chain.Statements) != 4 {
		t.Errorf("chain length = %d, want 4 (unchanged from slice 2)", len(chain.Statements))
	}
	if chain.ResolvedRPMetadata["client_name"] != "Test RP" {
		t.Errorf("resolved RP client_name = %v, want Test RP", chain.ResolvedRPMetadata["client_name"])
	}
}
