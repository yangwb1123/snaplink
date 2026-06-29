package federation_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/snaplink/sso/domains/federation"
)

// Metadata-policy tests drive the §10 engine through the resolver: a valid
// anchor->inter->leaf chain carries a metadata_policy on the subordinate
// statements (anchorPolicy = anchor about inter; interPolicy = inter about
// leaf). The leaf's RP metadata is then policy-applied (or rejected). All
// signatures/expiry are valid, so the ONLY variable under test is the policy.

// policy is a tiny helper to build the nested metadata_policy shape for
// openid_relying_party: param -> operator -> operand.
func policy(params map[string]map[string]any) map[string]map[string]map[string]any {
	return map[string]map[string]map[string]any{"openid_relying_party": params}
}

func resolveWithPolicy(t *testing.T, leafRP map[string]any, interPolicy map[string]map[string]map[string]any) (*federation.TrustChain, error) {
	t.Helper()
	f, anchor, _, leaf := buildLinearFederation(t, leafRP, nil, interPolicy)
	r := resolverFor(t, f, anchor)
	return r.ResolveTrustChain(context.Background(), leaf.id)
}

func resolveWithMergedPolicy(t *testing.T, leafRP map[string]any, anchorPolicy, interPolicy map[string]map[string]map[string]any) (*federation.TrustChain, error) {
	t.Helper()
	f, anchor, _, leaf := buildLinearFederation(t, leafRP, anchorPolicy, interPolicy)
	r := resolverFor(t, f, anchor)
	return r.ResolveTrustChain(context.Background(), leaf.id)
}

// --- value ---

func TestPolicy_Value_Pins(t *testing.T) {
	t.Parallel()
	chain, err := resolveWithPolicy(t,
		map[string]any{"token_endpoint_auth_method": "client_secret_basic"},
		policy(map[string]map[string]any{
			"token_endpoint_auth_method": {"value": "private_key_jwt"},
		}),
	)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// value OVERRIDES the leaf's self-asserted method.
	if got := chain.ResolvedRPMetadata["token_endpoint_auth_method"]; got != "private_key_jwt" {
		t.Errorf("value not pinned: got %v, want private_key_jwt", got)
	}
}

// --- default ---

func TestPolicy_Default_FillsWhenAbsent(t *testing.T) {
	t.Parallel()
	chain, err := resolveWithPolicy(t,
		map[string]any{"client_name": "RP"}, // no token_endpoint_auth_method
		policy(map[string]map[string]any{
			"token_endpoint_auth_method": {"default": "client_secret_basic"},
		}),
	)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := chain.ResolvedRPMetadata["token_endpoint_auth_method"]; got != "client_secret_basic" {
		t.Errorf("default not applied: got %v", got)
	}
}

func TestPolicy_Default_DoesNotOverridePresent(t *testing.T) {
	t.Parallel()
	chain, err := resolveWithPolicy(t,
		map[string]any{"token_endpoint_auth_method": "private_key_jwt"},
		policy(map[string]map[string]any{
			"token_endpoint_auth_method": {"default": "client_secret_basic"},
		}),
	)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := chain.ResolvedRPMetadata["token_endpoint_auth_method"]; got != "private_key_jwt" {
		t.Errorf("default overrode a present value: got %v", got)
	}
}

// --- add ---

func TestPolicy_Add_Appends(t *testing.T) {
	t.Parallel()
	chain, err := resolveWithPolicy(t,
		map[string]any{"grant_types": []any{"authorization_code"}},
		policy(map[string]map[string]any{
			"grant_types": {"add": []any{"refresh_token"}},
		}),
	)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got, _ := chain.ResolvedRPMetadata["grant_types"].([]string)
	if !reflect.DeepEqual(got, []string{"authorization_code", "refresh_token"}) {
		t.Errorf("add: got %v, want [authorization_code refresh_token]", got)
	}
}

// --- one_of ---

func TestPolicy_OneOf_AllowsMember(t *testing.T) {
	t.Parallel()
	_, err := resolveWithPolicy(t,
		map[string]any{"subject_type": "pairwise"},
		policy(map[string]map[string]any{
			"subject_type": {"one_of": []any{"public", "pairwise"}},
		}),
	)
	if err != nil {
		t.Fatalf("one_of member should pass: %v", err)
	}
}

func TestPolicy_OneOf_RejectsNonMember(t *testing.T) {
	t.Parallel()
	_, err := resolveWithPolicy(t,
		map[string]any{"subject_type": "global"},
		policy(map[string]map[string]any{
			"subject_type": {"one_of": []any{"public", "pairwise"}},
		}),
	)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("one_of non-member: err = %v, want ErrTrustChainInvalid", err)
	}
}

// --- subset_of ---

func TestPolicy_SubsetOf_RejectsOutOfSet(t *testing.T) {
	t.Parallel()
	_, err := resolveWithPolicy(t,
		map[string]any{"grant_types": []any{"authorization_code", "implicit"}},
		policy(map[string]map[string]any{
			"grant_types": {"subset_of": []any{"authorization_code", "refresh_token"}},
		}),
	)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("subset_of violation: err = %v, want ErrTrustChainInvalid", err)
	}
}

func TestPolicy_SubsetOf_AllowsSubset(t *testing.T) {
	t.Parallel()
	_, err := resolveWithPolicy(t,
		map[string]any{"grant_types": []any{"authorization_code"}},
		policy(map[string]map[string]any{
			"grant_types": {"subset_of": []any{"authorization_code", "refresh_token"}},
		}),
	)
	if err != nil {
		t.Fatalf("subset_of subset should pass: %v", err)
	}
}

// --- superset_of ---

func TestPolicy_SupersetOf_RejectsMissingRequired(t *testing.T) {
	t.Parallel()
	_, err := resolveWithPolicy(t,
		map[string]any{"grant_types": []any{"authorization_code"}},
		policy(map[string]map[string]any{
			"grant_types": {"superset_of": []any{"authorization_code", "refresh_token"}},
		}),
	)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("superset_of missing required: err = %v, want ErrTrustChainInvalid", err)
	}
}

// --- essential ---

func TestPolicy_Essential_RejectsMissing(t *testing.T) {
	t.Parallel()
	_, err := resolveWithPolicy(t,
		map[string]any{"client_name": "RP"}, // no contacts
		policy(map[string]map[string]any{
			"contacts": {"essential": true},
		}),
	)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("essential missing: err = %v, want ErrTrustChainInvalid", err)
	}
}

func TestPolicy_Essential_PassesWhenPresent(t *testing.T) {
	t.Parallel()
	_, err := resolveWithPolicy(t,
		map[string]any{"contacts": []any{"mailto:admin@rp.test"}},
		policy(map[string]map[string]any{
			"contacts": {"essential": true},
		}),
	)
	if err != nil {
		t.Fatalf("essential present should pass: %v", err)
	}
}

// essential satisfied via a default fill (default runs before the essential
// check, §10.3 ordering).
func TestPolicy_Essential_SatisfiedByDefault(t *testing.T) {
	t.Parallel()
	chain, err := resolveWithPolicy(t,
		map[string]any{"client_name": "RP"},
		policy(map[string]map[string]any{
			"token_endpoint_auth_method": {
				"default":   "client_secret_basic",
				"essential": true,
			},
		}),
	)
	if err != nil {
		t.Fatalf("essential-via-default should pass: %v", err)
	}
	if got := chain.ResolvedRPMetadata["token_endpoint_auth_method"]; got != "client_secret_basic" {
		t.Errorf("default not applied before essential: got %v", got)
	}
}

// ===========================================================================
// MERGE (top-down) + MERGE CONFLICT
// ===========================================================================

// A higher authority (anchor) and a lower one (intermediate) both pin `value`
// to DIFFERENT values → merge conflict → rejected (§10.2).
func TestPolicy_MergeConflict_ValueDisagrees(t *testing.T) {
	t.Parallel()
	_, err := resolveWithMergedPolicy(t,
		map[string]any{"token_endpoint_auth_method": "private_key_jwt"},
		policy(map[string]map[string]any{ // anchor about inter
			"token_endpoint_auth_method": {"value": "private_key_jwt"},
		}),
		policy(map[string]map[string]any{ // inter about leaf
			"token_endpoint_auth_method": {"value": "client_secret_basic"},
		}),
	)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("conflicting value merge: err = %v, want ErrTrustChainInvalid", err)
	}
}

// A higher authority's `value` pin may NOT be widened by a subordinate's `add`
// (OpenID Federation §5.1.2): the anchor pins redirect_uris to one callback; a
// compromised intermediate tries to append an attacker callback. The merge must
// fail the chain closed (ErrTrustChainInvalid), not silently union the two.
func TestPolicy_MergeConflict_ValuePlusAddRejected(t *testing.T) {
	t.Parallel()
	_, err := resolveWithMergedPolicy(t,
		map[string]any{"redirect_uris": []any{"https://rp.example/cb"}},
		policy(map[string]map[string]any{ // anchor about inter: pin
			"redirect_uris": {"value": []any{"https://rp.example/cb"}},
		}),
		policy(map[string]map[string]any{ // inter about leaf: compromised widen
			"redirect_uris": {"add": []any{"https://attacker.evil/cb"}},
		}),
	)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("value+add merge must fail closed (no widening past the anchor pin): err = %v, want ErrTrustChainInvalid", err)
	}
}

// one_of merges by intersection; disjoint sets → empty intersection → conflict.
func TestPolicy_MergeConflict_OneOfDisjoint(t *testing.T) {
	t.Parallel()
	_, err := resolveWithMergedPolicy(t,
		map[string]any{"subject_type": "public"},
		policy(map[string]map[string]any{
			"subject_type": {"one_of": []any{"public"}},
		}),
		policy(map[string]map[string]any{
			"subject_type": {"one_of": []any{"pairwise"}},
		}),
	)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("disjoint one_of merge: err = %v, want ErrTrustChainInvalid", err)
	}
}

// one_of merges by intersection; overlapping sets narrow to the intersection,
// and a leaf value in the intersection passes.
func TestPolicy_Merge_OneOfIntersectionNarrows(t *testing.T) {
	t.Parallel()
	// anchor allows {public, pairwise}; inter allows {pairwise, global};
	// intersection = {pairwise}. Leaf=pairwise passes.
	_, err := resolveWithMergedPolicy(t,
		map[string]any{"subject_type": "pairwise"},
		policy(map[string]map[string]any{
			"subject_type": {"one_of": []any{"public", "pairwise"}},
		}),
		policy(map[string]map[string]any{
			"subject_type": {"one_of": []any{"pairwise", "global"}},
		}),
	)
	if err != nil {
		t.Fatalf("intersection member should pass: %v", err)
	}

	// Leaf=public is excluded by the inter narrowing → rejected.
	_, err = resolveWithMergedPolicy(t,
		map[string]any{"subject_type": "public"},
		policy(map[string]map[string]any{
			"subject_type": {"one_of": []any{"public", "pairwise"}},
		}),
		policy(map[string]map[string]any{
			"subject_type": {"one_of": []any{"pairwise", "global"}},
		}),
	)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("value excluded by narrowed one_of: err = %v, want ErrTrustChainInvalid", err)
	}
}

// essential merges by OR: a superior requiring essential cannot be relaxed by a
// subordinate setting essential:false.
func TestPolicy_Merge_EssentialCannotBeRelaxed(t *testing.T) {
	t.Parallel()
	_, err := resolveWithMergedPolicy(t,
		map[string]any{"client_name": "RP"}, // contacts missing
		policy(map[string]map[string]any{ // anchor: contacts essential
			"contacts": {"essential": true},
		}),
		policy(map[string]map[string]any{ // inter tries to relax
			"contacts": {"essential": false},
		}),
	)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("essential relaxation: err = %v, want ErrTrustChainInvalid (essential stays true)", err)
	}
}

// A pinned `value` inconsistent with a merged `one_of` (value not in one_of) is
// a consistency error at merge.
func TestPolicy_MergeConflict_ValueNotInOneOf(t *testing.T) {
	t.Parallel()
	_, err := resolveWithMergedPolicy(t,
		map[string]any{"subject_type": "public"},
		policy(map[string]map[string]any{
			"subject_type": {"value": "public"},
		}),
		policy(map[string]map[string]any{
			"subject_type": {"one_of": []any{"pairwise", "global"}},
		}),
	)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("value-not-in-one_of: err = %v, want ErrTrustChainInvalid", err)
	}
}

// An unknown operator is rejected (fail-closed).
func TestPolicy_UnknownOperatorRejected(t *testing.T) {
	t.Parallel()
	_, err := resolveWithPolicy(t,
		map[string]any{"client_name": "RP"},
		policy(map[string]map[string]any{
			"client_name": {"regexp": "evil.*"},
		}),
	)
	if !errors.Is(err, federation.ErrTrustChainInvalid) {
		t.Fatalf("unknown operator: err = %v, want ErrTrustChainInvalid", err)
	}
}

// No policy anywhere → the leaf RP metadata passes through unchanged.
func TestPolicy_NoPolicy_PassThrough(t *testing.T) {
	t.Parallel()
	chain, err := resolveWithPolicy(t,
		map[string]any{"client_name": "RP", "subject_type": "public"},
		nil,
	)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if chain.ResolvedRPMetadata["client_name"] != "RP" || chain.ResolvedRPMetadata["subject_type"] != "public" {
		t.Errorf("RP metadata altered without policy: %v", chain.ResolvedRPMetadata)
	}
}
