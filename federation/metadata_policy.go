package federation

import (
	"fmt"
	"reflect"
	"sort"
)

// OpenID Federation 1.0 §10 — Metadata Policy. A superior constrains its
// subordinates' metadata via a metadata_policy on the Subordinate Statement it
// issues. Policies MERGE TOP-DOWN (trust anchor first, then each intermediate,
// then the leaf's immediate superior): a higher authority's constraint is
// AUTHORITATIVE and a lower one may only further restrict it, never relax it.
// A merge that CONFLICTS (e.g. two `value` operators disagree, or a narrower
// `one_of` excludes a pinned `value`) is an ERROR (§10.2). The merged policy is
// then APPLIED to the leaf's openid_relying_party metadata (§10.3); a leaf
// metadata that violates the merged policy (essential param missing, value
// mismatch, not within one_of/subset_of, etc.) is REJECTED.
//
// This is part of the trust boundary: a policy a superior set (e.g. pinning
// token_endpoint_auth_method to a sender-constrained method, or capping
// redirect_uris) must be ENFORCED before the leaf is admitted, and a forged
// subordinate policy that tries to LOOSEN a superior's constraint must be
// rejected at merge.
//
// Supported operators: value, add, default, one_of, subset_of, superset_of,
// essential (§5.1.1 / §10). An UNKNOWN operator is rejected (fail-closed — an
// operator we cannot interpret may be a constraint we would silently ignore).

const (
	opValue      = "value"
	opAdd        = "add"
	opDefault    = "default"
	opOneOf      = "one_of"
	opSubsetOf   = "subset_of"
	opSupersetOf = "superset_of"
	opEssential  = "essential"
)

// rpMetadataType is the metadata type whose policy the resolver applies. Slice
// 2 resolves RPs, so only openid_relying_party is enforced; other types (e.g.
// openid_provider) are carried but not applied here.
const rpMetadataType = "openid_relying_party"

// applyPolicy merges the metadata_policy from every Subordinate Statement in
// the chain (top-down) and applies the merged openid_relying_party policy to
// the leaf's RP metadata, returning the policy-applied metadata. A merge
// conflict or a leaf-metadata violation returns an error (the resolver maps it
// to ErrTrustChainInvalid).
//
// links is the canonical leaf-first chain: links[0] = leaf config, links[len-1]
// = anchor config; links[1..len-2] are the Subordinate Statements SS_1..SS_n
// (SS_1 just above the leaf, SS_n just below the anchor). To merge TOP-DOWN we
// walk the SS from the anchor end (SS_n) toward the leaf (SS_1): the highest
// authority's policy seeds the merge, lower ones combine in.
func (r *TrustChainResolver) applyPolicy(links []chainLink) (map[string]any, error) {
	// Collect Subordinate Statement policies in TOP-DOWN order (anchor-most
	// first). i runs len-2 (SS_n, just below the anchor config) down to 1 (SS_1,
	// just above the leaf config), so the first appended is the anchor-most
	// policy → top-down. The iss==sub guard is a defensive backstop (the
	// canonical chain has no self-signed link in this range).
	var policies []map[string]map[string]any
	for i := len(links) - 2; i >= 1; i-- {
		l := links[i]
		if l.claims.Iss == l.claims.Sub {
			continue
		}
		if pol, ok := l.claims.MetadataPolicy[rpMetadataType]; ok && len(pol) > 0 {
			policies = append(policies, pol)
		}
	}

	merged, err := mergePolicies(policies)
	if err != nil {
		return nil, err
	}

	// The leaf RP metadata (a copy so we never mutate the parsed statement).
	leaf := links[0]
	var rp map[string]any
	if leaf.claims.Metadata != nil && leaf.claims.Metadata.RP != nil {
		rp = cloneMetadata(leaf.claims.Metadata.RP)
	} else {
		rp = map[string]any{}
	}

	if err := enforcePolicy(merged, rp); err != nil {
		return nil, err
	}
	if len(rp) == 0 {
		return nil, nil
	}
	return rp, nil
}

// paramPolicy is the merged set of operators for one metadata parameter.
type paramPolicy map[string]any

// mergePolicies merges a TOP-DOWN-ordered slice of per-parameter policies
// (policies[0] is the highest authority). Per §10.2 each operator combines
// across levels with operator-specific rules; an incompatible combination is a
// conflict error.
func mergePolicies(policies []map[string]map[string]any) (map[string]paramPolicy, error) {
	out := map[string]paramPolicy{}
	for _, pol := range policies {
		for param, ops := range pol {
			cur := out[param]
			if cur == nil {
				cur = paramPolicy{}
			}
			for op, operand := range ops {
				if !isKnownOperator(op) {
					return nil, fmt.Errorf("metadata policy: unknown operator %q on %q", op, param)
				}
				combined, err := combineOperator(op, cur[op], operand, hasOp(cur, op))
				if err != nil {
					return nil, fmt.Errorf("metadata policy: merge conflict on %q.%s: %w", param, op, err)
				}
				cur[op] = combined
			}
			out[param] = cur
		}
	}
	// After merge, validate intra-parameter operator consistency (e.g. a pinned
	// `value` must satisfy `one_of`/`subset_of`; `default` must too).
	for param, pp := range out {
		if err := checkOperatorConsistency(param, pp); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func hasOp(pp paramPolicy, op string) bool {
	_, ok := pp[op]
	return ok
}

// combineOperator combines a previously-merged operand (present iff hasPrev)
// with a new (lower-authority) operand for the same operator, per §10.2.
func combineOperator(op string, prev any, next any, hasPrev bool) (any, error) {
	switch op {
	case opValue, opDefault:
		// Both levels setting value/default MUST agree (a lower authority cannot
		// override a higher one's pinned value).
		if hasPrev && !valuesEqual(prev, next) {
			return nil, fmt.Errorf("conflicting %s (%v vs %v)", op, prev, next)
		}
		return next, nil
	case opEssential:
		// essential merges by logical OR: once a superior requires the param,
		// a subordinate cannot relax it.
		pb, _ := prev.(bool)
		nb, ok := next.(bool)
		if !ok {
			return nil, fmt.Errorf("essential must be a boolean, got %T", next)
		}
		return pb || nb, nil
	case opAdd:
		// add: UNION of the value lists (every authority's additions apply).
		return unionStringSlices(prev, next)
	case opSupersetOf:
		// superset_of: UNION (the resulting required-subset grows as authorities
		// each demand their members be present).
		return unionStringSlices(prev, next)
	case opOneOf:
		// one_of: INTERSECTION (each authority narrows the allowed set). Empty
		// intersection = irreconcilable = conflict.
		return intersectStringSlices(op, prev, next, hasPrev)
	case opSubsetOf:
		// subset_of: INTERSECTION (each authority narrows the permitted set).
		return intersectStringSlices(op, prev, next, hasPrev)
	default:
		return nil, fmt.Errorf("unsupported operator %q", op)
	}
}

// intersectStringSlices intersects two string-list operands (one_of /
// subset_of merge). An empty result is a conflict (no value can satisfy both
// authorities). When there is no previous operand, next stands alone.
func intersectStringSlices(op string, prev, next any, hasPrev bool) (any, error) {
	ns, err := toStringSlice(next)
	if err != nil {
		return nil, fmt.Errorf("%s operand: %w", op, err)
	}
	if !hasPrev {
		return ns, nil
	}
	ps, err := toStringSlice(prev)
	if err != nil {
		return nil, fmt.Errorf("%s operand: %w", op, err)
	}
	set := map[string]struct{}{}
	for _, p := range ps {
		set[p] = struct{}{}
	}
	var inter []string
	for _, n := range ns {
		if _, ok := set[n]; ok {
			inter = append(inter, n)
		}
	}
	if len(inter) == 0 {
		return nil, fmt.Errorf("%s intersection is empty (%v vs %v)", op, ps, ns)
	}
	return inter, nil
}

// unionStringSlices unions two string-list operands (add / superset_of merge).
func unionStringSlices(prev, next any) (any, error) {
	ns, err := toStringSlice(next)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []string
	if prev != nil {
		ps, err := toStringSlice(prev)
		if err != nil {
			return nil, err
		}
		for _, p := range ps {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		}
	}
	for _, n := range ns {
		if _, ok := seen[n]; !ok {
			seen[n] = struct{}{}
			out = append(out, n)
		}
	}
	return out, nil
}

// checkOperatorConsistency validates the merged operators for one parameter are
// mutually satisfiable (§10.2): a pinned `value` must be within `one_of` /
// `subset_of` / `superset_of`; a `default` must satisfy the same constraints;
// `subset_of` must be reconcilable with `superset_of`.
func checkOperatorConsistency(param string, pp paramPolicy) error {
	if v, ok := pp[opValue]; ok {
		if err := valueSatisfiesConstraints(param, opValue, v, pp); err != nil {
			return err
		}
	}
	if d, ok := pp[opDefault]; ok {
		if err := valueSatisfiesConstraints(param, opDefault, d, pp); err != nil {
			return err
		}
	}
	// subset_of ∩ superset_of: every superset_of member must be allowed by
	// subset_of (else the param can satisfy neither).
	if sub, ok := pp[opSubsetOf]; ok {
		if sup, ok2 := pp[opSupersetOf]; ok2 {
			subset, err := toStringSlice(sub)
			if err != nil {
				return fmt.Errorf("metadata policy: %q subset_of: %w", param, err)
			}
			superset, err := toStringSlice(sup)
			if err != nil {
				return fmt.Errorf("metadata policy: %q superset_of: %w", param, err)
			}
			allowed := map[string]struct{}{}
			for _, s := range subset {
				allowed[s] = struct{}{}
			}
			for _, s := range superset {
				if _, ok := allowed[s]; !ok {
					return fmt.Errorf("metadata policy: %q superset_of member %q not permitted by subset_of", param, s)
				}
			}
		}
	}
	return nil
}

// valueSatisfiesConstraints checks a scalar-or-list operand (a value/default)
// against the one_of/subset_of/superset_of constraints in the same param
// policy. one_of constrains a SCALAR; subset_of/superset_of constrain a LIST.
func valueSatisfiesConstraints(param, label string, operand any, pp paramPolicy) error {
	if oneOf, ok := pp[opOneOf]; ok {
		allowed, err := toStringSlice(oneOf)
		if err != nil {
			return fmt.Errorf("metadata policy: %q one_of: %w", param, err)
		}
		s, ok := operand.(string)
		if !ok {
			return fmt.Errorf("metadata policy: %q %s must be a string to satisfy one_of, got %T", param, label, operand)
		}
		if !containsString(allowed, s) {
			return fmt.Errorf("metadata policy: %q %s %q not in one_of %v", param, label, s, allowed)
		}
	}
	if sub, ok := pp[opSubsetOf]; ok {
		allowed, err := toStringSlice(sub)
		if err != nil {
			return fmt.Errorf("metadata policy: %q subset_of: %w", param, err)
		}
		vals, err := toStringSlice(operand)
		if err != nil {
			return fmt.Errorf("metadata policy: %q %s must be a list to satisfy subset_of: %w", param, label, err)
		}
		for _, v := range vals {
			if !containsString(allowed, v) {
				return fmt.Errorf("metadata policy: %q %s value %q not in subset_of %v", param, label, v, allowed)
			}
		}
	}
	if sup, ok := pp[opSupersetOf]; ok {
		required, err := toStringSlice(sup)
		if err != nil {
			return fmt.Errorf("metadata policy: %q superset_of: %w", param, err)
		}
		vals, err := toStringSlice(operand)
		if err != nil {
			return fmt.Errorf("metadata policy: %q %s must be a list to satisfy superset_of: %w", param, label, err)
		}
		have := map[string]struct{}{}
		for _, v := range vals {
			have[v] = struct{}{}
		}
		for _, req := range required {
			if _, ok := have[req]; !ok {
				return fmt.Errorf("metadata policy: %q %s missing superset_of member %q", param, label, req)
			}
		}
	}
	return nil
}

// enforcePolicy applies the merged policy to the leaf RP metadata in place,
// per §10.3 ordering: value, then add, then default (modifiers), then the
// constraints one_of / subset_of / superset_of, then essential (presence).
// Any violation returns an error (the leaf is rejected). rp is mutated.
func enforcePolicy(merged map[string]paramPolicy, rp map[string]any) error {
	// Deterministic param order for stable error reporting.
	params := make([]string, 0, len(merged))
	for p := range merged {
		params = append(params, p)
	}
	sort.Strings(params)

	for _, param := range params {
		pp := merged[param]

		// value: pin the param (overrides whatever the leaf asserted).
		if v, ok := pp[opValue]; ok {
			rp[param] = v
		}
		// add: append the operands to the (list) param.
		if a, ok := pp[opAdd]; ok {
			additions, err := toStringSlice(a)
			if err != nil {
				return fmt.Errorf("metadata policy: %q add: %w", param, err)
			}
			rp[param] = appendUnique(rp[param], additions)
		}
		// default: fill the param if absent.
		if d, ok := pp[opDefault]; ok {
			if _, present := rp[param]; !present {
				rp[param] = d
			}
		}

		// one_of: the (scalar) value MUST be one of the set.
		if oneOf, ok := pp[opOneOf]; ok {
			if cur, present := rp[param]; present {
				allowed, err := toStringSlice(oneOf)
				if err != nil {
					return fmt.Errorf("metadata policy: %q one_of: %w", param, err)
				}
				s, ok := cur.(string)
				if !ok {
					return fmt.Errorf("metadata policy: %q value must be a string for one_of, got %T", param, cur)
				}
				if !containsString(allowed, s) {
					return fmt.Errorf("metadata policy: %q value %q violates one_of %v", param, s, allowed)
				}
			}
		}
		// subset_of: the (list) value MUST be a subset of the set.
		if sub, ok := pp[opSubsetOf]; ok {
			if cur, present := rp[param]; present {
				allowed, err := toStringSlice(sub)
				if err != nil {
					return fmt.Errorf("metadata policy: %q subset_of: %w", param, err)
				}
				vals, err := toStringSlice(cur)
				if err != nil {
					return fmt.Errorf("metadata policy: %q value must be a list for subset_of: %w", param, err)
				}
				for _, v := range vals {
					if !containsString(allowed, v) {
						return fmt.Errorf("metadata policy: %q value %q violates subset_of %v", param, v, allowed)
					}
				}
			}
		}
		// superset_of: the (list) value MUST contain all required members.
		if sup, ok := pp[opSupersetOf]; ok {
			if cur, present := rp[param]; present {
				required, err := toStringSlice(sup)
				if err != nil {
					return fmt.Errorf("metadata policy: %q superset_of: %w", param, err)
				}
				vals, err := toStringSlice(cur)
				if err != nil {
					return fmt.Errorf("metadata policy: %q value must be a list for superset_of: %w", param, err)
				}
				have := map[string]struct{}{}
				for _, v := range vals {
					have[v] = struct{}{}
				}
				for _, req := range required {
					if _, ok := have[req]; !ok {
						return fmt.Errorf("metadata policy: %q value missing required %q (superset_of)", param, req)
					}
				}
			}
		}
		// essential: the param MUST be present (after the modifiers above).
		if e, ok := pp[opEssential]; ok {
			if eb, _ := e.(bool); eb {
				if _, present := rp[param]; !present {
					return fmt.Errorf("metadata policy: essential parameter %q is missing", param)
				}
			}
		}
	}
	return nil
}

// --- value helpers (JSON-decoded operands are string / []any / bool) ---

func isKnownOperator(op string) bool {
	switch op {
	case opValue, opAdd, opDefault, opOneOf, opSubsetOf, opSupersetOf, opEssential:
		return true
	default:
		return false
	}
}

// valuesEqual compares two JSON-decoded operands for the value/default merge
// agreement check. Uses reflect.DeepEqual after normalizing JSON number/string
// shapes (operands come straight from encoding/json, so like-typed values
// compare directly).
func valuesEqual(a, b any) bool {
	return reflect.DeepEqual(a, b)
}

// toStringSlice coerces a JSON-decoded operand into a []string. Accepts a
// []string, a []any of strings (the encoding/json shape), or a single string
// (treated as a 1-element list). Anything else is an error (fail-closed — a
// malformed operand must not be silently treated as empty).
func toStringSlice(v any) ([]string, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case []string:
		return t, nil
	case string:
		return []string{t}, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("list element %v is not a string", e)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("operand %v (%T) is not a string or string list", v, v)
	}
}

func containsString(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// appendUnique appends additions to an existing (list) metadata value,
// de-duplicating. A non-list existing value is replaced by the additions
// (the add operator targets list-valued parameters; a scalar present value is
// treated as the empty base, matching the "append to a set" intent).
func appendUnique(existing any, additions []string) []string {
	seen := map[string]struct{}{}
	var out []string
	if cur, err := toStringSlice(existing); err == nil {
		for _, c := range cur {
			if _, ok := seen[c]; !ok {
				seen[c] = struct{}{}
				out = append(out, c)
			}
		}
	}
	for _, a := range additions {
		if _, ok := seen[a]; !ok {
			seen[a] = struct{}{}
			out = append(out, a)
		}
	}
	return out
}

// cloneMetadata shallow-copies the leaf RP metadata map so policy application
// never mutates the parsed statement (the resolver returns a fresh map).
func cloneMetadata(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
