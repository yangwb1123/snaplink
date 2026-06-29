package metadatapolicy

import (
	"fmt"
	"reflect"
	"sort"
)

const (
	opValue      = "value"
	opAdd        = "add"
	opDefault    = "default"
	opOneOf      = "one_of"
	opSubsetOf   = "subset_of"
	opSupersetOf = "superset_of"
	opEssential  = "essential"
)

// paramPolicy is the merged set of operators for one metadata parameter.
type paramPolicy map[string]any

// MergePolicies merges a TOP-DOWN-ordered slice of per-parameter policies
// (policies[0] is the highest authority). Per §10.2 each operator combines
// across levels with operator-specific rules; an incompatible combination is a
// conflict error.
func MergePolicies(policies []map[string]map[string]any) (map[string]paramPolicy, error) {
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
	// Security (OpenID Federation 1.0 §5.1.2): a higher authority's pinned `value`
	// must be the final, NARROWING word. EnforcePolicy applies modifiers in the
	// order value (overwrite) then add (append), and nothing re-validates after
	// add, so a subordinate authority's `add` for the same parameter silently
	// WIDENS the pin (a compromised intermediate appends an attacker redirect_uri
	// past a trust anchor's value-pin -> auth-code interception). Reject the
	// combination so a malicious subordinate fails the chain closed instead of
	// escalating. (value+one_of/subset_of/superset_of stay allowed below: those
	// constraints re-validate the result, so unlike add they cannot widen a pin.)
	if _, pinned := pp[opValue]; pinned {
		if _, widened := pp[opAdd]; widened {
			return fmt.Errorf("metadata policy: %q value may not be combined with add (a subordinate add cannot widen a pinned value)", param)
		}
	}
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
	if err := operandSatisfiesOneOf(param, label, operand, pp); err != nil {
		return err
	}
	if err := operandSatisfiesSubsetOf(param, label, operand, pp); err != nil {
		return err
	}
	return operandSatisfiesSupersetOf(param, label, operand, pp)
}

// EnforcePolicy applies the merged policy to the leaf RP metadata in place,
// per §10.3 ordering: value, then add, then default (modifiers), then the
// constraints one_of / subset_of / superset_of, then essential (presence).
// Any violation returns an error (the leaf is rejected). rp is mutated.
func EnforcePolicy(merged map[string]paramPolicy, rp map[string]any) error {
	// Deterministic param order for stable error reporting.
	params := make([]string, 0, len(merged))
	for p := range merged {
		params = append(params, p)
	}
	sort.Strings(params)

	for _, param := range params {
		if err := applyParamPolicy(param, merged[param], rp); err != nil {
			return err
		}
	}
	return nil
}

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

// CloneMetadata shallow-copies the leaf RP metadata map so policy application
// never mutates the parsed statement (the resolver returns a fresh map).
func CloneMetadata(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
