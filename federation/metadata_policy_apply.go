package federation

import "fmt"

// OpenID Federation 1.0 §10.3 — APPLYING the merged metadata policy to the
// leaf RP metadata, plus the §10.2 intra-parameter operand-satisfaction checks
// (checkOperatorConsistency). Split out of metadata_policy.go so each operator
// is a small, independently-budgeted helper while the merge/consistency logic
// stays alongside the policy types. Behavior is identical: applyParamPolicy
// runs the §10.3 ordering (modifiers, then constraints, then essential) and the
// operandSatisfies* helpers feed valueSatisfiesConstraints.

// applyParamPolicy applies one parameter's merged operators to rp in §10.3
// order: the modifiers (value, add, default) that may CHANGE the value, then
// the constraints (one_of, subset_of, superset_of) that validate it, then
// essential (presence). rp is mutated. Any violation is returned.
func applyParamPolicy(param string, pp paramPolicy, rp map[string]any) error {
	if err := applyParamModifiers(param, pp, rp); err != nil {
		return err
	}
	if err := applyParamConstraints(param, pp, rp); err != nil {
		return err
	}
	return applyParamEssential(param, pp, rp)
}

// applyParamModifiers applies the value/add/default operators (§10.3), which
// may change the param's value before the constraints validate it.
func applyParamModifiers(param string, pp paramPolicy, rp map[string]any) error {
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
	return nil
}

// applyParamConstraints validates the (possibly modified) param value against
// the one_of/subset_of/superset_of operators (§10.3). A constraint over an
// ABSENT param is a no-op (there is nothing to validate yet).
func applyParamConstraints(param string, pp paramPolicy, rp map[string]any) error {
	if err := applyOneOf(param, pp, rp); err != nil {
		return err
	}
	if err := applySubsetOf(param, pp, rp); err != nil {
		return err
	}
	return applySupersetOf(param, pp, rp)
}

// applyOneOf enforces one_of: the (scalar) value MUST be one of the set.
func applyOneOf(param string, pp paramPolicy, rp map[string]any) error {
	oneOf, ok := pp[opOneOf]
	if !ok {
		return nil
	}
	cur, present := rp[param]
	if !present {
		return nil
	}
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
	return nil
}

// applySubsetOf enforces subset_of: the (list) value MUST be a subset of the set.
func applySubsetOf(param string, pp paramPolicy, rp map[string]any) error {
	sub, ok := pp[opSubsetOf]
	if !ok {
		return nil
	}
	cur, present := rp[param]
	if !present {
		return nil
	}
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
	return nil
}

// applySupersetOf enforces superset_of: the (list) value MUST contain all
// required members.
func applySupersetOf(param string, pp paramPolicy, rp map[string]any) error {
	sup, ok := pp[opSupersetOf]
	if !ok {
		return nil
	}
	cur, present := rp[param]
	if !present {
		return nil
	}
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
	return nil
}

// applyParamEssential enforces essential: the param MUST be present after the
// modifiers above filled/pinned it.
func applyParamEssential(param string, pp paramPolicy, rp map[string]any) error {
	e, ok := pp[opEssential]
	if !ok {
		return nil
	}
	if eb, _ := e.(bool); eb {
		if _, present := rp[param]; !present {
			return fmt.Errorf("metadata policy: essential parameter %q is missing", param)
		}
	}
	return nil
}

// operandSatisfiesOneOf checks a SCALAR operand against the one_of constraint
// (for checkOperatorConsistency / valueSatisfiesConstraints).
func operandSatisfiesOneOf(param, label string, operand any, pp paramPolicy) error {
	oneOf, ok := pp[opOneOf]
	if !ok {
		return nil
	}
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
	return nil
}

// operandSatisfiesSubsetOf checks a LIST operand against the subset_of constraint.
func operandSatisfiesSubsetOf(param, label string, operand any, pp paramPolicy) error {
	sub, ok := pp[opSubsetOf]
	if !ok {
		return nil
	}
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
	return nil
}

// operandSatisfiesSupersetOf checks a LIST operand against the superset_of constraint.
func operandSatisfiesSupersetOf(param, label string, operand any, pp paramPolicy) error {
	sup, ok := pp[opSupersetOf]
	if !ok {
		return nil
	}
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
	return nil
}
