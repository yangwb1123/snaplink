package tokenpolicy

import "github.com/goccy/go-yaml"

// policyFile is the on-disk YAML shape: a top-level `token_policies` list of
// [Policy] documents. Durations use Go duration strings (e.g. max_ttl: 15m)
// — goccy/go-yaml decodes those into the time.Duration fields directly, as
// the config package already relies on.
type policyFile struct {
	TokenPolicies []Policy `yaml:"token_policies"`
}

// UnmarshalYAML strict-decodes ONE policy item with DisallowUnknownField so
// a misspelled selector (e.g. tennat_id) fails load on every YAML surface —
// including the inline token_policies.policies path, where the config
// layer's whole-config lenient re-decode would otherwise drop the field
// before Validate can see it (SRE F2). The type alias strips the method so
// the inner decode is plain field-by-field (no recursion).
func (p *Policy) UnmarshalYAML(b []byte) error {
	type plain Policy
	var raw plain
	if err := yaml.UnmarshalWithOptions(b, &raw, yaml.DisallowUnknownField()); err != nil {
		return err
	}
	*p = Policy(raw)
	return nil
}

// ParseYAML loads a token-policy rule set from YAML bytes. The document is a
// list under `token_policies:`; each item maps to a [Policy] via its yaml
// tags. An empty/absent list yields a nil slice with no error (a valid
// "no policies" configuration). Strict by design: an unknown top-level key
// (previously tolerated as "no policies") and an unknown item field both
// fail the parse, and every item is shape-validated by [Validate]. Callers
// seed a [Store] (see ./memory) with the result.
func ParseYAML(data []byte) ([]Policy, error) {
	var f policyFile
	if err := yaml.UnmarshalWithOptions(data, &f, yaml.DisallowUnknownField()); err != nil {
		return nil, err
	}
	if err := Validate(f.TokenPolicies); err != nil {
		return nil, err
	}
	return f.TokenPolicies, nil
}
