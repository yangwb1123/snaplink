package tokenpolicy

import "github.com/goccy/go-yaml"

// policyFile is the on-disk YAML shape: a top-level `token_policies` list of
// [Policy] documents. Durations use Go duration strings (e.g. max_ttl: 15m)
// — goccy/go-yaml decodes those into the time.Duration fields directly, as
// the config package already relies on.
type policyFile struct {
	TokenPolicies []Policy `yaml:"token_policies"`
}

// ParseYAML loads a token-policy rule set from YAML bytes. The document is a
// list under `token_policies:`; each item maps to a [Policy] via its yaml
// tags. An empty/absent list yields a nil slice with no error (a valid
// "no policies" configuration). Callers seed a [Store] (see ./memory) with
// the result.
func ParseYAML(data []byte) ([]Policy, error) {
	var f policyFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return f.TokenPolicies, nil
}
