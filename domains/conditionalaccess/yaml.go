package conditionalaccess

import (
	"context"
	"fmt"

	"github.com/goccy/go-yaml"
)

// policyDoc is the top-level shape of a policy YAML bundle:
//
//	policies:
//	  - name: restrict-admin-access
//	    priority: 100
//	    enabled: true
//	    conditions:
//	      user.member_of: ["admin"]
//	      device.managed: false
//	      risk_score: "> 0.5"
//	    actions:
//	      require_step_up: mfa
//	      restrict_scopes: ["admin:read"]
type policyDoc struct {
	Policies []Policy `yaml:"policies"`
}

// LoadPolicies parses a YAML policy bundle and validates every policy. Unknown
// fields are rejected so a typo in a rule fails loudly at load time rather than
// silently disabling a condition. The returned slice is unordered; the engine
// sorts by priority + specificity at evaluation time.
func LoadPolicies(data []byte) ([]Policy, error) {
	var doc policyDoc
	if err := yaml.UnmarshalWithOptions(data, &doc, yaml.DisallowUnknownField()); err != nil {
		return nil, fmt.Errorf("conditionalaccess: parse policy bundle: %w", err)
	}
	for i := range doc.Policies {
		if err := doc.Policies[i].Validate(); err != nil {
			return nil, err
		}
	}
	return doc.Policies, nil
}

// LoadInto parses a YAML policy bundle and Puts every policy into store. On the
// first invalid or un-storable policy it returns the error, having already
// stored the preceding ones (callers wanting all-or-nothing should load into a
// fresh MemoryStore and swap it in).
func LoadInto(ctx context.Context, store Store, data []byte) error {
	policies, err := LoadPolicies(data)
	if err != nil {
		return err
	}
	for _, p := range policies {
		if err := store.Put(ctx, p); err != nil {
			return err
		}
	}
	return nil
}
