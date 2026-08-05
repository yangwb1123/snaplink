package region

import (
	"errors"
	"fmt"
	"regexp"
)

// ErrInvalidRegion is returned by ValidateID / ValidatePolicy and wrapped by
// the policy stores' Set methods when a policy carries a malformed region
// ID. Region IDs are compared by exact string equality in the enforcement
// layer, so a typo ("EU-WEST-1" vs "eu-west-1") silently loosens or
// tightens a default-fail-open compliance control — validation must be loud
// at every write boundary instead.
var ErrInvalidRegion = errors.New("region: invalid region id")

// regionIDPattern is the canonical form: 1-63 characters, lowercase
// [a-z0-9] labels joined by single '-', no leading/trailing '-'. Covers
// "eu-west-1", "us-east-1", "ap-southeast-2". The empty ID is the
// unconstrained sentinel and is handled by callers (never passed here).
var regionIDPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidateID rejects a region ID that is not in canonical form. The empty
// ID is valid only at callers that treat it as the unconstrained sentinel;
// this function rejects it.
func ValidateID(id ID) error {
	if id == "" {
		return fmt.Errorf("%w: empty region id", ErrInvalidRegion)
	}
	if len(id) > 63 || !regionIDPattern.MatchString(string(id)) {
		return fmt.Errorf("%w: %q (canonical form: 1-63 lowercase [a-z0-9] labels joined by single '-')", ErrInvalidRegion, id)
	}
	return nil
}

// ValidatePolicy rejects a policy with a malformed HomeRegion or any
// malformed AllowedRegions entry.
func ValidatePolicy(p ResidencyPolicy) error {
	if p.HomeRegion != "" {
		if err := ValidateID(p.HomeRegion); err != nil {
			return err
		}
	}
	for _, r := range p.AllowedRegions {
		if err := ValidateID(r); err != nil {
			return err
		}
	}
	return nil
}
