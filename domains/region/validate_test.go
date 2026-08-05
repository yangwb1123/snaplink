package region

import (
	"errors"
	"testing"
)

func TestValidateID_AcceptsCanonicalIDs(t *testing.T) {
	for _, id := range []ID{"eu-west-1", "us-east-1", "ap-southeast-2", "a", "z9", "us"} {
		if err := ValidateID(id); err != nil {
			t.Errorf("ValidateID(%q) = %v, want nil", id, err)
		}
	}
}

func TestValidateID_RejectsMalformedIDs(t *testing.T) {
	for _, id := range []ID{"EU-WEST-1", "eu west", "eu_west", "-eu", "eu-", "eu-west-1-", "E"} {
		if err := ValidateID(id); !errors.Is(err, ErrInvalidRegion) {
			t.Errorf("ValidateID(%q) = %v, want ErrInvalidRegion", id, err)
		}
	}
}

func TestValidateID_RejectsEmptyAndOverlong(t *testing.T) {
	if err := ValidateID(""); !errors.Is(err, ErrInvalidRegion) {
		t.Errorf("ValidateID(\"\") = %v, want ErrInvalidRegion", err)
	}
	if err := ValidateID(ID("abcdefghijklmnopqrstuvwxyz0123456789-abcdefghijklmnopqrstuvwxyz0123456789-abcdefgh")); !errors.Is(err, ErrInvalidRegion) {
		t.Errorf("overlong id accepted: %v", err)
	}
}

func TestValidatePolicy_RejectsSingleBadAllowedRegion(t *testing.T) {
	p := ResidencyPolicy{HomeRegion: "eu-west-1", AllowedRegions: []ID{"eu-west-1", "EU-WEST-1"}}
	if err := ValidatePolicy(p); !errors.Is(err, ErrInvalidRegion) {
		t.Errorf("ValidatePolicy = %v, want ErrInvalidRegion", err)
	}
}

func TestValidatePolicy_AcceptsValidAndZero(t *testing.T) {
	if err := ValidatePolicy(ResidencyPolicy{}); err != nil {
		t.Errorf("zero policy = %v, want nil", err)
	}
	if err := ValidatePolicy(ResidencyPolicy{HomeRegion: "eu-west-1", AllowedRegions: []ID{"eu-central-1"}, EnforceWrites: true}); err != nil {
		t.Errorf("valid policy = %v, want nil", err)
	}
}
