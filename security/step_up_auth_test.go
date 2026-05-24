package security_test

import (
	"strings"
	"testing"

	"github.com/snaplink/sso/security"
)

func TestBuildStepUpChallenge_AllFields(t *testing.T) {
	got, err := security.BuildStepUpChallenge(security.StepUpChallenge{
		ACRValues:   []string{"urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze"},
		MaxAge:      60,
		Realm:       "payments",
		Description: "high-value transfer requires fresh auth",
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	want := []string{
		`Bearer error="insufficient_user_authentication"`,
		`error_description="high-value transfer requires fresh auth"`,
		`realm="payments"`,
		`acr_values="urn:mace:incommon:iap:silver urn:mace:incommon:iap:bronze"`,
		`max_age="60"`,
	}
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in %q", w, got)
		}
	}
}

func TestBuildStepUpChallenge_ACRValuesOnly(t *testing.T) {
	got, err := security.BuildStepUpChallenge(security.StepUpChallenge{
		ACRValues: []string{"urn:level:high"},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.HasPrefix(got, `Bearer error="insufficient_user_authentication"`) {
		t.Errorf("prefix wrong: %q", got)
	}
	if !strings.Contains(got, `acr_values="urn:level:high"`) {
		t.Errorf("acr_values missing: %q", got)
	}
	// No max_age requested → header MUST NOT carry it.
	if strings.Contains(got, "max_age") {
		t.Errorf("max_age leaked when not requested: %q", got)
	}
}

func TestBuildStepUpChallenge_MaxAgeOnly(t *testing.T) {
	got, err := security.BuildStepUpChallenge(security.StepUpChallenge{MaxAge: 120})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.Contains(got, `max_age="120"`) {
		t.Errorf("max_age missing: %q", got)
	}
}

func TestBuildStepUpChallenge_RejectsEmptyDemand(t *testing.T) {
	// No ACR + no max_age → RFC 9470 has no semantics; refuse.
	_, err := security.BuildStepUpChallenge(security.StepUpChallenge{Realm: "x"})
	if err == nil {
		t.Fatal("expected error on empty demand")
	}
}

func TestBuildStepUpChallenge_EscapesUntrustedDescription(t *testing.T) {
	// Description with embedded quote + backslash MUST be
	// escaped per RFC 7235 quoted-string rules — otherwise an
	// attacker who controls part of the description could
	// inject additional header parameters.
	const evil = `breakout"; injected="foo`
	got, err := security.BuildStepUpChallenge(security.StepUpChallenge{
		ACRValues:   []string{"urn:level:high"},
		Description: evil,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// The injection attempt MUST be escaped (i.e., not appear
	// verbatim ending in a closing quote that would close the
	// description and start a new attribute).
	if strings.Contains(got, `error_description="breakout";`) {
		t.Errorf("unescaped quote injected: %q", got)
	}
	// Properly escaped form: backslash + quote.
	if !strings.Contains(got, `breakout\";`) {
		t.Errorf("expected escaped form, got: %q", got)
	}
}

func TestMustBuildStepUpChallenge_PanicsOnEmpty(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic")
		}
	}()
	_ = security.MustBuildStepUpChallenge(security.StepUpChallenge{})
}
