package config

import (
	"strings"
	"testing"
)

func TestLoadPasswordPolicyProjection(t *testing.T) {
	t.Parallel()
	path := writeTemp(t, "password-policy.yaml", `authenticators:
  password:
    policy:
      min_length: 14
      require_upper: true
      require_lower: true
      require_digit: true
      require_special: true
      max_age_days: 365
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	policy := cfg.Authenticators.Password.Policy
	if policy == nil {
		t.Fatal("password policy was not decoded")
	}
	if policy.MinLength != 14 || !policy.RequireUpper || !policy.RequireLower ||
		!policy.RequireDigit || !policy.RequireSpecial || policy.MaxAgeDays != 365 {
		t.Fatalf("decoded policy = %+v", *policy)
	}
}

func TestPasswordPolicyValidationBounds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  PasswordPolicyConfig
		want string
	}{
		{"negative length", PasswordPolicyConfig{MinLength: -1}, "min_length"},
		{"length too large", PasswordPolicyConfig{MinLength: 1025}, "min_length"},
		{"negative age", PasswordPolicyConfig{MaxAgeDays: -1}, "max_age_days"},
		{"age too large", PasswordPolicyConfig{MaxAgeDays: 36501}, "max_age_days"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			cfg := &Config{Authenticators: AuthenticatorsConfig{
				Password: &PasswordConfig{Policy: &test.cfg},
			}}
			err := cfg.validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want path containing %q", err, test.want)
			}
		})
	}
	valid := &Config{
		Logging: LoggingConfig{Level: "info"},
		Authenticators: AuthenticatorsConfig{
			Password: &PasswordConfig{Policy: &PasswordPolicyConfig{
				MinLength: 1024, MaxAgeDays: 36500,
			}},
		},
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("upper-bound policy rejected: %v", err)
	}
}

func TestPasswordPolicyMissingAndZeroValuesRemainValid(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		"authenticators:\n  password:\n    enabled: false\n",
		"authenticators:\n  password:\n    policy: {}\n",
	} {
		path := writeTemp(t, "password-policy-zero.yaml", body)
		if _, err := Load(path); err != nil {
			t.Fatalf("zero/omitted policy Load(%q): %v", body, err)
		}
	}
}
