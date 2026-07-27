package buildinfo

import (
	"strings"
	"testing"
)

func TestResolve_NeverEmpty(t *testing.T) {
	if ver, _, _ := Resolve(""); ver == "" {
		t.Error("Resolve must never return an empty version string")
	}
}

func TestResolve_OverrideWins(t *testing.T) {
	if ver, _, _ := Resolve("v9.9.9-test"); ver != "v9.9.9-test" {
		t.Errorf("override = %q, want v9.9.9-test", ver)
	}
}

func TestWrite_FormatsProgNameAndGoVersion(t *testing.T) {
	var sb strings.Builder
	Write(&sb, "demo", "v1.2.3")
	out := sb.String()
	if !strings.HasPrefix(out, "demo v1.2.3") {
		t.Errorf("want prefix 'demo v1.2.3', got %q", out)
	}
	if !strings.Contains(out, "go") || !strings.HasSuffix(out, "\n") {
		t.Errorf("want go-version + trailing newline, got %q", out)
	}
}

func TestFormatEditionVersion(t *testing.T) {
	tests := map[string]string{
		"prototype":  "snaplink-v1.1.1.prototype",
		"minimal":    "snaplink-v1.1.1.minimal",
		"production": "snaplink-v1.1.1.production",
		"standard":   "v1.1.1",
		"custom":     "v1.1.1",
	}
	for profile, want := range tests {
		if got := FormatEditionVersion("v1.1.1", profile); got != want {
			t.Errorf("%s version = %q, want %q", profile, got, want)
		}
	}
}

func TestFormatEditionVersionIsIdempotent(t *testing.T) {
	const want = "snaplink-v1.1.1.minimal"
	if got := FormatEditionVersion(want, "minimal"); got != want {
		t.Fatalf("decorated version = %q, want %q", got, want)
	}
}

func TestWriteProfileUsesEditionIdentity(t *testing.T) {
	var out strings.Builder
	WriteProfile(&out, "sso-server", "v1.1.1", "production")
	if !strings.HasPrefix(out.String(), "snaplink-v1.1.1.production") {
		t.Fatalf("production version = %q", out.String())
	}
}
