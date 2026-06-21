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
