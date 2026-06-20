package main

import (
	"strings"
	"testing"
)

func TestWriteVersion_IncludesProgNameAndGoVersion(t *testing.T) {
	var sb strings.Builder
	writeVersion(&sb)
	out := sb.String()
	if !strings.HasPrefix(out, progName+" ") {
		t.Errorf("version output should start with %q, got %q", progName, out)
	}
	if !strings.Contains(out, "go") {
		t.Errorf("version output should mention the go version, got %q", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("version output should end with a newline, got %q", out)
	}
}

func TestResolveVersion_NeverEmpty(t *testing.T) {
	ver, _, _ := resolveVersion()
	if ver == "" {
		t.Error("resolveVersion must never return an empty version string")
	}
}

// TestResolveVersion_LdflagsOverride documents that an injected build version
// takes precedence over build-info derivation.
func TestResolveVersion_LdflagsOverride(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })
	version = "v9.9.9-test"
	if ver, _, _ := resolveVersion(); ver != "v9.9.9-test" {
		t.Errorf("ldflags version override = %q, want v9.9.9-test", ver)
	}
}
