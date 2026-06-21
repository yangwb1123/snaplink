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
