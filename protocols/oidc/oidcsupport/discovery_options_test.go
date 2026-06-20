package oidcsupport

import (
	"slices"
	"testing"
)

func TestCodeChallengeMethodsFor(t *testing.T) {
	t.Parallel()

	// OAuth 2.1 strict = S256 only
	methods := CodeChallengeMethodsFor(true)
	if len(methods) != 1 {
		t.Fatalf("expected 1 method in strict mode, got %d: %v", len(methods), methods)
	}
	if methods[0] != "S256" {
		t.Errorf("expected S256, got %s", methods[0])
	}

	// Non-strict = S256 + plain
	methods = CodeChallengeMethodsFor(false)
	if len(methods) != 2 {
		t.Fatalf("expected 2 methods in non-strict mode, got %d: %v", len(methods), methods)
	}
	if !slices.Contains(methods, "S256") {
		t.Error("expected S256 in non-strict mode")
	}
	if !slices.Contains(methods, "plain") {
		t.Error("expected plain in non-strict mode")
	}
}

func TestResponseTypesFor(t *testing.T) {
	t.Parallel()

	// OAuth 2.1 strict = code only
	types := ResponseTypesFor(true)
	if len(types) != 1 {
		t.Fatalf("expected 1 response type in strict mode, got %d: %v", len(types), types)
	}
	if types[0] != "code" {
		t.Errorf("expected code, got %s", types[0])
	}

	// Non-strict = code + token
	types = ResponseTypesFor(false)
	if len(types) != 2 {
		t.Fatalf("expected 2 response types in non-strict mode, got %d: %v", len(types), types)
	}
	if !slices.Contains(types, "code") {
		t.Error("expected code in non-strict mode")
	}
	if !slices.Contains(types, "token") {
		t.Error("expected token in non-strict mode")
	}
}

func TestSubjectTypesFor(t *testing.T) {
	t.Parallel()

	// Pairwise store wired = public + pairwise
	types := SubjectTypesFor(true)
	if len(types) != 2 {
		t.Fatalf("expected 2 subject types with pairwise, got %d: %v", len(types), types)
	}
	if !slices.Contains(types, "public") {
		t.Error("expected public")
	}
	if !slices.Contains(types, "pairwise") {
		t.Error("expected pairwise")
	}

	// No pairwise store = public only
	types = SubjectTypesFor(false)
	if len(types) != 1 {
		t.Fatalf("expected 1 subject type without pairwise, got %d: %v", len(types), types)
	}
	if types[0] != "public" {
		t.Errorf("expected public, got %s", types[0])
	}
}

func TestIsValidResponseMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode string
		want bool
	}{
		{"query", true},
		{"fragment", true},
		{"form_post", true},
		{"jwt", false},
		{"query.jwt", false},
		{"", false},
		{"invalid", false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.mode, func(t *testing.T) {
			t.Parallel()
			got := IsValidResponseMode(tc.mode)
			if got != tc.want {
				t.Errorf("IsValidResponseMode(%q) = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}
