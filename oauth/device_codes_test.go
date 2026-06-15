package oauth

import (
	"strings"
	"testing"
)

func TestGenerateDeviceCode(t *testing.T) {
	t.Parallel()

	code, err := GenerateDeviceCode()
	if err != nil {
		t.Fatalf("GenerateDeviceCode() error: %v", err)
	}
	if code == "" {
		t.Fatal("GenerateDeviceCode() returned empty string")
	}
	// Should be base64url encoded, about 43 chars for 32 bytes
	if len(code) < 40 || len(code) > 48 {
		t.Errorf("unexpected device_code length: %d (expected ~43)", len(code))
	}
	// Should be deterministic-enough: two calls produce different codes
	code2, _ := GenerateDeviceCode()
	if code == code2 {
		t.Error("GenerateDeviceCode() returned same value twice")
	}
}

func TestGenerateUserCode(t *testing.T) {
	t.Parallel()

	code, err := GenerateUserCode()
	if err != nil {
		t.Fatalf("GenerateUserCode() error: %v", err)
	}
	if code == "" {
		t.Fatal("GenerateUserCode() returned empty string")
	}
	// Format: XXXX-XXXX
	if len(code) != 9 {
		t.Errorf("unexpected user_code length: %d (want 9)", len(code))
	}
	if code[4] != '-' {
		t.Errorf("expected dash at position 4, got %q", code[4])
	}
	// All characters should be from the alphabet
	parts := strings.Split(code, "-")
	for _, part := range parts {
		for _, ch := range part {
			if !strings.ContainsRune(UserCodeAlphabet, ch) {
				t.Errorf("unexpected character %c in user_code %q", ch, code)
			}
		}
	}
	// Two calls should differ
	code2, _ := GenerateUserCode()
	if code == code2 {
		t.Error("GenerateUserCode() returned same value twice")
	}
}

func TestNormalizeUserCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{input: "ABCD-EFGH", want: "ABCDEFGH"},
		{input: "abcd-efgh", want: "ABCDEFGH"},
		{input: "ABCDEFGH", want: "ABCDEFGH"},
		{input: "a1b2-c3d4", want: "A1B2C3D4"},
		{input: "", want: ""},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := NormalizeUserCode(tc.input)
			if got != tc.want {
				t.Errorf("NormalizeUserCode(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
