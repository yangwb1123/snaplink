package security

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestCompareClientSecret_BcryptPath(t *testing.T) {
	t.Parallel()
	plaintext := "my-secret"
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("generate hash: %v", err)
	}
	stored := string(hash)
	if !strings.HasPrefix(stored, "$2") {
		t.Fatalf("generated hash does not start with $2: %q", stored)
	}
	if !CompareClientSecret(stored, plaintext) {
		t.Error("correct plaintext not accepted on bcrypt path")
	}
	if CompareClientSecret(stored, "wrong") {
		t.Error("wrong plaintext accepted on bcrypt path")
	}
}

func TestCompareClientSecret_PlaintextFallback(t *testing.T) {
	t.Parallel()
	// Stored value does not start with "$2" — falls back to constant-time
	// string compare.
	stored := "raw-plaintext"
	if !CompareClientSecret(stored, "raw-plaintext") {
		t.Error("correct plaintext not accepted on fallback path")
	}
	if CompareClientSecret(stored, "wrong") {
		t.Error("wrong plaintext accepted on fallback path")
	}
	// Empty plaintext vs non-empty stored must fail.
	if CompareClientSecret(stored, "") {
		t.Error("empty plaintext accepted on fallback path")
	}
}

func TestCompareClientSecret_EmptyStoredEmptyPlaintext(t *testing.T) {
	t.Parallel()
	// Both empty — conceptually equal but this should return true (constant-
	// time path: len(a)==len(b)==0, subtle.ConstantTimeCompare([],[]) returns 1).
	if !CompareClientSecret("", "") {
		t.Error("empty vs empty should match on plaintext fallback")
	}
}
