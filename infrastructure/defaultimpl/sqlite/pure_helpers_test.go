package sqlite

import (
	"errors"
	"testing"
	"time"
)

// These pure helpers are exercised here directly (package-internal test) so
// the constraint-classification + boundary branches the store-level tests
// only graze are fully covered.

func TestIsConstraintErr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unique", errors.New("UNIQUE constraint failed: t.x"), true},
		{"generic constraint", errors.New("constraint failed"), true},
		{"unrelated", errors.New("disk full"), false},
	}
	for _, c := range cases {
		if got := isConstraintErr(c.err); got != c.want {
			t.Errorf("isConstraintErr(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIsUniqueViolation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("UNIQUE constraint failed"), true},
		{errors.New("PRIMARY KEY must be unique"), true},
		{errors.New("constraint failed"), true},
		{errors.New("syntax error"), false},
	}
	for _, c := range cases {
		if got := isUniqueViolation(c.err); got != c.want {
			t.Errorf("isUniqueViolation(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestIsBcryptHash(t *testing.T) {
	t.Parallel()
	if !isBcryptHash("$2a$10$abcdefghijklmnopqrstuv") {
		t.Error("bcrypt hash not recognised")
	}
	if isBcryptHash("plaintext") {
		t.Error("plaintext misclassified as bcrypt hash")
	}
	if isBcryptHash("") {
		t.Error("empty misclassified as bcrypt hash")
	}
}

func TestLockedUntilUnix(t *testing.T) {
	t.Parallel()
	if got := lockedUntilUnix(time.Time{}); got != 0 {
		t.Errorf("lockedUntilUnix(zero) = %d, want 0", got)
	}
	ts := time.Unix(0, 1700000000123456789).UTC()
	if got := lockedUntilUnix(ts); got != ts.UnixNano() {
		t.Errorf("lockedUntilUnix(non-zero) = %d, want %d", got, ts.UnixNano())
	}
}

func TestSplitNonEmpty(t *testing.T) {
	t.Parallel()
	if got := splitNonEmpty(""); got != nil {
		t.Errorf("splitNonEmpty(\"\") = %v, want nil", got)
	}
	got := splitNonEmpty("a b c")
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Errorf("splitNonEmpty = %v, want [a b c]", got)
	}
}

func TestNullable(t *testing.T) {
	t.Parallel()
	if n := nullable(""); n.Valid {
		t.Errorf("nullable(\"\") should be NULL, got %+v", n)
	}
	n := nullable("x")
	if !n.Valid || n.String != "x" {
		t.Errorf("nullable(\"x\") = %+v, want valid 'x'", n)
	}
}

func TestGenerateClientSecret(t *testing.T) {
	t.Parallel()
	a, err := generateClientSecret()
	if err != nil {
		t.Fatalf("generateClientSecret: %v", err)
	}
	b, _ := generateClientSecret()
	if a == "" || a == b {
		t.Errorf("generateClientSecret produced empty or non-unique value: %q / %q", a, b)
	}
}

func TestHashClientSecret_NonEmptyAndComparable(t *testing.T) {
	t.Parallel()
	h, err := hashClientSecret("topsecret")
	if err != nil {
		t.Fatalf("hashClientSecret: %v", err)
	}
	if !isBcryptHash(h) {
		t.Errorf("hash is not bcrypt-shaped: %q", h)
	}
	if !compareClientSecret(h, "topsecret") {
		t.Error("compareClientSecret rejected the matching plaintext")
	}
	if compareClientSecret(h, "wrong") {
		t.Error("compareClientSecret accepted a wrong plaintext")
	}
}
