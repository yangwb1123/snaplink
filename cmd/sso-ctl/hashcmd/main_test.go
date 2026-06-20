package hashcmd

import (
	"strings"
	"testing"

	"github.com/snaplink/sso/domains/authenticators"
)

func TestReadPassword_FlagWins(t *testing.T) {
	got, err := readPassword("literal", strings.NewReader("from-stdin\n"))
	if err != nil || got != "literal" {
		t.Fatalf("readPassword(flag) = %q, %v; want \"literal\", nil", got, err)
	}
}

func TestReadPassword_Stdin(t *testing.T) {
	got, err := readPassword("", strings.NewReader("s3cret\n"))
	if err != nil || got != "s3cret" {
		t.Fatalf("readPassword(stdin) = %q, %v; want \"s3cret\", nil", got, err)
	}
}

func TestReadPassword_StdinNoNewline(t *testing.T) {
	got, _ := readPassword("", strings.NewReader("s3cret"))
	if got != "s3cret" {
		t.Fatalf("readPassword(no-newline) = %q; want \"s3cret\"", got)
	}
}

func TestRun_EmptyPasswordIsUsageError(t *testing.T) {
	if code := Run([]string{"--password", ""}); code != 2 {
		t.Errorf("empty password exit = %d, want 2", code)
	}
}

// TestRun_ProducesVerifiableHash is the round-trip: the emitted hash must
// verify against the original plaintext with the server's own verifier.
func TestRun_ProducesVerifiableHash(t *testing.T) {
	const pw = "round-trip-secret"
	h, err := authenticators.HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := authenticators.VerifyHash(t.Context(), h, pw); err != nil {
		t.Errorf("emitted hash does not verify against its plaintext: %v", err)
	}
	if code := Run([]string{"--password", pw, "--quiet"}); code != 0 {
		t.Errorf("hash --password exit = %d, want 0", code)
	}
}
