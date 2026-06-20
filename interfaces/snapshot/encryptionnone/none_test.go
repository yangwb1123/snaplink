package none_test

import (
	"bytes"
	"testing"

	"github.com/snaplink/sso/interfaces/snapshot"
	"github.com/snaplink/sso/interfaces/snapshot/encryptionnone"
)

func TestNew_SatisfiesSealerInterface(t *testing.T) {
	var _ snapshot.Sealer = none.New()
}

func TestAlgorithm(t *testing.T) {
	if got := none.New().Algorithm(); got != snapshot.EncryptionNone {
		t.Errorf("Algorithm = %q, want %q", got, snapshot.EncryptionNone)
	}
}

func TestSeal_PassesThrough(t *testing.T) {
	plain := []byte("hello world")
	out, params, err := none.New().Seal(plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !bytes.Equal(out, plain) {
		t.Errorf("Seal mutated body: in=%q out=%q", plain, out)
	}
	if params != nil {
		t.Errorf("Seal returned non-nil params for no-encryption sealer: %v", params)
	}
	// Output must NOT alias input — callers might mutate plain after.
	out[0] = 'X'
	if plain[0] == 'X' {
		t.Error("Seal returned an alias of plain; downstream mutations corrupt the caller's buffer")
	}
}

func TestOpen_PassesThrough(t *testing.T) {
	cipher := []byte("hello world")
	out, err := none.New().Open(cipher, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(out, cipher) {
		t.Errorf("Open mutated body: in=%q out=%q", cipher, out)
	}
	// Symmetric: Open output must not alias input.
	out[0] = 'X'
	if cipher[0] == 'X' {
		t.Error("Open returned an alias of cipher")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	original := []byte("round-trip-bytes")
	s := none.New()
	sealed, params, _ := s.Seal(original)
	opened, err := s.Open(sealed, params)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(opened, original) {
		t.Errorf("round-trip drift: %q vs %q", opened, original)
	}
}

func TestSeal_EmptyInput(t *testing.T) {
	out, _, err := none.New().Seal(nil)
	if err != nil {
		t.Fatalf("Seal(nil): %v", err)
	}
	if len(out) != 0 {
		t.Errorf("Seal(nil) = %v, want empty", out)
	}
}
