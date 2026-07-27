package passphrase_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/snapshot/encryptionpassphrase"
)

func TestSealOpenRoundtrip(t *testing.T) {
	t.Parallel()
	s := passphrase.NewFromString("hunter2")
	plain := []byte("the quick brown fox")
	cipher, params, err := s.Seal(plain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Equal(cipher, plain) {
		t.Errorf("ciphertext equals plaintext")
	}
	if len(params) == 0 {
		t.Errorf("params empty — KDF salt + nonce should be there")
	}
	got, err := s.Open(cipher, params)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("roundtrip mismatch: %q", got)
	}
}

func TestSealNotDeterministic(t *testing.T) {
	t.Parallel()
	s := passphrase.NewFromString("k")
	c1, _, _ := s.Seal([]byte("data"))
	c2, _, _ := s.Seal([]byte("data"))
	if bytes.Equal(c1, c2) {
		t.Errorf("two seals produced identical ciphertext — salt+nonce should differ")
	}
}

func TestOpen_WrongPassphrase(t *testing.T) {
	t.Parallel()
	s1 := passphrase.NewFromString("right")
	cipher, params, _ := s1.Seal([]byte("data"))

	s2 := passphrase.NewFromString("wrong")
	_, err := s2.Open(cipher, params)
	if err == nil {
		t.Errorf("open with wrong passphrase should fail")
	}
}

func TestOpen_TamperedCipher(t *testing.T) {
	t.Parallel()
	s := passphrase.NewFromString("k")
	cipher, params, _ := s.Seal([]byte("data"))
	cipher[0] ^= 0xFF
	_, err := s.Open(cipher, params)
	if err == nil {
		t.Errorf("open with tampered cipher should fail")
	}
}

func TestSeal_RejectsEmptyPassphrase(t *testing.T) {
	t.Parallel()
	s := &passphrase.Sealer{}
	_, _, err := s.Seal([]byte("data"))
	if err == nil || !strings.Contains(err.Error(), "passphrase required") {
		t.Errorf("want passphrase-required error, got %v", err)
	}
}

func TestOpen_RejectsEmptyParams(t *testing.T) {
	t.Parallel()
	s := passphrase.NewFromString("k")
	_, err := s.Open([]byte("x"), nil)
	if err == nil || !strings.Contains(err.Error(), "missing encryption params") {
		t.Errorf("want missing-params error, got %v", err)
	}
}
