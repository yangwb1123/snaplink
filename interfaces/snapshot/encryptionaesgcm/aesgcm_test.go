package aesgcm_test

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	"github.com/yangwb1123/snaplink/interfaces/snapshot/encryptionaesgcm"
)

func mkKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, aesgcm.KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestNew_RejectsWrongKeyLength(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 16, 24, 31, 33, 64} {
		_, err := aesgcm.New(make([]byte, n))
		if err == nil {
			t.Errorf("key length %d should reject", n)
		}
	}
}

func TestSealer_AlgorithmString(t *testing.T) {
	t.Parallel()
	s, err := aesgcm.New(mkKey(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s.Algorithm(); got != snapshot.EncryptionAESGCM {
		t.Errorf("Algorithm = %q, want %q", got, snapshot.EncryptionAESGCM)
	}
}

func TestSealer_SealOpenRoundtrip(t *testing.T) {
	t.Parallel()
	s, _ := aesgcm.New(mkKey(t))
	plain := []byte("hello cluster")

	cipher, params, err := s.Seal(plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Equal(cipher, plain) {
		t.Fatal("cipher equals plain — encryption no-op")
	}
	got, err := s.Open(cipher, params)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("roundtrip mismatch: got %q want %q", got, plain)
	}
}

func TestSealer_SealsProducesFreshNonce(t *testing.T) {
	t.Parallel()
	// AES-GCM nonce reuse with the same key is catastrophic. Verify
	// two successive Seal calls produce different (ciphertext, nonce).
	s, _ := aesgcm.New(mkKey(t))
	plain := []byte("identical plaintext")
	c1, p1, err := s.Seal(plain)
	if err != nil {
		t.Fatalf("first Seal: %v", err)
	}
	c2, p2, err := s.Seal(plain)
	if err != nil {
		t.Fatalf("second Seal: %v", err)
	}
	if bytes.Equal(c1, c2) {
		t.Error("two successive Seals produced identical ciphertext — nonce not fresh")
	}
	if bytes.Equal(p1, p2) {
		t.Error("two successive Seals produced identical params — nonce not fresh")
	}
}

func TestSealer_OpenWrongKeyFails(t *testing.T) {
	t.Parallel()
	s1, _ := aesgcm.New(mkKey(t))
	s2, _ := aesgcm.New(mkKey(t)) // different key

	cipher, params, _ := s1.Seal([]byte("secret"))
	_, err := s2.Open(cipher, params)
	if err == nil {
		t.Fatal("wrong key Open should fail")
	}
}

func TestSealer_OpenTamperedCipherFails(t *testing.T) {
	t.Parallel()
	s, _ := aesgcm.New(mkKey(t))
	cipher, params, _ := s.Seal([]byte("trust me"))
	cipher[0] ^= 0xFF // flip a bit
	_, err := s.Open(cipher, params)
	if err == nil {
		t.Fatal("tampered ciphertext Open should fail (AEAD MAC catches it)")
	}
}

func TestSealer_OpenEmptyParamsFails(t *testing.T) {
	t.Parallel()
	s, _ := aesgcm.New(mkKey(t))
	_, err := s.Open([]byte("any"), nil)
	if err == nil {
		t.Fatal("empty params Open should fail")
	}
}

func TestSealer_OpenMalformedParamsFails(t *testing.T) {
	t.Parallel()
	s, _ := aesgcm.New(mkKey(t))
	_, err := s.Open([]byte("any"), []byte("not json"))
	if err == nil {
		t.Fatal("malformed params Open should fail")
	}
}

func TestSealer_KeyCopiedAtConstruction(t *testing.T) {
	t.Parallel()
	// Caller wipes their source slice; Sealer must still work.
	k := mkKey(t)
	s, err := aesgcm.New(k)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := range k {
		k[i] = 0xFF
	}
	cipher, params, err := s.Seal([]byte("still works"))
	if err != nil {
		t.Fatalf("Seal after caller wiped: %v", err)
	}
	got, err := s.Open(cipher, params)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != "still works" {
		t.Errorf("got %q", got)
	}
}

func TestSealer_PluggableInPipeline(t *testing.T) {
	t.Parallel()
	// AES-GCM Sealer satisfies snapshot.Sealer — implicit via the
	// compile-time assertion in aesgcm.go, but a concrete check
	// here helps refactors notice if the interface drifts.
	s, _ := aesgcm.New(mkKey(t))
	var _ snapshot.Sealer = s
	// Smoke: a wrong-version params blob fails on Open.
	cipher, _, _ := s.Seal([]byte("x"))
	_, err := s.Open(cipher, []byte(`{"version":99,"nonce":"AAAA"}`))
	if err == nil {
		t.Fatal("unsupported version Open should fail")
	}
	// The error should mention the version mismatch; exact wording can drift.
	if !strings.Contains(err.Error(), "version") {
		t.Fatalf("expected version error, got %v", err)
	}
}
