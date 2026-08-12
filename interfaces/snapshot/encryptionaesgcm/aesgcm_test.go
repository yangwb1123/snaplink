package aesgcm_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
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

// testEnv mirrors the production envelopeParams JSON shape (aesgcm.go).
// If the tags ever drift, mutations stop reaching the field production
// reads and the row succeeds — the failing assertion makes the drift
// self-detecting by construction. The version branch is not duplicated
// here: TestSealer_PluggableInPipeline already covers it.
type testEnv struct {
	Version uint32 `json:"version"`
	Nonce   []byte `json:"nonce"`
}

func TestSealer_OpenRejectsBadNonceLength(t *testing.T) {
	t.Parallel()
	s, err := aesgcm.New(mkKey(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cipher, params, err := s.Seal([]byte("data"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	rows := []struct {
		name    string
		wantLen int
		mutated []byte
	}{
		{"zero", 0, mutateParams(t, params, func(e *testEnv) { e.Nonce = nil })},
		{"eleven", 11, mutateParams(t, params, func(e *testEnv) { e.Nonce = e.Nonce[:11] })},
		{"thirteen", 13, mutateParams(t, params, func(e *testEnv) { e.Nonce = append(e.Nonce, 0) })},
		{"hundred", 100, mutateParams(t, params, func(e *testEnv) { e.Nonce = append(e.Nonce, make([]byte, 88)...) })},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			_, err := s.Open(cipher, row.mutated)
			// AES-GCM nonce size is 12; the production error carries the
			// want-length, so both parts of the message are pinned.
			want := fmt.Sprintf("bad nonce length %d (want 12)", row.wantLen)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("nonce %d: want error containing %q, got %v", row.wantLen, want, err)
			}
		})
	}
}

func TestSealer_OpenErrorClassOracleStable(t *testing.T) {
	t.Parallel()
	// Byte-identity of the AEAD failure class across every key-oracle
	// cause; pinned to the exact stdlib string so any future split of
	// the class fails loudly. The version branch is not duplicated —
	// TestSealer_PluggableInPipeline covers it.
	const want = "snapshot/aesgcm: open: cipher: message authentication failed"

	s, err := aesgcm.New(mkKey(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	wrong, err := aesgcm.New(mkKey(t)) // different key
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cipher, params, err := s.Seal([]byte("data"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tamperedCipher := bytes.Clone(cipher)
	tamperedCipher[0] ^= 0xFF
	swappedNonce := mutateParams(t, params, func(e *testEnv) { e.Nonce[0] ^= 0xFF })

	rows := []struct {
		name string
		s    *aesgcm.Sealer
		c    []byte
		p    []byte
	}{
		{"wrong_key", wrong, cipher, params},
		{"tampered_cipher", s, tamperedCipher, params},
		{"swapped_nonce", s, cipher, swappedNonce},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			_, err := row.s.Open(row.c, row.p)
			if err == nil || err.Error() != want {
				t.Errorf("%s: want exact error %q, got %v", row.name, want, err)
			}
		})
	}
}

// mutateParams unmarshals a sealed envelope, applies fn, and
// re-marshals — exactly the attacker-tamper model (swap a field in
// otherwise-valid params JSON, always producing valid base64).
func mutateParams(t *testing.T, params []byte, fn func(*testEnv)) []byte {
	t.Helper()
	var e testEnv
	if err := json.Unmarshal(params, &e); err != nil {
		t.Fatalf("unmarshal sealed params: %v", err)
	}
	fn(&e)
	mutated, err := json.Marshal(&e)
	if err != nil {
		t.Fatalf("marshal mutated params: %v", err)
	}
	return mutated
}
