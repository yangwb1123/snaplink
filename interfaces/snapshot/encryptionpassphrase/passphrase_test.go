package passphrase_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
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

// lowCostSealer returns a Sealer with a ~1 ms argon2 envelope instead
// of the ~70 ms Defaults one. Validation outcomes are KDF-cost-
// independent — the version/salt/zero-KDF checks reject pre-KDF and
// the nonce/AEAD stages only need a valid derivation — so every table
// below seals with this envelope to keep the suite fast while still
// exercising the real KDF path.
func lowCostSealer() *passphrase.Sealer {
	return &passphrase.Sealer{
		Passphrase: []byte("k"),
		KDF:        passphrase.KDFParams{Time: 1, Memory: 1024, Threads: 1},
	}
}

func sealWith(t *testing.T, s *passphrase.Sealer, plain []byte) (cipher, params []byte) {
	t.Helper()
	cipher, params, err := s.Seal(plain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return cipher, params
}

// testEnv and testKDF mirror the production envelopeParams/KDFParams
// JSON shapes (passphrase.go). The external test package cannot read
// the unexported production structs, so rows derive from a sealed
// envelope and mutate through this mirror. If the JSON tags ever
// drift, mutations stop reaching the field production reads and the
// row succeeds — the failing assertion makes the drift self-detecting
// by construction.
type testEnv struct {
	Version uint32  `json:"version"`
	KDF     testKDF `json:"kdf"`
	Salt    []byte  `json:"salt"`
	Nonce   []byte  `json:"nonce"`
}

type testKDF struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory_kib"`
	Threads uint8  `json:"threads"`
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

func TestOpen_RejectsUnsupportedVersion(t *testing.T) {
	t.Parallel()
	s := lowCostSealer()
	cipher, params := sealWith(t, s, []byte("data"))

	rows := []struct {
		name    string
		version uint32
		mutated []byte
	}{
		{"zero", 0, mutateParams(t, params, func(e *testEnv) { e.Version = 0 })},
		{"two", 2, mutateParams(t, params, func(e *testEnv) { e.Version = 2 })},
		{"max_uint32", math.MaxUint32, mutateParams(t, params, func(e *testEnv) { e.Version = math.MaxUint32 })},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			_, err := s.Open(cipher, row.mutated)
			want := fmt.Sprintf("unsupported KDF version %d", row.version)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("version %d: want error containing %q, got %v", row.version, want, err)
			}
		})
	}
}

func TestOpen_RejectsBadSaltLength(t *testing.T) {
	t.Parallel()
	s := lowCostSealer()
	cipher, params := sealWith(t, s, []byte("data"))

	rows := []struct {
		name    string
		wantLen int
		mutated []byte
	}{
		{"zero", 0, mutateParams(t, params, func(e *testEnv) { e.Salt = nil })},
		{"fifteen", 15, mutateParams(t, params, func(e *testEnv) { e.Salt = e.Salt[:15] })},
		{"seventeen", 17, mutateParams(t, params, func(e *testEnv) { e.Salt = append(e.Salt, 0) })},
		{"hundred", 100, mutateParams(t, params, func(e *testEnv) { e.Salt = append(e.Salt, make([]byte, 84)...) })},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			_, err := s.Open(cipher, row.mutated)
			want := fmt.Sprintf("bad salt length %d", row.wantLen)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("salt %d: want error containing %q, got %v", row.wantLen, want, err)
			}
		})
	}
}

func TestOpen_RejectsZeroKDFParam(t *testing.T) {
	t.Parallel()
	s := lowCostSealer()
	cipher, params := sealWith(t, s, []byte("data"))

	rows := []struct {
		name    string
		mutated []byte
	}{
		{"time_zero", mutateParams(t, params, func(e *testEnv) { e.KDF.Time = 0 })},
		{"memory_zero", mutateParams(t, params, func(e *testEnv) { e.KDF.Memory = 0 })},
		{"threads_zero", mutateParams(t, params, func(e *testEnv) { e.KDF.Threads = 0 })},
		{"all_zero", mutateParams(t, params, func(e *testEnv) { e.KDF = testKDF{} })},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			_, err := s.Open(cipher, row.mutated)
			if err == nil || err.Error() != "snapshot/passphrase: zero KDF param" {
				t.Errorf("%s: want exact zero-KDF error, got %v", row.name, err)
			}
		})
	}
}

func TestOpen_RejectsBadNonceLength(t *testing.T) {
	t.Parallel()
	s := lowCostSealer()
	cipher, params := sealWith(t, s, []byte("data"))

	rows := []struct {
		name    string
		wantLen int
		mutated []byte
	}{
		{"zero", 0, mutateParams(t, params, func(e *testEnv) { e.Nonce = nil })},
		{"twenty_three", 23, mutateParams(t, params, func(e *testEnv) { e.Nonce = e.Nonce[:23] })},
		{"twenty_five", 25, mutateParams(t, params, func(e *testEnv) { e.Nonce = append(e.Nonce, 0) })},
		{"hundred", 100, mutateParams(t, params, func(e *testEnv) { e.Nonce = append(e.Nonce, make([]byte, 76)...) })},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			_, err := s.Open(cipher, row.mutated)
			want := fmt.Sprintf("bad nonce length %d", row.wantLen)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("nonce %d: want error containing %q, got %v", row.wantLen, want, err)
			}
		})
	}
}

func TestOpen_RejectsOversizedParamsBlob(t *testing.T) {
	t.Parallel()
	s := lowCostSealer()
	cipher, params := sealWith(t, s, []byte("data"))

	t.Run("one_mib_non_json", func(t *testing.T) {
		t.Parallel()
		_, err := s.Open(cipher, bytes.Repeat([]byte{0x41}, 1<<20))
		if err == nil || !strings.Contains(err.Error(), "unmarshal params") {
			t.Errorf("want unmarshal-params error, got %v", err)
		}
	})
	t.Run("one_mib_salt", func(t *testing.T) {
		t.Parallel()
		mutated := mutateParams(t, params, func(e *testEnv) { e.Salt = bytes.Repeat([]byte{'A'}, 1<<20) })
		_, err := s.Open(cipher, mutated)
		if err == nil || !strings.Contains(err.Error(), "bad salt length") {
			t.Errorf("want bad-salt-length error, got %v", err)
		}
	})
}

func TestOpen_TamperedParams(t *testing.T) {
	t.Parallel()
	s := lowCostSealer()
	cipher, params := sealWith(t, s, []byte("data"))

	rows := []struct {
		name    string
		mutated []byte
		want    string
	}{
		{"swapped_salt", mutateParams(t, params, func(e *testEnv) { e.Salt[0] ^= 0xFF }), "chacha20poly1305: message authentication failed"},
		{"swapped_nonce", mutateParams(t, params, func(e *testEnv) { e.Nonce[0] ^= 0xFF }), "chacha20poly1305: message authentication failed"},
		{"version_zero", mutateParams(t, params, func(e *testEnv) { e.Version = 0 }), "unsupported KDF version"},
		{"version_two", mutateParams(t, params, func(e *testEnv) { e.Version = 2 }), "unsupported KDF version"},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			_, err := s.Open(cipher, row.mutated)
			if err == nil || !strings.Contains(err.Error(), row.want) {
				t.Errorf("%s: want error containing %q, got %v", row.name, row.want, err)
			}
		})
	}
}

func TestOpen_ErrorClassOracleStable(t *testing.T) {
	t.Parallel()
	// Byte-identity of the AEAD failure class across every key-oracle
	// cause. Deliberately pinned to the exact library string: if
	// x/crypto ever rewrites it, or a future edit leaks "wrong
	// passphrase" vs "tampered ciphertext", these rows fail together
	// and force a review — the byte-identity of the class is the
	// property under test.
	const want = "snapshot/passphrase: open: chacha20poly1305: message authentication failed"

	s := lowCostSealer()
	wrong := &passphrase.Sealer{Passphrase: []byte("wrong"), KDF: passphrase.KDFParams{Time: 1, Memory: 1024, Threads: 1}}
	cipher, params := sealWith(t, s, []byte("data"))

	tamperedCipher := bytes.Clone(cipher)
	tamperedCipher[0] ^= 0xFF
	swappedSalt := mutateParams(t, params, func(e *testEnv) { e.Salt[0] ^= 0xFF })
	swappedNonce := mutateParams(t, params, func(e *testEnv) { e.Nonce[0] ^= 0xFF })

	rows := []struct {
		name string
		s    *passphrase.Sealer
		c    []byte
		p    []byte
	}{
		{"wrong_passphrase", wrong, cipher, params},
		{"tampered_cipher", s, tamperedCipher, params},
		{"swapped_salt", s, cipher, swappedSalt},
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

func TestOpen_AnySingleByteMutationFails(t *testing.T) {
	t.Parallel()
	// Exhaustive deterministic scan: every byte position of the params
	// JSON and of the ciphertext, flipped with ^= 0x01, must fail Open.
	// Covers JSON-structure flips (unmarshal class), version-digit
	// flips (version class), digit-to-zero flips (zero-KDF class), and
	// base64/cipher flips (AEAD class). The only theoretical escape is
	// an XChaCha20-Poly1305 tag forgery (2^-128), the same bound every
	// AEAD negative test in the tree assumes.
	s := lowCostSealer()
	cipher, params := sealWith(t, s, []byte("x"))

	var violations []string
	for i := range params {
		mutated := bytes.Clone(params)
		mutated[i] ^= 0x01
		if _, err := s.Open(cipher, mutated); err == nil {
			violations = append(violations, fmt.Sprintf("params byte %d", i))
		}
	}
	for i := range cipher {
		mutated := bytes.Clone(cipher)
		mutated[i] ^= 0x01
		if _, err := s.Open(mutated, params); err == nil {
			violations = append(violations, fmt.Sprintf("cipher byte %d", i))
		}
	}
	if len(violations) > 0 {
		t.Errorf("Open accepted mutated input at: %s", strings.Join(violations, ", "))
	}
}

func FuzzSealOpenRoundtrip(f *testing.F) {
	// Seeds run under plain `go test` in CI (no -fuzz flag needed).
	f.Add([]byte{})
	f.Add([]byte("the quick brown fox"))
	f.Add([]byte{0x00, 0x01, 0x02, 0xFF})

	pattern4k := make([]byte, 4<<10)
	for i := range pattern4k {
		pattern4k[i] = byte(i)
	}
	f.Add(pattern4k)

	large := make([]byte, 64<<10)
	for i := range large {
		large[i] = byte(i * 7)
	}
	f.Add(large)

	// The passphrase is fixed non-empty inside the target, so the
	// empty-passphrase branch stays with TestSeal_RejectsEmptyPassphrase;
	// the property here is: Seal never errors and Open round-trips.
	// Fuzz targets must not call t.Parallel.
	f.Fuzz(func(t *testing.T, plain []byte) {
		s := lowCostSealer()
		cipher, params, err := s.Seal(plain)
		if err != nil {
			t.Errorf("seal: %v", err)
			return
		}
		got, err := s.Open(cipher, params)
		if err != nil {
			t.Errorf("open: %v", err)
			return
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("roundtrip mismatch: got %d bytes, want %d", len(got), len(plain))
		}
	})
}
