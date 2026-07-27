// Package passphrase encrypts snapshots using argon2id-derived keys and
// XChaCha20-Poly1305 AEAD. Each Seal call generates a fresh salt and
// nonce so re-sealing the same snapshot with the same passphrase yields
// distinct ciphertexts.
//
// The salt + nonce + KDF tunables travel inside SealedEnvelope.EncryptionParams,
// not in the ciphertext, so the pipeline can present readable metadata
// (algorithm, KDF cost) to operators without decrypting.
//
// Passphrase strength is the operator's responsibility. The KDF tunables
// here (time=1, memory=64MiB, threads=4) match the OWASP 2024 baseline
// for low-latency interactive use; raise Memory for archival snapshots.
package passphrase

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/yangwb1123/snaplink/interfaces/snapshot"
)

const (
	saltLen = 16

	// kdfVersion stamps the KDF wire format. Bumped if the KDF or AEAD
	// choice changes; readers refuse unknown versions.
	kdfVersion = 1
)

// KDFParams are the argon2id tunables. The defaults below are a sane
// starting point — operators with paranoid threat models should
// override Memory upward.
type KDFParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory_kib"`
	Threads uint8  `json:"threads"`
}

// Defaults is the recommended baseline. ~70ms per derivation on a
// modern x86 core.
var Defaults = KDFParams{Time: 1, Memory: 64 * 1024, Threads: 4}

// Sealer encrypts snapshots with a passphrase. Passphrase MUST be set
// (a zero-length passphrase is rejected on Seal/Open). KDF defaults
// when the caller leaves it zero.
type Sealer struct {
	Passphrase []byte
	KDF        KDFParams
}

// New constructs a Sealer with the given passphrase and the Default KDF
// parameters.
func New(passphrase []byte) *Sealer {
	cp := make([]byte, len(passphrase))
	copy(cp, passphrase)
	return &Sealer{Passphrase: cp, KDF: Defaults}
}

// NewFromString is the convenience for string-typed passphrases (CLI flags,
// env vars). The string is copied into a private []byte; callers should
// still consider clearing the source string when feasible.
func NewFromString(passphrase string) *Sealer {
	return New([]byte(passphrase))
}

func (s *Sealer) Algorithm() string { return snapshot.EncryptionPassphrase }

// envelopeParams is the JSON shape persisted into
// SealedEnvelope.EncryptionParams. Versioned so future KDF/AEAD swaps
// stay backward-compatible.
type envelopeParams struct {
	Version uint32    `json:"version"`
	KDF     KDFParams `json:"kdf"`
	Salt    []byte    `json:"salt"`
	Nonce   []byte    `json:"nonce"`
}

func (s *Sealer) effectiveKDF() KDFParams {
	if s.KDF == (KDFParams{}) {
		return Defaults
	}
	return s.KDF
}

func (s *Sealer) Seal(plain []byte) ([]byte, []byte, error) {
	if len(s.Passphrase) == 0 {
		return nil, nil, errors.New("snapshot/passphrase: passphrase required")
	}
	kdf := s.effectiveKDF()

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("snapshot/passphrase: salt: %w", err)
	}
	key := argon2.IDKey(s.Passphrase, salt, kdf.Time, kdf.Memory, kdf.Threads, chacha20poly1305.KeySize)
	defer wipe(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, fmt.Errorf("snapshot/passphrase: aead init: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("snapshot/passphrase: nonce: %w", err)
	}
	cipher := aead.Seal(nil, nonce, plain, nil)

	params, err := json.Marshal(envelopeParams{
		Version: kdfVersion,
		KDF:     kdf,
		Salt:    salt,
		Nonce:   nonce,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("snapshot/passphrase: marshal params: %w", err)
	}
	return cipher, params, nil
}

func (s *Sealer) Open(cipher []byte, paramsRaw []byte) ([]byte, error) {
	if len(s.Passphrase) == 0 {
		return nil, errors.New("snapshot/passphrase: passphrase required")
	}
	if len(paramsRaw) == 0 {
		return nil, errors.New("snapshot/passphrase: missing encryption params")
	}
	var p envelopeParams
	if err := json.Unmarshal(paramsRaw, &p); err != nil {
		return nil, fmt.Errorf("snapshot/passphrase: unmarshal params: %w", err)
	}
	if p.Version != kdfVersion {
		return nil, fmt.Errorf("snapshot/passphrase: unsupported KDF version %d", p.Version)
	}
	if len(p.Salt) != saltLen {
		return nil, fmt.Errorf("snapshot/passphrase: bad salt length %d", len(p.Salt))
	}
	if p.KDF.Time == 0 || p.KDF.Memory == 0 || p.KDF.Threads == 0 {
		return nil, errors.New("snapshot/passphrase: zero KDF param")
	}

	key := argon2.IDKey(s.Passphrase, p.Salt, p.KDF.Time, p.KDF.Memory, p.KDF.Threads, chacha20poly1305.KeySize)
	defer wipe(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("snapshot/passphrase: aead init: %w", err)
	}
	if len(p.Nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("snapshot/passphrase: bad nonce length %d", len(p.Nonce))
	}
	plain, err := aead.Open(nil, p.Nonce, cipher, nil)
	if err != nil {
		// AEAD failure is the canonical "wrong passphrase or tampered
		// ciphertext" signal — both look the same from the outside.
		return nil, fmt.Errorf("snapshot/passphrase: open: %w", err)
	}
	return plain, nil
}

// wipe zeroes a key buffer so it doesn't linger on the GC heap. Best
// effort — Go can move memory around freely, so this is a defense in
// depth, not a guarantee.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Compile-time interface check.
var _ snapshot.Sealer = (*Sealer)(nil)
