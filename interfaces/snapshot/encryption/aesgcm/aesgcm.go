// Package aesgcm encrypts snapshots with a direct 32-byte AES-256
// key + AES-GCM AEAD. Aimed at operators whose KMS / HSM hands
// them raw key bytes (AWS KMS GenerateDataKey, GCP KMS Decrypt of
// a DEK, HashiCorp Vault transit decrypt-into-app) rather than the
// passphrase-derivation flow snapshot/encryption/passphrase
// provides for human-typed secrets.
//
// Each Seal call generates a fresh 12-byte nonce, written into
// SealedEnvelope.EncryptionParams so the pipeline can present
// algorithm + nonce-len to operators without decrypting. The key
// never lands on disk — Sealer holds it in a private []byte and
// the caller is responsible for both supplying + clearing it on
// shutdown (operators wiring this from a KMS-fetched DEK should
// not log the bytes).
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/snaplink/sso/interfaces/snapshot"
)

// KeySize is the AES-256 key length in bytes. Sealers reject keys
// of any other length — operators using AES-128 / AES-192 should
// build their own sealer; the wire algorithm string is unique to
// 256.
const KeySize = 32

// wireVersion stamps the AEAD wire format. Bumped if the AEAD
// choice or nonce-length changes; readers refuse unknown versions.
const wireVersion = 1

// Sealer encrypts snapshots with the supplied 32-byte AES-256 key.
// Key length is validated at construction; subsequent Seal/Open
// calls assume the key is well-formed.
type Sealer struct {
	key []byte
}

// New validates key length (32 bytes) and returns a Sealer. The
// key is COPIED into a private buffer so the caller can wipe their
// source slice without breaking subsequent Seal calls. Empty / wrong-
// length key → error (operators see the misconfiguration at boot).
func New(key []byte) (*Sealer, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("snapshot/aesgcm: key must be %d bytes, got %d", KeySize, len(key))
	}
	cp := make([]byte, KeySize)
	copy(cp, key)
	return &Sealer{key: cp}, nil
}

// Algorithm returns the canonical wire string written into
// SealedEnvelope.Algorithm.
func (s *Sealer) Algorithm() string { return snapshot.EncryptionAESGCM }

// envelopeParams is the JSON shape persisted into
// SealedEnvelope.EncryptionParams. Versioned so future AEAD swaps
// stay backward-compatible.
type envelopeParams struct {
	Version uint32 `json:"version"`
	Nonce   []byte `json:"nonce"`
}

// Seal AEAD-encrypts plain under the configured key. Returns
// (ciphertext, params, error). params carries the wire-format
// version + the fresh nonce — operators rotating snapshots with
// the same key get distinct ciphertexts (nonce reuse with AES-GCM
// is catastrophic; the random 12-byte nonce here is well below
// the 2^32-collision threshold for any realistic snapshot
// cadence).
func (s *Sealer) Seal(plain []byte) ([]byte, []byte, error) {
	if len(s.key) != KeySize {
		return nil, nil, errors.New("snapshot/aesgcm: sealer not configured")
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, nil, fmt.Errorf("snapshot/aesgcm: cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("snapshot/aesgcm: gcm init: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("snapshot/aesgcm: nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plain, nil)
	params, err := json.Marshal(envelopeParams{Version: wireVersion, Nonce: nonce})
	if err != nil {
		return nil, nil, fmt.Errorf("snapshot/aesgcm: marshal params: %w", err)
	}
	return ciphertext, params, nil
}

// Open AEAD-decrypts ciphertext under the configured key + the
// nonce recovered from paramsRaw. AEAD failure surfaces as a
// generic error — "wrong key" and "tampered ciphertext" are
// indistinguishable by construction, same as the passphrase sealer.
func (s *Sealer) Open(ciphertext []byte, paramsRaw []byte) ([]byte, error) {
	if len(s.key) != KeySize {
		return nil, errors.New("snapshot/aesgcm: sealer not configured")
	}
	if len(paramsRaw) == 0 {
		return nil, errors.New("snapshot/aesgcm: missing encryption params")
	}
	var p envelopeParams
	if err := json.Unmarshal(paramsRaw, &p); err != nil {
		return nil, fmt.Errorf("snapshot/aesgcm: unmarshal params: %w", err)
	}
	if p.Version != wireVersion {
		return nil, fmt.Errorf("snapshot/aesgcm: unsupported version %d", p.Version)
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, fmt.Errorf("snapshot/aesgcm: cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("snapshot/aesgcm: gcm init: %w", err)
	}
	if len(p.Nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("snapshot/aesgcm: bad nonce length %d (want %d)", len(p.Nonce), gcm.NonceSize())
	}
	plain, err := gcm.Open(nil, p.Nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("snapshot/aesgcm: open: %w", err)
	}
	return plain, nil
}

// Compile-time interface assertion.
var _ snapshot.Sealer = (*Sealer)(nil)
