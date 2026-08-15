package snapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Storage is the persistence interface for sealed snapshots. Implementations
// live in snapshot/storage/*. A Storage handles only opaque bytes — codec
// and encryption are handled higher up by Pipeline.
type Storage interface {
	// Put stores data under name. Implementations MAY reject names with
	// path separators or other unsafe characters. Overwrites are allowed
	// (older copy is replaced).
	Put(ctx context.Context, name string, data []byte) error
	// Get fetches the bytes previously written under name. Returns
	// ErrSnapshotNotFound when missing.
	Get(ctx context.Context, name string) ([]byte, error)
	// List enumerates the names known to the storage in arbitrary order.
	List(ctx context.Context) ([]string, error)
	// Delete removes name. Idempotent: missing names return nil so
	// retry loops don't churn.
	Delete(ctx context.Context, name string) error
}

// ErrSnapshotNotFound is the sentinel Storage.Get implementations should
// return for missing names. Callers branch on this via errors.Is.
var ErrSnapshotNotFound = errors.New("snapshot: not found")

// Sealer applies (or skips) encryption around the codec-encoded bytes.
// Pipeline.Save calls Seal once on the marshaled bytes; Pipeline.Load
// calls Open once on the envelope's body.
//
// The "none" sealer is the no-op default — an explicit opt-out so
// pipelines never accidentally store cleartext when an encryption sealer
// was the intent.
type Sealer interface {
	// Algorithm is the canonical name persisted in the SealedEnvelope
	// (see EncryptionAlgorithm constants).
	Algorithm() string
	// Seal wraps plaintext into ciphertext + an opaque parameter blob
	// (salt, nonce, etc.) that Open later needs.
	Seal(plain []byte) (cipher []byte, params []byte, err error)
	// Open reverses Seal using the params recovered from the envelope.
	Open(cipher []byte, params []byte) (plain []byte, err error)
}

// PurposeSealer is an OPTIONAL Sealer capability: derive a
// purpose-separated Sealer from this one. The derived sealer's key is
// HKDF-SHA256 over the master key material with info=purpose, so
// ciphertexts sealed for one purpose cannot be opened (or swapped) under
// another, and each derived sealer mints its own random nonces (the AEAD
// nonce domain stays per-purpose).
//
// encryptionaesgcm and encryptionpassphrase implement it; the none
// sealer deliberately does not — no real encryption, no purpose
// separation, which is exactly the fail-closed gate the TOTP-seed
// envelope relies on (no encryption ⇒ seeds never leave the node).
type PurposeSealer interface {
	DeriveSealer(purpose string) (Sealer, error)
}

// EncryptionAlgorithm constants. These are written into the envelope so
// readers know which Sealer to use.
const (
	EncryptionNone       = "none"
	EncryptionPassphrase = "passphrase-argon2id-chacha20poly1305"
	EncryptionAESGCM     = "aes-256-gcm"
)

// EnvelopeVersion is the wire-format version of SealedEnvelope. Bumped on
// breaking changes to the envelope shape.
const EnvelopeVersion = "1"

// SealedEnvelope is the wire format Pipeline writes to Storage. Header
// fields stay readable (json) so operators can `cat` an envelope and
// confirm what they're holding without decrypting.
type SealedEnvelope struct {
	EnvelopeVersion  string `json:"envelope_version"`
	SnapshotID       string `json:"snapshot_id"`
	Codec            string `json:"codec"`
	Algorithm        string `json:"encryption_algorithm"`
	EncryptionParams []byte `json:"encryption_params,omitempty"`
	ChecksumSHA256   string `json:"plaintext_sha256_hex"`
	Body             []byte `json:"body"`

	// Kind mirrors Snapshot.Kind as an additive header field (empty for
	// ordinary exports). It lives HERE, not in the body, so retention and
	// List can classify artifacts with PeekEnvelope alone (no decryption)
	// and pre-change binaries still decode every body byte-identically
	// (the body codec rejects unknown fields). Old readers ignore the
	// unknown header field; new readers treat its absence as "ordinary".
	Kind string `json:"kind,omitempty"`
}

// Pipeline composes a Codec + Sealer + Storage. Construct one and re-use
// across many snapshots — implementations are stateless.
type Pipeline struct {
	Codec  Codec  // defaults to NewJSONCodec when nil
	Sealer Sealer // defaults to a no-op when nil — must be explicit if encryption is required
}

// Save marshals snap, seals the bytes, wraps them in a SealedEnvelope,
// and stores the envelope under name. The envelope JSON is deterministic
// (header field order via json marshaling) so identical snapshots produce
// identical files when no encryption is configured.
func (p *Pipeline) Save(ctx context.Context, snap *Snapshot, dst Storage, name string) error {
	if snap == nil {
		return errors.New("snapshot/pipeline: nil snapshot")
	}
	if dst == nil {
		return errors.New("snapshot/pipeline: nil storage")
	}
	codec := p.codec()
	plain, err := codec.Marshal(snap)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(plain)

	sealer := p.sealer()
	cipher, params, err := sealer.Seal(plain)
	if err != nil {
		return fmt.Errorf("snapshot/pipeline: seal: %w", err)
	}
	env := SealedEnvelope{
		EnvelopeVersion:  EnvelopeVersion,
		SnapshotID:       snap.SnapshotID,
		Codec:            codec.ContentType(),
		Algorithm:        sealer.Algorithm(),
		EncryptionParams: params,
		ChecksumSHA256:   hex.EncodeToString(sum[:]),
		Body:             cipher,
		Kind:             snap.Kind,
	}
	raw, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("snapshot/pipeline: envelope marshal: %w", err)
	}
	return dst.Put(ctx, name, raw)
}

// Load reverses Save — fetches the envelope bytes, unwraps + opens, and
// decodes back to a Snapshot. ErrChecksumMismatch is returned when the
// recomputed SHA-256 doesn't match the envelope's recorded one (catches
// silent corruption + tampering attempts).
func (p *Pipeline) Load(ctx context.Context, src Storage, name string) (*Snapshot, error) {
	if src == nil {
		return nil, errors.New("snapshot/pipeline: nil storage")
	}
	raw, err := src.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	var env SealedEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("snapshot/pipeline: envelope unmarshal: %w", err)
	}
	if env.EnvelopeVersion != EnvelopeVersion {
		return nil, fmt.Errorf("snapshot/pipeline: unknown envelope version %q (want %q)", env.EnvelopeVersion, EnvelopeVersion)
	}

	codec := p.codec()
	if env.Codec != codec.ContentType() {
		return nil, fmt.Errorf("snapshot/pipeline: codec mismatch: envelope=%q pipeline=%q", env.Codec, codec.ContentType())
	}

	sealer := p.sealer()
	if env.Algorithm != sealer.Algorithm() {
		return nil, fmt.Errorf("snapshot/pipeline: algorithm mismatch: envelope=%q pipeline=%q", env.Algorithm, sealer.Algorithm())
	}

	plain, err := sealer.Open(env.Body, env.EncryptionParams)
	if err != nil {
		return nil, fmt.Errorf("snapshot/pipeline: open: %w", err)
	}

	sum := sha256.Sum256(plain)
	want, err := hex.DecodeString(env.ChecksumSHA256)
	if err != nil || len(want) != sha256.Size {
		return nil, fmt.Errorf("snapshot/pipeline: checksum encoding: %w", err)
	}
	if !bytesEq(sum[:], want) {
		return nil, ErrChecksumMismatch
	}
	snap, err := codec.Unmarshal(plain)
	if err != nil {
		return nil, err
	}
	// Kind is header-only; re-attach it so in-memory consumers (the
	// orchestrator's recursion guard, rollback validation) see the same
	// classification PeekEnvelope reports.
	snap.Kind = env.Kind
	return snap, nil
}

// PeekEnvelope decodes the SealedEnvelope wrapper from raw bytes
// without touching Body — useful for List endpoints that want to render
// header metadata (snapshot id, codec, algorithm, taken_at) without
// paying the cost of decryption + Codec.Unmarshal. The Body field on
// the returned envelope is intentionally cleared.
func PeekEnvelope(raw []byte) (SealedEnvelope, error) {
	var env SealedEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return SealedEnvelope{}, fmt.Errorf("snapshot/pipeline: peek: %w", err)
	}
	env.Body = nil
	return env, nil
}

func (p *Pipeline) codec() Codec {
	if p.Codec != nil {
		return p.Codec
	}
	return NewJSONCodec()
}

func (p *Pipeline) sealer() Sealer {
	if p.Sealer != nil {
		return p.Sealer
	}
	return noopSealer{}
}

// noopSealer is the explicit "no encryption" Sealer. Pipeline picks it
// up when Sealer is nil; consumers wanting it explicitly should use the
// snapshot/encryption/none package which re-exports a typed value.
type noopSealer struct{}

func (noopSealer) Algorithm() string { return EncryptionNone }
func (noopSealer) Seal(plain []byte) (cipher []byte, params []byte, err error) {
	out := make([]byte, len(plain))
	copy(out, plain)
	return out, nil, nil
}
func (noopSealer) Open(cipher []byte, _ []byte) (plain []byte, err error) {
	out := make([]byte, len(cipher))
	copy(out, cipher)
	return out, nil
}

// bytesEq is a tiny helper to avoid importing crypto/subtle for an
// integrity (not secrecy) check.
func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
