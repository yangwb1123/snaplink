package snapshot

// Codec converts a Snapshot to and from its on-the-wire byte form. The
// envelope (Snapshot struct) is identical across codecs; only the
// serialization format differs.
//
// Implementations MUST be deterministic for the same input — the
// pipeline computes a checksum over the encoded bytes, and a
// non-deterministic codec would fail integrity checks on roundtrip.
type Codec interface {
	// Marshal encodes snap. The returned slice is owned by the caller.
	Marshal(snap *Snapshot) ([]byte, error)
	// Unmarshal decodes data into a fresh Snapshot. The codec MUST
	// reject schema versions it cannot handle (use IsValidSchemaVersion
	// or the snapshot.ErrUnknownSchemaVersion sentinel).
	Unmarshal(data []byte) (*Snapshot, error)
	// ContentType is a stable, human-readable identifier persisted in
	// the SealedEnvelope so the loader can pick the right codec.
	ContentType() string
}

// CodecID is the canonical name for a Codec, written into the envelope.
type CodecID string

const (
	CodecJSON CodecID = "json"
)
