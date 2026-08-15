package snapshot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/yangwb1123/snaplink/shared/core"
)

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

// JSONCodec is the canonical Codec — encoding/json with HTML escaping
// disabled and indented output. Indentation makes diffs friendly when
// snapshots are committed to git for review; for size-sensitive flows
// callers can wrap with their own compact codec.
type JSONCodec struct {
	// Indent toggles the two-space indented form. Defaults to true.
	// Set to false for the compact form when size matters.
	Indent bool
}

// NewJSONCodec is a small convenience over the zero value with Indent on.
func NewJSONCodec() *JSONCodec { return &JSONCodec{Indent: true} }

func (c *JSONCodec) ContentType() string { return string(CodecJSON) }

func (c *JSONCodec) Marshal(snap *Snapshot) ([]byte, error) {
	if snap == nil {
		return nil, errors.New("snapshot/json: nil snapshot")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if c == nil || c.Indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(snap); err != nil {
		return nil, fmt.Errorf("snapshot/json: marshal: %w", err)
	}
	// json.Encoder.Encode appends a trailing newline; keep it — text
	// tools (less, diff) like trailing newlines.
	return buf.Bytes(), nil
}

func (c *JSONCodec) Unmarshal(data []byte) (*Snapshot, error) {
	if len(data) == 0 {
		return nil, errors.New("snapshot/json: empty input")
	}
	var snap Snapshot
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&snap); err != nil {
		return nil, fmt.Errorf("snapshot/json: unmarshal: %w", err)
	}
	if !IsValidSchemaVersion(snap.SchemaVersion) {
		return nil, errors.Join(ErrUnknownSchemaVersion, fmt.Errorf("got %q", snap.SchemaVersion))
	}
	return &snap, nil
}

// Compile-time interface check.
var _ Codec = (*JSONCodec)(nil)

// PaginatedSnapshotStorage is an OPTIONAL extension a Storage MAY implement
// to push List's pagination down into the backend instead of the grpcadmin
// fallback's full List() -> sort.Strings -> offset slice. Same
// optional-extension pattern as core.PaginatedClientStore: callers
// type-assert, absence degrades to List(). Items are snapshot NAME strings
// sorted ascending (the proto exposes no order_by/filter).
type PaginatedSnapshotStorage interface {
	ListPage(ctx context.Context, q core.PageQuery) ([]string, []byte, int, error)
}
