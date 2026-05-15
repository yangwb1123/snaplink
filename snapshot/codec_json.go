package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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
