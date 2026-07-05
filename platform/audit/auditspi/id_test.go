package auditspi

import (
	"encoding/hex"
	"testing"
)

// TestNewEventID_FormatAndUniqueness pins the wire format every sink relies
// on: a 24-char lowercase hex string (12 random bytes). Sinks that persist
// IDs (SQLite index, webhook JSON) assume this shape; a change here is a
// storage-compatibility break, not a free refactor.
func TestNewEventID_FormatAndUniqueness(t *testing.T) {
	t.Parallel()
	const n = 1000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id := NewEventID()
		if len(id) != 24 {
			t.Fatalf("NewEventID() len = %d, want 24 (id=%q)", len(id), id)
		}
		if _, err := hex.DecodeString(id); err != nil {
			t.Fatalf("NewEventID() = %q, not valid hex: %v", id, err)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("NewEventID() produced duplicate %q across %d calls", id, n)
		}
		seen[id] = struct{}{}
	}
}
