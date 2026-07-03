package configaudit

import "testing"

func TestDigest_StableAcrossMapIterationOrder(t *testing.T) {
	a := map[string]any{"z": "1", "a": "2", "m": map[string]any{"x": "1", "y": "2"}}
	b := map[string]any{"a": "2", "m": map[string]any{"y": "2", "x": "1"}, "z": "1"}

	da, err := Digest(a)
	if err != nil {
		t.Fatalf("Digest(a): %v", err)
	}
	db, err := Digest(b)
	if err != nil {
		t.Fatalf("Digest(b): %v", err)
	}
	if da != db {
		t.Errorf("structurally identical maps must digest identically: %q != %q", da, db)
	}
	if len(da) != 64 {
		t.Errorf("expected a 64-char sha256 hex digest, got %d chars: %q", len(da), da)
	}
}

func TestDigest_DiffersOnChange(t *testing.T) {
	a := map[string]any{"a": "1"}
	b := map[string]any{"a": "2"}
	da, _ := Digest(a)
	db, _ := Digest(b)
	if da == db {
		t.Errorf("differing maps must not digest identically")
	}
}
