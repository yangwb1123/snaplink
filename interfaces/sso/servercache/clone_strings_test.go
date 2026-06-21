package servercache

import "testing"

func TestCloneStrings(t *testing.T) {
	t.Parallel()

	orig := []string{"a", "b", "c"}
	cloned := cloneStrings(orig)
	if len(cloned) != 3 {
		t.Fatalf("cloneStrings() len = %d, want 3", len(cloned))
	}
	// Mutating clone should not affect original
	cloned[0] = "modified"
	if orig[0] != "a" {
		t.Error("cloneStrings() should not alias original")
	}

	// Nil input
	if cloneStrings(nil) != nil {
		t.Error("cloneStrings(nil) should return nil")
	}
}
