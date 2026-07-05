package auditspi

import (
	"errors"
	"fmt"
	"testing"
)

// TestErrEventNotFound_WrapsWithErrorsIs confirms ErrEventNotFound survives
// %w-wrapping — every Sink.Get implementation across backends (memory,
// SQLite, ...) wraps it with context (e.g. "get event %s: %w"), and callers
// key their 404 mapping off errors.Is(err, auditspi.ErrEventNotFound). A
// sentinel that stops matching once wrapped would silently turn a 404 into a
// 500 everywhere at once.
func TestErrEventNotFound_WrapsWithErrorsIs(t *testing.T) {
	t.Parallel()
	wrapped := fmt.Errorf("get event %s: %w", "abc123", ErrEventNotFound)
	if !errors.Is(wrapped, ErrEventNotFound) {
		t.Fatal("wrapped ErrEventNotFound no longer matches errors.Is")
	}
	if errors.Is(wrapped, errors.New("audit: event not found")) {
		t.Fatal("errors.Is matched a distinct error value with the same message; sentinel identity broke")
	}
}
