package wasmauthz_test

// Construction-time (New) tests: the module compiles and its ABI is
// validated eagerly, so a malformed/incompatible module must fail HERE,
// never silently at the first Authorize call. Every fixture loaded below is
// a REAL, genuinely-compiled WASM binary (see testdata/*.c) exercised
// end-to-end through wazero — no mocks, per this repo's testing philosophy.

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/snaplink/sso/platform/lifecycle/wasmauthz"
)

// loadFixture reads a compiled .wasm test fixture from testdata/. t.Fatal on
// any read error (a missing fixture is a test-setup bug, not a case to
// assert on).
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return data
}

func TestNew_ValidModule(t *testing.T) {
	t.Parallel()
	eng, err := wasmauthz.New(context.Background(), loadFixture(t, "policy.wasm"))
	if err != nil {
		t.Fatalf("New(policy.wasm): %v", err)
	}
	defer func() { _ = eng.Close(context.Background()) }()
}

func TestNew_EmptyModule(t *testing.T) {
	t.Parallel()
	_, err := wasmauthz.New(context.Background(), nil)
	if !errors.Is(err, wasmauthz.ErrInvalidModule) {
		t.Fatalf("New(nil) error = %v, want ErrInvalidModule", err)
	}
}

func TestNew_MissingAuthorizeExport(t *testing.T) {
	t.Parallel()
	// missingexport.wasm exports alloc/dealloc but not authorize -- the ABI
	// mismatch a real policy-module author is most likely to hit.
	_, err := wasmauthz.New(context.Background(), loadFixture(t, "missingexport.wasm"))
	if !errors.Is(err, wasmauthz.ErrInvalidModule) {
		t.Fatalf("New(missingexport.wasm) error = %v, want ErrInvalidModule", err)
	}
}

func TestNew_NotAWasmModule(t *testing.T) {
	t.Parallel()
	_, err := wasmauthz.New(context.Background(), []byte("this is not a wasm binary"))
	if err == nil {
		t.Fatal("New(garbage bytes) succeeded, want a compile error")
	}
}

func TestEngine_Close_NilSafe(t *testing.T) {
	t.Parallel()
	var eng *wasmauthz.Engine
	if err := eng.Close(context.Background()); err != nil {
		t.Fatalf("nil *Engine Close() = %v, want nil", err)
	}
}

func TestEngine_Close_Idempotent(t *testing.T) {
	t.Parallel()
	eng, err := wasmauthz.New(context.Background(), loadFixture(t, "policy.wasm"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Close(context.Background()); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := eng.Close(context.Background()); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
