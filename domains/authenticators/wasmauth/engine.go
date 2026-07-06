package wasmauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// Request is the authentication input marshaled to JSON and written into
// the guest module's linear memory before calling authenticate (see the
// package doc for the exact ABI). Credential is req.Credential verbatim —
// this package does not interpret it, the guest policy module does.
type Request struct {
	Credential map[string]string `json:"credential,omitempty"`
}

// Result is the authentication output the guest module returns as JSON.
// Reason is for audit/debugging only — never parsed or interpreted by
// this package, and never part of the fail-closed contract (only a
// non-nil error from a call, or Authenticated==false, means reject).
type Result struct {
	Authenticated bool              `json:"authenticated"`
	SubjectID     string            `json:"subject_id"`
	Claims        map[string]string `json:"claims,omitempty"`
	Reason        string            `json:"reason"`
}

// Required guest exports, per the ABI contract documented in the package
// doc — mirrors platform/lifecycle/wasmauthz's identical interop pattern.
const (
	fnAlloc        = "alloc"
	fnAuthenticate = "authenticate"
	fnDealloc      = "dealloc"
	exportMemory   = "memory"
)

// DefaultMemoryLimitPages caps each guest instance's linear memory at 256
// wazero pages (16 MiB — a wazero page is 64 KiB). See
// platform/lifecycle/wasmauthz.DefaultMemoryLimitPages's doc for the full
// rationale (an unbounded module could otherwise OOM the host); the value
// and reasoning are identical here.
const DefaultMemoryLimitPages = 256

// ErrInvalidModule is returned by [New] when the supplied WASM module
// does not export the required alloc/authenticate/dealloc functions
// (with the required arity) or the required "memory" export — an ABI
// mismatch caught at CONSTRUCTION time, never silently at first use.
var ErrInvalidModule = errors.New("wasmauth: module does not satisfy the required ABI")

// ErrGuestFault is returned by [Engine.authenticate] when the guest
// module misbehaves in a way that is not a plain WASM trap: a null/
// out-of-bounds pointer from alloc, or a response the guest claims is at
// an address/length outside its own memory. Like every other
// authenticate error, this MUST be treated as a rejected login (see the
// package doc's "Fail-closed" section).
var ErrGuestFault = errors.New("wasmauth: guest module fault")

// Engine hosts one compiled WASM authentication-policy module. Construct
// with [New]; safe for unlimited concurrent authenticate calls — every
// call gets its own freshly instantiated, anonymous module instance
// (mirrors platform/lifecycle/wasmauthz.Engine's concurrency model
// exactly, for the identical reasons: wazero's api.Function.Call is not
// documented as goroutine-safe per instance, and WithCloseOnContextDone
// permanently closes whichever instance was running when a deadline
// fires, so a shared instance would wedge forever after one slow call).
// The zero value is not usable — always construct via New.
type Engine struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
}

// NewEngine compiles wasmModule (the expensive step, done exactly once
// here) and validates its export table against the required ABI WITHOUT
// instantiating it, so a malformed or ABI-incompatible module fails fast
// at construction time rather than on the first Authenticate call.
//
// wasmModule is the raw bytes of an already-compiled .wasm binary
// supplied by the caller; this package never fetches, reads from a path,
// or compiles from source. Pass the resulting *Engine to [New] to build
// the core.Authenticator.
func NewEngine(ctx context.Context, wasmModule []byte) (*Engine, error) {
	if len(wasmModule) == 0 {
		return nil, fmt.Errorf("%w: empty module", ErrInvalidModule)
	}
	rc := wazero.NewRuntimeConfig().
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(DefaultMemoryLimitPages)
	runtime := wazero.NewRuntimeWithConfig(ctx, rc)

	compiled, err := runtime.CompileModule(ctx, wasmModule)
	if err != nil {
		_ = runtime.Close(ctx)
		return nil, fmt.Errorf("wasmauth: compile module: %w", err)
	}
	if err := validateABI(compiled); err != nil {
		_ = compiled.Close(ctx)
		_ = runtime.Close(ctx)
		return nil, err
	}
	return &Engine{runtime: runtime, compiled: compiled}, nil
}

// validateABI inspects compiled's export table (pure metadata reads, no
// instantiation needed) and fails with ErrInvalidModule when the
// required ABI is not satisfied.
func validateABI(compiled wazero.CompiledModule) error {
	fns := compiled.ExportedFunctions()
	if err := requireFunction(fns, fnAlloc, 1, 1); err != nil {
		return err
	}
	if err := requireFunction(fns, fnAuthenticate, 2, 1); err != nil {
		return err
	}
	if err := requireFunction(fns, fnDealloc, 2, 0); err != nil {
		return err
	}
	if _, ok := compiled.ExportedMemories()[exportMemory]; !ok {
		return fmt.Errorf("%w: missing exported memory %q", ErrInvalidModule, exportMemory)
	}
	return nil
}

// requireFunction fails with ErrInvalidModule unless fns contains name
// with exactly wantParams parameters and wantResults results.
func requireFunction(fns map[string]api.FunctionDefinition, name string, wantParams, wantResults int) error {
	fn, ok := fns[name]
	if !ok {
		return fmt.Errorf("%w: missing exported function %q", ErrInvalidModule, name)
	}
	if len(fn.ParamTypes()) != wantParams || len(fn.ResultTypes()) != wantResults {
		return fmt.Errorf("%w: exported function %q has wrong signature (want %d param(s)/%d result(s), got %d/%d)",
			ErrInvalidModule, name, wantParams, wantResults, len(fn.ParamTypes()), len(fn.ResultTypes()))
	}
	return nil
}

// Close releases the wazero runtime (which transitively releases the
// compiled module and any in-flight instances). Safe to call on a nil
// *Engine. After Close, every Authenticate call fails (fail-closed).
func (e *Engine) Close(ctx context.Context) error {
	if e == nil || e.runtime == nil {
		return nil
	}
	return e.runtime.Close(ctx)
}
