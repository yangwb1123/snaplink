package wasmauthz

import (
	"context"
	"errors"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// Request is the authorization input marshaled to JSON and written into the
// guest module's linear memory before calling authorize (see the package doc
// for the exact ABI). Subject/Action/Resource are free-form strings — this
// package does not interpret them, the guest policy module does. Context
// carries anything else a policy needs (subject roles, tenant id, source IP,
// …) without requiring an ABI change for every new attribute a policy author
// wants to consult.
type Request struct {
	Subject  string            `json:"subject"`
	Action   string            `json:"action"`
	Resource string            `json:"resource"`
	Context  map[string]string `json:"context,omitempty"`
}

// Decision is the authorization output the guest module returns as JSON.
// Reason is for audit/debugging only — never parsed or interpreted by this
// package, and never part of the fail-closed contract (only a non-nil error
// from Authorize means "treat as denied"; a Decision with Allowed==false is
// an ordinary, successfully-evaluated denial).
type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// Required guest exports, per the ABI contract documented in the package doc.
const (
	fnAlloc      = "alloc"
	fnAuthorize  = "authorize"
	fnDealloc    = "dealloc"
	exportMemory = "memory"
)

// DefaultMemoryLimitPages caps each guest instance's linear memory at 256
// wazero pages (16 MiB — a wazero page is 64 KiB). Without an explicit
// ceiling, wazero defaults to allowing a module whose memory section omits
// a max (the ordinary shape of a plain wasm-ld/TinyGo build, exactly what
// this package's own testdata fixtures are) to grow to 4 GiB; since a fresh
// instance is created per Authorize call (see the package doc's
// "Concurrency" section) and the guest is documented as untrusted,
// operator-supplied code, an unbounded ceiling lets one malicious or buggy
// module exhaust host memory well within DefaultCallTimeout. 16 MiB is far
// beyond what a JSON authorization request/response needs.
const DefaultMemoryLimitPages = 256

// ErrInvalidModule is returned by [New] when the supplied WASM module does
// not export the required alloc/authorize/dealloc functions (with the
// required arity) or the required "memory" export — an ABI mismatch caught
// at CONSTRUCTION time, never silently at first use.
var ErrInvalidModule = errors.New("wasmauthz: module does not satisfy the required ABI")

// ErrGuestFault is returned by [Engine.Authorize] when the guest module
// misbehaves in a way that is not a plain WASM trap: a null/out-of-bounds
// pointer from alloc, or a response the guest claims is at an address/length
// outside its own memory. Like every other Authorize error, this MUST be
// treated by the caller as a denial (see the package doc's "Fail-closed"
// section).
var ErrGuestFault = errors.New("wasmauthz: guest module fault")

// Engine hosts one compiled WASM authorization-policy module. Construct with
// [New]; safe for unlimited concurrent [Engine.Authorize] calls (see the
// package doc's "Concurrency" section for why a persistent shared module
// instance is deliberately NOT used). The zero value is not usable — always
// construct via New.
type Engine struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
}

// New compiles wasmModule (the expensive step: parsing, validation, and
// machine-code generation happen exactly ONCE, here) and validates its
// export table against the required ABI (see the package doc) WITHOUT
// instantiating it — a cheap, metadata-only check, so a malformed or
// ABI-incompatible module fails fast at construction time rather than on
// the first Authorize call.
//
// wasmModule is the raw bytes of an already-compiled .wasm binary supplied
// by the caller; this package never fetches, reads from a path, or compiles
// from source — matching the same "supplied by caller, not resolved by us"
// pattern [github.com/yangwb1123/snaplink/interfaces/sso.WithSCIMProvisioner] and
// [github.com/yangwb1123/snaplink/interfaces/sso.WithRebacEngine] already use for
// their own plugins.
func New(ctx context.Context, wasmModule []byte) (*Engine, error) {
	if len(wasmModule) == 0 {
		return nil, fmt.Errorf("%w: empty module", ErrInvalidModule)
	}
	// WithCloseOnContextDone lets a per-call context deadline actually
	// interrupt a looping/blocked guest (see Authorize) instead of merely
	// giving up on the Go side while the guest keeps burning CPU forever.
	// WithMemoryLimitPages bounds each instance's linear memory (see
	// DefaultMemoryLimitPages) so an unbounded-growth guest can't OOM the
	// host process.
	rc := wazero.NewRuntimeConfig().
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(DefaultMemoryLimitPages)
	runtime := wazero.NewRuntimeWithConfig(ctx, rc)

	compiled, err := runtime.CompileModule(ctx, wasmModule)
	if err != nil {
		_ = runtime.Close(ctx)
		return nil, fmt.Errorf("wasmauthz: compile module: %w", err)
	}
	if err := validateABI(compiled); err != nil {
		_ = compiled.Close(ctx)
		_ = runtime.Close(ctx)
		return nil, err
	}
	return &Engine{runtime: runtime, compiled: compiled}, nil
}

// validateABI inspects compiled's export table (no instantiation needed —
// CompiledModule.ExportedFunctions/ExportedMemories are pure metadata reads)
// and fails with ErrInvalidModule when the required ABI is not satisfied.
func validateABI(compiled wazero.CompiledModule) error {
	fns := compiled.ExportedFunctions()
	if err := requireFunction(fns, fnAlloc, 1, 1); err != nil {
		return err
	}
	if err := requireFunction(fns, fnAuthorize, 2, 1); err != nil {
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

// requireFunction fails with ErrInvalidModule unless fns contains name with
// exactly wantParams parameters and wantResults results — an arity check,
// not a full type check, but enough to catch the overwhelmingly common
// mistake (wrong parameter/result count) at construction time.
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
// *Engine. After Close, every Authorize call fails (fail-closed).
func (e *Engine) Close(ctx context.Context) error {
	if e == nil || e.runtime == nil {
		return nil
	}
	return e.runtime.Close(ctx)
}
