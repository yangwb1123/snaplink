package wasmauthz

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// DefaultCallTimeout bounds a single Authorize call's guest execution time.
// The guest module is untrusted, operator-supplied code; without a bound, a
// policy module that loops or blocks would hang its caller forever. ctx's
// own deadline (if any) still applies ON TOP of this — context.WithTimeout
// always resolves to the EARLIER of the two, so a caller may pass a shorter
// deadline but never a longer effective one.
const DefaultCallTimeout = 5 * time.Second

// Authorize evaluates req against the hosted WASM policy module and returns
// its [Decision]. Safe for unlimited concurrent use (see the package doc's
// "Concurrency" section): every call gets its OWN freshly instantiated,
// anonymous module instance drawn from the one CompiledModule built at
// [New], and that instance is closed again before Authorize returns,
// regardless of outcome.
//
// FAIL-CLOSED: a non-nil error means the decision could not be evaluated —
// a guest trap, a malformed JSON response, an out-of-bounds pointer, or the
// per-call timeout firing. The caller MUST treat ANY error as a denial,
// never as "inconclusive, so allow" (see the package doc's "Fail-closed"
// section for why — this mirrors this SDK's CAEP-receiver and federation
// trust-chain fail-closed doctrine). A zero-value Decision is returned
// alongside every error; callers must not act on it.
func (e *Engine) Authorize(ctx context.Context, req Request) (Decision, error) {
	if e == nil || e.runtime == nil || e.compiled == nil {
		return Decision{}, fmt.Errorf("wasmauthz: %w", ErrGuestFault)
	}
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return Decision{}, fmt.Errorf("wasmauthz: marshal request: %w", err)
	}

	callCtx, cancel := context.WithTimeout(ctx, DefaultCallTimeout)
	defer cancel()

	mod, err := e.runtime.InstantiateModule(callCtx, e.compiled, wazero.NewModuleConfig().WithName(""))
	if err != nil {
		return Decision{}, fmt.Errorf("wasmauthz: instantiate module: %w", err)
	}
	// Best-effort cleanup with a fresh context: callCtx may already be
	// past its deadline (WithCloseOnContextDone may have closed mod
	// already, in which case this is a harmless no-op), and cleanup must
	// not be skipped just because the call itself timed out.
	defer func() { _ = mod.Close(context.Background()) }()

	respJSON, err := callAuthorize(callCtx, mod, reqJSON)
	if err != nil {
		return Decision{}, err
	}
	var dec Decision
	if err := json.Unmarshal(respJSON, &dec); err != nil {
		return Decision{}, fmt.Errorf("wasmauthz: %w: decode decision: %v", ErrGuestFault, err)
	}
	return dec, nil
}

// callAuthorize runs the ABI's alloc -> write -> authorize -> read -> dealloc
// sequence (see the package doc) against one already-instantiated mod, and
// returns a COPY of the guest's response bytes (copied out of guest memory
// before dealloc runs, since dealloc may let the guest reuse that block).
func callAuthorize(ctx context.Context, mod api.Module, reqJSON []byte) ([]byte, error) {
	mem := mod.Memory()
	if mem == nil {
		return nil, fmt.Errorf("wasmauthz: %w: module exports no memory", ErrGuestFault)
	}
	reqPtr, err := guestAlloc(ctx, mod, uint32(len(reqJSON)))
	if err != nil {
		return nil, err
	}
	if !mem.Write(reqPtr, reqJSON) {
		return nil, fmt.Errorf("wasmauthz: %w: writing %d-byte request at guest pointer %d", ErrGuestFault, len(reqJSON), reqPtr)
	}

	authorizeFn := mod.ExportedFunction(fnAuthorize)
	results, err := authorizeFn.Call(ctx, uint64(reqPtr), uint64(len(reqJSON)))
	if err != nil {
		return nil, fmt.Errorf("wasmauthz: guest authorize trapped: %w", err)
	}
	respPtr, respLen := unpackPtrLen(results[0])
	respView, ok := mem.Read(respPtr, respLen)
	if !ok {
		return nil, fmt.Errorf("wasmauthz: %w: guest returned out-of-bounds response (ptr=%d len=%d)", ErrGuestFault, respPtr, respLen)
	}
	resp := append([]byte(nil), respView...)

	// Best-effort memory hygiene: a dealloc trap must not fail an
	// otherwise-successful decision, since resp is already copied out.
	guestDealloc(ctx, mod, reqPtr, uint32(len(reqJSON)))
	guestDealloc(ctx, mod, respPtr, respLen)
	return resp, nil
}

// guestAlloc calls the guest's alloc export and validates the result is a
// usable (non-null, for a non-empty request) pointer.
func guestAlloc(ctx context.Context, mod api.Module, size uint32) (uint32, error) {
	allocFn := mod.ExportedFunction(fnAlloc)
	results, err := allocFn.Call(ctx, uint64(size))
	if err != nil {
		return 0, fmt.Errorf("wasmauthz: guest alloc trapped: %w", err)
	}
	ptr := uint32(results[0])
	if ptr == 0 && size > 0 {
		return 0, fmt.Errorf("wasmauthz: %w: guest alloc(%d) returned null", ErrGuestFault, size)
	}
	return ptr, nil
}

// guestDealloc calls the guest's dealloc export, discarding any error — see
// callAuthorize's comment on why a dealloc failure must not fail the call.
func guestDealloc(ctx context.Context, mod api.Module, ptr, size uint32) {
	deallocFn := mod.ExportedFunction(fnDealloc)
	if deallocFn == nil {
		return
	}
	_, _ = deallocFn.Call(ctx, uint64(ptr), uint64(size))
}

// unpackPtrLen splits authorize's packed uint64 return value into the
// response pointer (high 32 bits) and length (low 32 bits) — see the
// package doc's ABI contract.
func unpackPtrLen(packed uint64) (ptr, length uint32) {
	return uint32(packed >> 32), uint32(packed)
}
