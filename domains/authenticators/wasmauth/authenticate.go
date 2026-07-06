package wasmauth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// DefaultCallTimeout bounds a single authenticate call's guest execution
// time. The guest module is untrusted, operator-supplied code; without a
// bound, a policy module that loops or blocks would hang its caller
// forever. ctx's own deadline (if any) still applies ON TOP of this.
const DefaultCallTimeout = 5 * time.Second

// authenticate evaluates req against the hosted WASM module and returns
// its [Result]. Safe for unlimited concurrent use — every call gets its
// own freshly instantiated, anonymous module instance drawn from the one
// CompiledModule built at [New], closed again before authenticate
// returns, regardless of outcome.
//
// FAIL-CLOSED: a non-nil error means the credential could NOT be
// verified — a guest trap, a malformed JSON response, an out-of-bounds
// pointer, or the per-call timeout firing. The caller (Authenticator.
// Authenticate) MUST treat ANY error as a rejected login, never as
// "inconclusive, so allow" (see the package doc's "Fail-closed"
// section).
func (e *Engine) authenticate(ctx context.Context, req Request) (Result, error) {
	if e == nil || e.runtime == nil || e.compiled == nil {
		return Result{}, fmt.Errorf("wasmauth: %w", ErrGuestFault)
	}
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return Result{}, fmt.Errorf("wasmauth: marshal request: %w", err)
	}

	callCtx, cancel := context.WithTimeout(ctx, DefaultCallTimeout)
	defer cancel()

	mod, err := e.runtime.InstantiateModule(callCtx, e.compiled, wazero.NewModuleConfig().WithName(""))
	if err != nil {
		return Result{}, fmt.Errorf("wasmauth: instantiate module: %w", err)
	}
	// Best-effort cleanup with a fresh context: callCtx may already be
	// past its deadline (WithCloseOnContextDone may have closed mod
	// already, in which case this is a harmless no-op).
	defer func() { _ = mod.Close(context.Background()) }()

	respJSON, err := callAuthenticate(callCtx, mod, reqJSON)
	if err != nil {
		return Result{}, err
	}
	var res Result
	if err := json.Unmarshal(respJSON, &res); err != nil {
		return Result{}, fmt.Errorf("wasmauth: %w: decode result: %v", ErrGuestFault, err)
	}
	return res, nil
}

// callAuthenticate runs the ABI's alloc -> write -> authenticate -> read
// -> dealloc sequence against one already-instantiated mod, returning a
// COPY of the guest's response bytes (copied before dealloc runs, since
// dealloc may let the guest reuse that block).
func callAuthenticate(ctx context.Context, mod api.Module, reqJSON []byte) ([]byte, error) {
	mem := mod.Memory()
	if mem == nil {
		return nil, fmt.Errorf("wasmauth: %w: module exports no memory", ErrGuestFault)
	}
	reqPtr, err := guestAlloc(ctx, mod, uint32(len(reqJSON)))
	if err != nil {
		return nil, err
	}
	if !mem.Write(reqPtr, reqJSON) {
		return nil, fmt.Errorf("wasmauth: %w: writing %d-byte request at guest pointer %d", ErrGuestFault, len(reqJSON), reqPtr)
	}

	authenticateFn := mod.ExportedFunction(fnAuthenticate)
	results, err := authenticateFn.Call(ctx, uint64(reqPtr), uint64(len(reqJSON)))
	if err != nil {
		return nil, fmt.Errorf("wasmauth: guest authenticate trapped: %w", err)
	}
	respPtr, respLen := unpackPtrLen(results[0])
	respView, ok := mem.Read(respPtr, respLen)
	if !ok {
		return nil, fmt.Errorf("wasmauth: %w: guest returned out-of-bounds response (ptr=%d len=%d)", ErrGuestFault, respPtr, respLen)
	}
	resp := append([]byte(nil), respView...)

	// Best-effort memory hygiene: a dealloc trap must not fail an
	// otherwise-successful result, since resp is already copied out.
	guestDealloc(ctx, mod, reqPtr, uint32(len(reqJSON)))
	guestDealloc(ctx, mod, respPtr, respLen)
	return resp, nil
}

// guestAlloc calls the guest's alloc export and validates the result is
// a usable (non-null, for a non-empty request) pointer.
func guestAlloc(ctx context.Context, mod api.Module, size uint32) (uint32, error) {
	allocFn := mod.ExportedFunction(fnAlloc)
	results, err := allocFn.Call(ctx, uint64(size))
	if err != nil {
		return 0, fmt.Errorf("wasmauth: guest alloc trapped: %w", err)
	}
	ptr := uint32(results[0])
	if ptr == 0 && size > 0 {
		return 0, fmt.Errorf("wasmauth: %w: guest alloc(%d) returned null", ErrGuestFault, size)
	}
	return ptr, nil
}

// guestDealloc calls the guest's dealloc export, discarding any error —
// see callAuthenticate's comment on why a dealloc failure must not fail
// the call.
func guestDealloc(ctx context.Context, mod api.Module, ptr, size uint32) {
	deallocFn := mod.ExportedFunction(fnDealloc)
	if deallocFn == nil {
		return
	}
	_, _ = deallocFn.Call(ctx, uint64(ptr), uint64(size))
}

// unpackPtrLen splits authenticate's packed uint64 return value into the
// response pointer (high 32 bits) and length (low 32 bits).
func unpackPtrLen(packed uint64) (ptr, length uint32) {
	return uint32(packed >> 32), uint32(packed)
}
