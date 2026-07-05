// trap.c -- test fixture whose authorize export deliberately executes an
// `unreachable` WASM instruction (via __builtin_trap), so
// Engine.Authorize's call into the guest must surface a WASM RUNTIME TRAP
// error rather than a decision (fail-closed: see ../authorize.go) -- this
// exercises the "guest module trap" failure mode distinctly from a
// malformed JSON response (malformed.c) or a timeout (infiniteloop.c). See
// policy.c for the toolchain rationale.
//
// Compiled with (from this directory):
//
//	clang --target=wasm32-unknown-unknown -nostdlib -O0 \
//	  -Wl,--no-entry -Wl,--export-all -Wl,--allow-undefined \
//	  -o trap.wasm trap.c

typedef unsigned int u32;
typedef unsigned long long u64;

// A tiny static buffer so alloc can return a real, non-zero address (0 is
// the host-side ABI's "allocation failed" sentinel -- see policy.c) without
// needing a real allocator: this fixture's authorize() never reads the
// buffer anyway, it just traps.
static unsigned char buf[64];

__attribute__((visibility("default")))
u32 alloc(u32 size) { (void)size; return (u32)(unsigned long)&buf[0]; }

__attribute__((visibility("default")))
void dealloc(u32 ptr, u32 size) { (void)ptr; (void)size; }

__attribute__((visibility("default")))
u64 authorize(u32 req_ptr, u32 req_len) {
    (void)req_ptr; (void)req_len;
    __builtin_trap();
    return 0;
}
