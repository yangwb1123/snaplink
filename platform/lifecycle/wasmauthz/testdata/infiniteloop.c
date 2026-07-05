// infiniteloop.c -- test fixture whose authorize export never returns, so
// Engine.Authorize's per-call timeout (DefaultCallTimeout, bounded further by
// the test's own short context deadline) must fire and the call must return
// an error (fail-closed: see ../authorize.go). The volatile counter is a
// side effect that keeps clang from proving the loop dead code and
// eliminating/transforming it at higher optimization levels (compiled at
// -O0 anyway, but kept for robustness against toolchain differences). See
// policy.c for the toolchain rationale.
//
// Compiled with (from this directory):
//
//	clang --target=wasm32-unknown-unknown -nostdlib -O0 \
//	  -Wl,--no-entry -Wl,--export-all -Wl,--allow-undefined \
//	  -o infiniteloop.wasm infiniteloop.c

typedef unsigned int u32;
typedef unsigned long long u64;

// A tiny static buffer so alloc can return a real, non-zero address (0 is
// the host-side ABI's "allocation failed" sentinel -- see policy.c) without
// needing a real allocator: this fixture's authorize() never reads the
// buffer anyway, it just loops forever.
static unsigned char buf[64];

__attribute__((visibility("default")))
u32 alloc(u32 size) { (void)size; return (u32)(unsigned long)&buf[0]; }

__attribute__((visibility("default")))
void dealloc(u32 ptr, u32 size) { (void)ptr; (void)size; }

__attribute__((visibility("default")))
u64 authorize(u32 req_ptr, u32 req_len) {
    (void)req_ptr; (void)req_len;
    volatile int x = 0;
    while (1) {
        x = x + 1;
    }
    return 0;
}
