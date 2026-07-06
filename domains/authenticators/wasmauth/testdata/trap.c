// trap.c -- test fixture whose authenticate export deliberately executes
// an `unreachable` WASM instruction (via __builtin_trap), so a call into
// the guest must surface a WASM RUNTIME TRAP error rather than a result
// (fail-closed: see ../authenticate.go). See policy.c for the toolchain
// rationale.
//
// Compiled with (from this directory):
//
//	clang --target=wasm32-unknown-unknown -nostdlib -O0 \
//	  -Wl,--no-entry -Wl,--export-all -Wl,--allow-undefined \
//	  -o trap.wasm trap.c

typedef unsigned int u32;
typedef unsigned long long u64;

static unsigned char buf[64];

__attribute__((visibility("default")))
u32 alloc(u32 size) { (void)size; return (u32)(unsigned long)&buf[0]; }

__attribute__((visibility("default")))
void dealloc(u32 ptr, u32 size) { (void)ptr; (void)size; }

__attribute__((visibility("default")))
u64 authenticate(u32 req_ptr, u32 req_len) {
    (void)req_ptr; (void)req_len;
    __builtin_trap();
    return 0;
}
