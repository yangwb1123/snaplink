// missingexport.c -- deliberately ABI-INCOMPLETE test fixture: exports
// alloc and dealloc but NOT authenticate, so New's construction-time
// export validation (see ../engine.go's validateABI) must reject it. See
// policy.c for the toolchain rationale.
//
// Compiled with (from this directory):
//
//	clang --target=wasm32-unknown-unknown -nostdlib -O0 \
//	  -Wl,--no-entry -Wl,--export-all -Wl,--allow-undefined \
//	  -o missingexport.wasm missingexport.c

typedef unsigned int u32;
__attribute__((visibility("default")))
u32 alloc(u32 size) { (void)size; return 0; }
__attribute__((visibility("default")))
void dealloc(u32 ptr, u32 size) { (void)ptr; (void)size; }
