// malformed.c -- test fixture whose authorize export satisfies the ABI's
// SIGNATURE but returns bytes that are NOT valid JSON, so
// Engine.Authorize's json.Unmarshal of the Decision must fail (fail-closed:
// see ../authorize.go). See policy.c for the toolchain rationale.
//
// Compiled with (from this directory):
//
//	clang --target=wasm32-unknown-unknown -nostdlib -O0 \
//	  -Wl,--no-entry -Wl,--export-all -Wl,--allow-undefined \
//	  -o malformed.wasm malformed.c

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

// See policy.c for why reserved_zero_page precedes arena: address 0 is the
// host-side ABI's "allocation failed" sentinel, so a real allocation must
// never legitimately land there.
#define ARENA_SIZE 256
static u8 reserved_zero_page[8];
static u8 arena[ARENA_SIZE];
static u32 bump_top = 0;

__attribute__((visibility("default")))
u32 alloc(u32 size) {
    (void)reserved_zero_page;
    if (size > ARENA_SIZE - bump_top) return 0;
    u32 p = (u32)(unsigned long)&arena[bump_top];
    bump_top += size;
    return p;
}

__attribute__((visibility("default")))
void dealloc(u32 ptr, u32 size) { (void)ptr; (void)size; }

static const char GARBAGE[] = "not-json-at-all {{{";

__attribute__((visibility("default")))
u64 authorize(u32 req_ptr, u32 req_len) {
    (void)req_ptr; (void)req_len;
    u32 ptr = (u32)(unsigned long)GARBAGE;
    u32 len = 0;
    while (GARBAGE[len]) len++;
    return ((u64)ptr << 32) | (u64)len;
}
