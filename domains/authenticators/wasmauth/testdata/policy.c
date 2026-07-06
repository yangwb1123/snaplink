// policy.c -- reference WASM authentication module for this package's
// tests (see ../doc.go for the ABI contract: exported "memory" +
// alloc/authenticate/dealloc). Mirrors
// platform/lifecycle/wasmauthz/testdata/policy.c's toolchain rationale
// and bump-allocator approach exactly -- see that file's header comment
// for why a freestanding C99 fixture compiled with clang's wasm32 backend
// (rather than requiring TinyGo) is used.
//
// Compiled with (from this directory):
//
//	clang --target=wasm32-unknown-unknown -nostdlib -O0 \
//	  -Wl,--no-entry -Wl,--export-all -Wl,--allow-undefined \
//	  -o policy.wasm policy.c
//
// Policy (intentionally trivial -- this is a TEST fixture, not a real
// authentication scheme):
//   - AUTHENTICATED, subject_id "alice", when the request JSON contains
//     `"username":"alice"` AND `"password":"correct-horse"`.
//   - REJECTED otherwise.
//
// Byte-substring matching on the host's json.Marshal output is safe here
// because this package's Request field order/encoding is fixed (see
// ../engine.go) -- a REAL policy module should parse JSON properly.

typedef unsigned char  u8;
typedef unsigned int   u32;
typedef unsigned long long u64;

#define ARENA_SIZE (1 << 16)
static u8 reserved_zero_page[8];
static u8 arena[ARENA_SIZE];
static u32 bump_top = 0;

__attribute__((visibility("default")))
u32 alloc(u32 size) {
    (void)reserved_zero_page;
    if (size > ARENA_SIZE - bump_top) {
        return 0;
    }
    u32 ptr = (u32)(unsigned long)&arena[bump_top];
    bump_top += size;
    return ptr;
}

__attribute__((visibility("default")))
void dealloc(u32 ptr, u32 size) {
    (void)ptr;
    (void)size;
}

static int has(const u8 *buf, u32 len, const char *needle) {
    u32 nlen = 0;
    while (needle[nlen]) nlen++;
    if (nlen == 0 || nlen > len) return 0;
    for (u32 i = 0; i + nlen <= len; i++) {
        u32 j = 0;
        while (j < nlen && buf[i + j] == (u8)needle[j]) j++;
        if (j == nlen) return 1;
    }
    return 0;
}

static u32 clen(const char *s) {
    u32 n = 0;
    while (s[n]) n++;
    return n;
}

static const char REJECT[] = "{\"authenticated\":false,\"reason\":\"no match\"}";
static const char ACCEPT_ALICE[] = "{\"authenticated\":true,\"subject_id\":\"alice\",\"claims\":{\"role\":\"member\"},\"reason\":\"ok\"}";

__attribute__((visibility("default")))
u64 authenticate(u32 req_ptr, u32 req_len) {
    const u8 *buf = (const u8 *)(unsigned long)req_ptr;
    const char *resp;
    if (has(buf, req_len, "\"username\":\"alice\"") && has(buf, req_len, "\"password\":\"correct-horse\"")) {
        resp = ACCEPT_ALICE;
    } else {
        resp = REJECT;
    }
    u32 ptr = (u32)(unsigned long)resp;
    u32 len = clen(resp);
    return ((u64)ptr << 32) | (u64)len;
}
