// policy.c -- reference WASM authorization policy module for
// platform/lifecycle/wasmauthz's tests (see ../doc.go for the ABI contract
// this implements: exported "memory" + alloc/authorize/dealloc).
//
// No WASM toolchain (TinyGo, wasm32 clang+lld) ships pre-installed in every
// environment this repo's tests run in; where TinyGo is unavailable, a
// freestanding C99 program compiled with clang's wasm32 backend is the next
// most practical way to produce a GENUINE, non-trivial compiled .wasm module
// (as opposed to a hand-encoded byte literal) without adding a new build-time
// dependency to this repo — clang/lld are commonly available, and nothing
// here becomes a go.mod or CI dependency (policy.wasm is committed as a
// prebuilt binary test fixture, exactly like any other golden testdata file).
//
// Compiled with (from this directory):
//
//	clang --target=wasm32-unknown-unknown -nostdlib -O0 \
//	  -Wl,--no-entry -Wl,--export-all -Wl,--allow-undefined \
//	  -o policy.wasm policy.c
//
// Policy (intentionally trivial -- this is a TEST fixture, not a real
// authorization policy):
//   - ALLOW, reason "context.role=admin override", when the request JSON
//     contains `"role":"admin"` anywhere (i.e. in Request.Context).
//   - ALLOW, reason "alice may read", when subject == "alice" AND
//     action == "read".
//   - DENY, reason "no matching policy rule", otherwise.
//
// Byte-substring matching on the host's json.Marshal output is safe here
// because the wasmauthz.Request field order and encoding are fixed (see
// ../engine.go); a REAL policy module should parse JSON properly (e.g. via
// TinyGo's encoding/json) -- this fixture skips that only to avoid needing a
// JSON parser in freestanding C.

typedef unsigned char  u8;
typedef unsigned int   u32;
typedef unsigned long long u64;

// Bump allocator over a static arena. dealloc is a deliberate no-op -- see
// ../doc.go's ABI contract for what a production module should do instead
// (this reference fixture only ever serves a handful of test calls).
//
// reserved_zero_page exists ONLY so arena is never linked at absolute
// address 0: the host-side ABI contract (see ../engine.go's guestAlloc)
// treats a returned pointer of 0 as "allocation failed", so a real
// allocation must never legitimately land at address 0.
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
    // Return the actual linear-memory ADDRESS of the arena slice, not the
    // bare bump_top offset -- bump_top is only valid as an index into
    // arena, not as a standalone pointer.
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

static const char DENY[]        = "{\"allowed\":false,\"reason\":\"no matching policy rule\"}";
static const char ALLOW_ADMIN[] = "{\"allowed\":true,\"reason\":\"context.role=admin override\"}";
static const char ALLOW_ALICE[] = "{\"allowed\":true,\"reason\":\"alice may read\"}";

__attribute__((visibility("default")))
u64 authorize(u32 req_ptr, u32 req_len) {
    const u8 *buf = (const u8 *)(unsigned long)req_ptr;
    const char *resp;
    if (has(buf, req_len, "\"role\":\"admin\"")) {
        resp = ALLOW_ADMIN;
    } else if (has(buf, req_len, "\"subject\":\"alice\"") && has(buf, req_len, "\"action\":\"read\"")) {
        resp = ALLOW_ALICE;
    } else {
        resp = DENY;
    }
    u32 ptr = (u32)(unsigned long)resp;
    u32 len = clen(resp);
    return ((u64)ptr << 32) | (u64)len;
}
