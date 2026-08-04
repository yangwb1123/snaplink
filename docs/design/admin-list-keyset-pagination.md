# Design — grpcadmin List RPC 全量物化改造：keyset 下推、MAC 绑定游标、TotalSize 解耦

**Scope**: the 9 `grpcadmin` List RPCs (Clients/Users/ListSessions/Releases/
ListTenants/ListDomains/ListRoles/ListAssignments/Snapshots/ListOperations) plus
`ListExpiring`. Three coupled improvements:

1. Optional pagination Store SPI — keyset pushdown with `List()` fallback.
2. Versioned, MAC-protected, filter/order-bound cursor tokens replacing base64
   decimal offsets.
3. `TotalSize` decoupled from full materialization; `ListExpiring` windowed.

**Hard constraints** (from requirements + AGENTS.md):

- `interfaces/grpcserver/grpcadmin` is at its 10 non-test-file fan-out cap; all
  new grpcadmin code goes into existing files, `admin_paginate.go` first.
- Zero breaking wire changes: `page_token` stays "Opaque cursor",
  `total_size` stays "Approximate" (`proto/admin/v1/clients.proto:84,100`).
- No new `Err*`, no new config keys, no new grpcadmin files, no renamed proto
  fields. Additive proto fields allowed for `ListExpiring` and `ListOperations`
  (the only two List messages lacking page fields today).
- Fallback path (store without the extension) stays byte-identical, including
  all error strings and offset-token semantics.
- Layering: composition → interfaces → infrastructure → protocols → domains →
  platform → shared. grpcadmin (interfaces) must never be imported by stores;
  shared semantics live at or below each entity's home package.

---

## D1 — SPI placement: pagination types + core SPIs in `shared/core/pagination.go`, per-entity SPIs in home packages

`shared/core/spi.go` is at its 500-line budget (its own header comment says
so), so the new types **cannot** go literally "next to `TenantScopedClientStore`
in spi.go" without crossing the file budget. The requirement's intent — the
*pattern* of `TenantScopedClientStore` (optional, type-asserted, `List()`
fallback) — is preserved; the file split follows the existing `tenant_user.go`
precedent (spi.go already says "this file was at its 500-line budget" for that
split).

**API surface:**

```go
// shared/core/pagination.go (new file, package core)

// PageQuery is the pushdown query carried by every optional pagination SPI.
type PageQuery struct {
    Limit   int    // rows to fetch, already clamped to [1, maxAdminPageSize]
    OrderBy string // canonical field, "" = default (id asc)
    Desc    bool   // true = descending
    Filter  string // mini-grammar expr ("field:value" | "field eq value"), "" = match all
    After   []byte // opaque keyset cursor from the previous response; nil = first page
}

// PageResult-free per-entity signature (concrete, no generics — matches the
// codebase's non-generic SPI style):
//   ListPage(ctx, PageQuery) (items []*T, next []byte, totalHint int, err error)

type PaginatedClientStore interface {
    ListPage(ctx context.Context, q PageQuery) ([]*Client, []byte, int, error)
}

// ClientExpiryLister is the windowed counterpart for ListExpiring, mirroring
// the clientrotation.ClientRotationLister precedent (durable backends already
// implement time-window index queries).
type ClientExpiryLister interface {
    ListExpiringPage(ctx context.Context, cutoff time.Time, q PageQuery) ([]*Client, []byte, int, error)
}

type PaginatedUserProvider interface {
    ListPage(ctx context.Context, q PageQuery) ([]*User, []byte, int, error)
}

type PaginatedSessionLister interface {
    // userID "" = all sessions (ListAll); non-empty = that user's (ListByUser).
    ListPage(ctx context.Context, userID string, q PageQuery) ([]*Session, []byte, int, error)
}

// Mini-grammar parser, shared by grpcadmin AND every store implementation so
// the two paths cannot drift apart. Moves out of grpcadmin's parseAdminFilter.
func ParseFilterExpr(expr string) (field, value string, ok bool)
```

Non-core entities get their SPI in their **home package** (import direction
domains/platform → shared allows `core.PageQuery` everywhere):

| Entity | Base interface (home) | Extension |
|---|---|---|
| Tenant | `tenant.Store` (domains/tenant) | `PaginatedTenantStore` |
| Domain | `tenant.Store` (domains/tenant) | `PaginatedDomainStore` (tenantID "" = all) |
| Role/Assignment | `permissions.Provider` (domains/permissions) | `PaginatedPermissionProvider` (clientID-scoped, like the base) |
| Release | `releases.ReleaseStore` (platform/releases) | `PaginatedReleaseStore` |
| Operation | `operations.Store` (platform/lifecycle/operations) | `PaginatedOperationStore` |
| Snapshot | `snapshot.Storage` (interfaces/snapshot) | `PaginatedSnapshotStorage` (items are `[]string` names) |

Aliases (`sso.PaginatedClientStore = core.PaginatedClientStore`, etc.) go into
the existing `interfaces/sso/aliases.go` — no new file there (interfaces/sso is
at its 60-file cap).

**Cursor contract**: `next`/`After` are **store-opaque bytes**. The store
encodes its own last-row position (sort key + tiebreaker); the handler wraps
those bytes in a MAC'd token without interpreting them. This is deliberate: the
handler cannot reconstruct sort keys from proto responses (e.g. `order_by=
created_at` on users — the wire `User` has no `created_at`), so the store must
be the cursor authority, and keeping the bytes opaque lets each backend choose
its own encoding (memory: compact text; postgres: row-value pair).

**totalHint contract**: approximate count of rows matching `Filter` (ignoring
`OrderBy`/`After`/`Limit`), for UI display. `-1` = "unknown" (backend has no
cheap count). Backends MUST NOT full-scan to compute it. Memory backends return
the exact filtered count.

**Rationale**: mirrors the two existing optional-extension precedents
(`TenantScopedClientStore`, `ClientStoreStats`, `ClientRotationLister`):
callers type-assert, absence degrades to `List()`, and no existing
implementation breaks.

---

## D2 — Cursor token format: `v1.<payload>.<mac>`, codec in `shared/security`, singleton key

**Format** (deviation from the requirement's sketch, see note):

```text
v1.<base64url(payload)>.<base64url(HMAC-SHA256(key, payload))>
payload = after_bytes || 0x00 || filter_canonical || 0x00 || order_canonical
```

- `after_bytes` — the store's opaque cursor from the previous page (contains
  the last sort key + tiebreaker id, in the store's own encoding).
- `filter_canonical` — re-serialization of `ParseFilterExpr`: lowercase field +
  `:` + value; `""` for no filter. The two grammar spellings (`name eq x` vs
  `name:x`) canonicalize identically, so a client may switch spellings between
  pages.
- `order_canonical` — `parseOrderBy` result re-serialized (`name`, `-name`,
  `""` for default). Whitespace-insensitive for the same reason.
- MAC key: HMAC-SHA256, compare with `subtle.ConstantTimeCompare`.

**Why MAC over the whole payload instead of a separate fingerprint field**
(requirement sketch had `MAC(filter_fingerprint|order_by|last_sort_key|last_id|seq)`):
binding filter + order + after into one MAC input is equivalent protection with
one fewer field. The sketch's `seq` is dropped: cursors are short-lived opaque
values with no replay value (paging is idempotent — re-fetching a page returns
the same rows), so a sequence number adds integrity without a use case.

**Decode** (all failures byte-identical, see D9):

1. Must start with `v1.` and have exactly two more dot-separated parts.
   Legacy offset tokens are base64url of digits — no dots, no `v1.` prefix —
   so the two formats are disjoint by construction; each path cleanly rejects
   the other's tokens.
2. base64url-decode both parts.
3. Constant-time MAC compare; split payload on `0x00` into exactly three
   parts.
4. Compare `filter_canonical`/`order_canonical` against the current request's
   canonical forms.
5. Return `after_bytes` to the store.

**Placement**: `shared/security/pagecursor.go` (package `security`, an
existing exempt directory — no new package, so no `layerName()` classification
change). A small codec:

```go
type PageCursorCodec struct{ key []byte }
func NewPageCursorCodec(key []byte) *PageCursorCodec        // nil/empty → crypto/rand key
func (c *PageCursorCodec) Encode(after []byte, filter, orderCanonical string) (string, error)
func (c *PageCursorCodec) Decode(token string) (after []byte, filter, orderCanonical string, err error)
```

grpcadmin uses a package-level default codec (`security.PageCursorCodec()`),
with `security.InstallPageCursorKey([]byte)` called once at cmd boot. **Key
sourcing decision**: derive from an existing deployment-stable secret when one
is configured (e.g. the audit-webhook HMAC secret via HKDF); otherwise the
default random key is used (single-replica, restart-invalidates-cursors
semantics). No new config key in this change — flagged as a scope risk in D10.

**Why not keep offset tokens on the extension path**: a decimal offset says
nothing about the rows seen; under concurrent writes it silently drifts. The
extension path therefore never mints offset tokens, and any token without the
`v1.` prefix is rejected as `invalid page_token` (requirement 2.4). The
fallback path is untouched: it still mints and consumes offset tokens.

---

## D3 — grpcadmin dispatch: one generic helper, validation stays handler-side

All new grpcadmin code lands in `admin_paginate.go` (331 lines today; budget
budgeted in D10). One generic skeleton replaces the 9 near-identical handlers:

```go
// admin_paginate.go
type pageLister[T any] interface {
    ListPage(ctx context.Context, q core.PageQuery) ([]T, []byte, int, error)
}

// runListPage: extension path when ext is implemented, else the existing
// listAll → filter → sort → offset-slice path. Errors from the extension
// store map to Internal exactly as List() errors do today. ErrUnsupportedOperation
// (decorator passthrough) falls back silently.
func runListPage[T any](ctx context.Context,
    token string, pageSize int32, orderBy, filter string,
    ext pageLister[T],
    listAll func(ctx) ([]T, error),
    filterSort func(items []T, orderBy string) ([]T, error), // fallback semantics
    validate func(filter, orderBy string) error,             // row-independent spec check
) (items []T, nextToken string, total int32, err error)
```

Each List handler shrinks to: nil-check → clamp page size → `runListPage` →
proto-convert the returned window (per-RPC conversion loop stays in the handler
file, unchanged).

**Validation split** (important): every error the current matchers/comparators
produce — `unsupported filter field %q`, `invalid filter value for active:
%q`, `unsupported order_by field %q` — is **row-independent** (field membership
+ `ParseBool` only). So:

- Extension path: the handler pre-validates via `validate` (single-sourced
  error strings, see D6 extraction) and passes the raw filter/order to the
  store. The store never sees an unsupported field, so backends cannot drift on
  error text. Stores implement the *matching semantics* (exact/substring/bool)
  per the documented mini-grammar.
- Fallback path: the existing filter+sort code runs unchanged (post-extraction
  it calls the same shared functions, so behavior is preserved).

**ListExpiring** (`admin_paginate.go:43-73`): type-assert `ClientExpiryLister`
→ windowed keyset page; else the existing full-scan → filter → sort path, with
the new optional page params applied as offset pagination over the filtered
slice when present (absent params = today's return-everything behavior). An
extension that *errors* propagates Internal — no silent full-scan fallback (a
broken backend must not be masked by a slow path; consistent with how
`ListDueForRotation` propagates).

**OperationAdminService.ListOperations** (`admin_paginate.go:271-289`): gains
real pagination via the same helper. Behavior change documented in D10: the
extension path introduces a deterministic order (id ascending) where today the
response is store-order; the fallback path keeps today's behavior.

---

## D4 — Additive proto changes (only two messages)

| File | Change |
|---|---|
| `proto/admin/v1/clients.proto` | `ListExpiringClientsRequest` += `page_token = 2`, `page_size = 3`; `ListExpiringClientsResponse` += `next_page_token = 2`, `total_size = 3` |
| `proto/admin/v1/operations.proto` | `ListOperationsRequest {}` += `page_token = 1`, `page_size = 2`; `ListOperationsResponse` += `next_page_token = 2`, `total_size = 3` |

Both are purely additive (new field numbers, existing fields untouched), so
old clients and the gRPC gateway stay wire-compatible. Regenerate
`gen/proto`, `docs/openapi_embed.go`, and `docs/openapi.yaml` (buf) in the same
change. `total_size`'s "Approximate" doc is already correct — confirm, don't
edit. `docs/feature-matrix.md` gains a row for pagination pushdown; error-codes
and config-reference are untouched (no new `Err*`, no new config key).

---

## D5 — Storage model: keyset predicate + tiebreaker, store-defined cursor bytes

**Predicate** (evaluated inside the store, ASC; DESC mirrors):

```text
(sort_key > lastK) OR (sort_key = lastK AND tiebreaker > lastID)   -- asc
(sort_key < lastK) OR (sort_key = lastK AND tiebreaker < lastID)   -- desc
```

The tiebreaker gives a strict total order over equal sort keys. Per entity:

| Entity | sort key (OrderBy) | tiebreaker (unique) |
|---|---|---|
| Client | id (default/"created_at" alias), name | `id` |
| User | id (default), created_at, provider | `id` |
| Session | id (only field) | `id` |
| Release | id | `id` |
| Tenant | id (default), slug, name, status | `id` |
| Domain | hostname | `hostname` (unique) |
| Role | code | `code` (unique within the client_id scope) |
| Assignment | user_id | `user_id` (unique within the client_id scope) |
| Snapshot | name | `name` (unique) |
| Operation | id | `id` |

**Cursor bytes**: store-defined encoding of `(lastK, lastID)`. Memory stores
use a compact text form; a durable backend uses its own (e.g. the raw column
values). The handler never interprets them.

**Durable-backend shape** (postgres, for the follow-up; the contract is ready
now): `WHERE (filter predicates) AND ((sort_col, id) > ($k, $id)) ORDER BY
sort_col, id LIMIT n` over a composite index `(sort_col, id)`; `totalHint` from
a filtered `COUNT` (or `-1`). Sorting semantics (collation, time encoding) are
the backend's responsibility — contract-documented, conformance-tested via the
fake-store acceptance tests (D11).

---

## D6 — Storage model: memory implementations + shared semantics extraction

The memory stores implement the SPIs (requirement 1.3), and the handler will
take the extension path against them — so the memory implementations **must**
reproduce today's handler-side filter/sort exactly (ordering, substring vs
exact, error strings). The only way to guarantee that without duplication is to
extract the pure semantics to the entity home packages and have both grpcadmin
and the memory stores call them:

| Extracted to | Functions (clients/users/sessions) |
|---|---|
| `shared/core/pagination.go` | `ParseFilterExpr`, `ValidateClientFilter/OrderBy`, `ClientMatches`, `CompareClients`, `ValidateUserFilter/OrderBy`, `UserMatches`, `CompareUsers`, `CompareSessions` |
| `domains/tenant` | tenant/domain matchers + comparators + validators |
| `domains/permissions` | role (`code`) and assignment (`user_id`) comparators |
| `platform/releases` | release comparator (`id`) |
| `platform/lifecycle/operations` | operation comparator (`id` asc — **new deterministic order**, see D10) |
| `interfaces/snapshot` | name sort (`sort.Strings`) — already deterministic |

grpcadmin's `filterClients/clientMatches/sortClients/clientLess` and peers
become thin wrappers over these (error text preserved verbatim), keeping the
fallback path byte-identical while giving memory stores the reference
semantics for their `ListPage`.

Memory `ListPage` algorithm: filter the full slice (shared matchers) → sort
(shared comparators, `sort.SliceStable`) → binary-search `After` → slice
`Limit` rows → `next` = cursor of the last row, `nil` when the slice ended at
the tail → `totalHint` = `len(filtered)` (exact, so every existing TotalSize
assertion holds). Under the store's `RLock`; the sort runs on the snapshot, so
random map iteration cannot leak into page order.

**In scope here**: the SPI + memory implementations (memorystoreidentity,
releases/storememory, operations.MemoryStore) + grpcadmin dispatch + codec.
**Follow-ups (contract-ready, out of scope)**: postgres/sqlite/redis
`ListPage`/`ListExpiringPage` — until then those backends take the fallback
path, byte-identical to today.

---

## D7 — TotalSize sourcing rules

Priority on the **extension path** (never calls `List(ctx)` to count):

1. `totalHint >= 0` from the SPI — use it.
2. `totalHint == -1` AND `filter == ""` AND entity is client AND the store
   implements `ClientStoreStats` — use `Stats().count`.
3. Both unavailable — return `0` (the proto contract says "Approximate… for UI
   display"; a 0 is honest when the backend cannot count cheaply).

Priority on the **fallback path**: `len(all)` after filter — exact, unchanged.
Memory stores return exact `totalHint`, so all existing unit tests keep their
exact-TotalSize assertions.

`ListExpiring`: extension path → `totalHint`; fallback → `len(filtered
slice)`.

---

## D8 — Decorator passthrough

`ClientStoreCache` (`interfaces/sso/servercache/server_client_cache.go`) gains
the same forwarding pattern it already uses for `ListByTenant`/`Stats`/
`ListDueForRotation` (lines 203-231 precedent): implement
`PaginatedClientStore` + `ClientExpiryLister` unconditionally, forwarding to
the inner store when it implements them and returning
`core.ErrUnsupportedOperation` otherwise; uncached (admin listing is not the
hot path). `runListPage` treats `ErrUnsupportedOperation` as "extension
absent" and falls back silently — so a store behind the decorator never loses
capability, and a non-extension store behind the decorator behaves exactly as
before. Note: in the default `cmd/sso-server` build the admin services receive
the raw store (the Server wraps only its own internal `s.clientStore`), so the
passthrough matters for embedders and for the mandated forwarding test.

---

## D9 — Failure modes (oracle-safe, byte-identical messages)

| Case | Result |
|---|---|
| Token not `v1.`-shaped, base64 decode failure, MAC mismatch, wrong part count, filter/order mismatch vs request — **on the extension path** | `codes.InvalidArgument`, message `invalid page_token` — byte-identical to today's negative-offset handling |
| Same failures **on the fallback path** | `decodeOffset` unchanged — same `invalid page_token` |
| Legacy offset token presented to extension path / v1 token to fallback path | `invalid page_token` (formats are disjoint, one message) |
| Unsupported filter/order_by field or bad bool value | Unchanged `InvalidArgument` messages from the shared validators/matchers |
| Extension store error | `Internal "list: %v"` — same shape as today's `List()` error |
| `ErrUnsupportedOperation` from decorator | silent fallback to `List()` |
| `ListExpiring` extension error | `Internal` — propagate, never mask with a full scan |
| Snapshot per-item `Get` failure mid-page | `Internal` — unchanged |
| Concurrent insert/delete between pages | Keyset semantics: rows inserted after the cursor appear exactly once; rows inserted before the cursor never appear; deleted rows vanish. **No duplicates ever** (the offset path's skip/repeat drift is gone). Not a global snapshot — documented |
| Restart / key change (ephemeral key) | In-flight cursors → `invalid page_token`; identical message, safe failure |
| Client changes `page_size` mid-sequence | Allowed — the token binds filter/order/position, not size |
| Client re-fetches a page | Same cursor → same page (idempotent; no replay hazard) |

---

## D10 — What could break the design

1. **grpcadmin file budgets (10-file fan-out + 500-line/file).** All new code
   must fit existing files; `admin_paginate.go` is 331 lines today and gains
   the generic helper (~90), token wrappers (~40), and ListExpiring rework
   (~30) — near the 500-line ceiling. Mitigations: the codec lives in
   `shared/security` (not here); if the file still overflows, the token
   wrappers move to another existing file (`admin_clients.go` — the first List
   RPC file) rather than creating a new one. Verify with the maintainability
   gate before finalizing.

2. **MAC key stability is the weakest point.** There is no universal
   deployment-stable secret in the codebase today (checked: no cluster/bus
   shared secret; signing keys rotate; JWE/snapshot keys are optional). An
   ephemeral default key invalidates in-flight cursors on restart and breaks
   round-robin multi-replica pagination. Mitigations: install a derived key at
   boot from an existing configured secret (e.g. audit-webhook HMAC secret)
   when present; document the ephemeral semantics. **Scope flag**: if product
   requires fleet-stable cursors by default, a config key is unavoidable —
   that is a deliberate deviation from "no new config keys" and needs sign-off.

3. **Behavior drift between extension and fallback paths.** Durable backends
   implement sort/filter in SQL (collation, time encoding, `LIKE` semantics)
   and may differ from Go string compare on edge rows (case, Unicode, time
   zones). Mitigated by: single-sourced reference semantics in the entity
   packages, handler-side validation, contract documentation, and
   conformance-style fake-store tests. The default `cmd/sso-server` build with
   a postgres backend takes the fallback path until the follow-up lands, so
   no production behavior changes in this change.

4. **`TotalSize` can become `0` on the extension path** when a backend
   reports `totalHint == -1` and no `Stats` exists. The proto allows
   "Approximate", and acceptance keeps fake/memory exact, but a UI built on
   exact counts would regress. Mitigation: memory stores return exact; the
   `0`-when-unknown case only appears for durable backends that opt into the
   SPI with `-1` — a follow-up concern, documented in the SPI contract.

5. **`ListOperations` gets its first deterministic order and real
   pagination.** Today it returns everything in store order. The extension
   path orders by id ascending (new contract); the fallback keeps today's
   order. A client that assumed insertion order sees reordering only on the
   extension path. Additive proto fields mean old clients are unaffected, but
   this is the one genuine behavioral change beyond token format.

6. **Tests asserting token internals.** Any test asserting exact
   `next_page_token` bytes (not just empty/non-empty) breaks — the v1 token is
   longer and contains dots. Audit for `encodeOffset`/`decodeOffset` uses in
   tests; the acceptance criteria only pin empty/non-empty, which is preserved
   (`next` nil → empty token; else non-empty). Existing tests that hand-craft
   offset tokens (`base64("100")`) still pass on the fallback path and fail
   with the same `invalid page_token` on the extension path.

7. **Error-string drift during the extraction (D6).** Moving matchers to
   entity packages risks subtle message changes (`unsupported filter field %q`
   etc.). Mitigation: pin the exact strings with the existing
   `admin_*_test.go` fallback assertions and the new extension-path tests;
   the fallback path exercises the same functions, so the old tests are the
   drift detector.

8. **The cache decorator forgetting the passthrough** would silently disable
   pushdown for embedders that wire `ClientStoreCache` around the store handed
   to admin services. Covered by the mandated forwarding test (D11).

9. **Import-direction traps.** `domains/tenant`, `domains/permissions`,
   `platform/releases`, `platform/lifecycle/operations`, and
   `interfaces/snapshot` must import `shared/core` for `PageQuery` — all legal
   per the layer order (downward), but each is a new edge; the architecture
   gate test (`go test -run 'TestArchitecture_' .`) catches violations, and
   none of these packages may import `interfaces/sso` or `interfaces/grpcserver`.

10. **Proto regeneration is load-bearing.** The two additive messages require
    buf regen of `gen/proto`, the gRPC gateway, `openapi_embed.go`, and
    `docs/openapi.yaml` in the same commit; forgetting any one leaves the REST
    gateway serving the new fields without validation or docs drift.
    `ListExpiring`'s REST route (`/api/v1/admin/clients/expiring`) gains query
    params — verify gateway passthrough in e2e.

11. **Concurrency test semantics must be defined as keyset, not offset.**
    "No duplicates, no omissions" (requirement 2 acceptance) holds only
    relative to the keyset view: rows inserted *after* the cursor appear once;
    rows inserted *before* it do not appear at all. The test must compare
    against a no-write baseline union and document this (it is a feature, not
    a bug).

12. **`interfaces/sso` 60-file cap**: aliases go into the existing
    `aliases.go`; no new files there. `shared/core` gains exactly one new
    file (`pagination.go`); `shared/security` gains one file in the existing
    package (no new package → no `layerName()` classification needed).

---

## D11 — Verification plan (maps 1:1 to acceptance criteria)

- **Counting fake store** (grpcadmin test file): N=10,000, page_size=100, 3
  pages → `List(ctx)` called 0 times; `ListPage` fetches ≤100 rows per call;
  `TotalSize` equals the backend count; request of TotalSize triggers no
  `List(ctx)`.
- **Fallback regression**: existing `admin_*_test.go` suites (order,
  TotalSize, next_page_token non-empty/empty, filter/order_by error codes)
  green against a non-extension store.
- **Tamper/mismatch**: flip any byte of a v1 token, swap filter, swap
  order_by, reuse a token across a filter change → all `invalid page_token`,
  messages byte-identical.
- **Concurrency stability**: insert/delete rows between page 1 and page 2 on
  the memory extension path; compare union with a no-write baseline (keyset
  semantics per D10.11).
- **`ClientStoreCache` forwarding test**: extension capability reachable
  through the decorator; `ErrUnsupportedOperation` falls back.
- **ListExpiring**: fake store records `cutoff` (window passed correctly);
  non-extension store behaves as today (admin_clients_test.go:197 etc.).
- **e2e**: `test/` REST pagination + TotalSize assertions unchanged; new
  ListExpiring page-param round trip.
- **Gates**: `go build ./... && go vet ./...`, `go test -run
  'TestMaintainability_|TestArchitecture_' .`, `make ci` (incl. buf/proto
  regen checks), `go test ./... -race`.
