Design doc written and verified. Summary of the deliverable:

## `docs/auto/interfaces-middleware-direction2-design.md`

**The one finding that matters most** — verified by compile experiment against `go 1.26.1` before writing anything:

> **The spec's literal API is illegal Go.** `HandlerContext.Get[T](RequestKey[T])` as an interface method fails to compile (`interface method must have no type parameters`). The design replaces it with generic **free functions** `core.Get[T](*RequestState, RequestKey[T])` + a non-generic `HandlerContext.State() *RequestState` accessor. The compile-time cross-type guarantee survives (T is inferred from the key), and a working prototype of the final API shape was compiled and run.

Other verified corrections baked in: the "four string keys" are really **seven** (const-keyed `geo:info` + region's bag key escape the spec's literal-string grep); capture position at the router boundary is what keeps the idempotency replay cache uncompressed (a stack installed at RequestLogger's layer would cache gzip bytes and replay them as JSON).

**Structure** (per your request, one `##` decision each):
- **Decision 1 — Typed registry**: `RequestKey[T]`/`RequestState`/`RequestStateOf` API; name-keyed `map[string]typedSlot` storage with a Set-time cross-type collision panic (fail-fast); a `var requestStateAnchor = new(int)` context anchor so the `rg 'type \w+Key struct{}'` freeze stays literally true; all 8 struct keys + 7 bag keys migrated with signature-preserving helpers; per-adapter `sync.Map` bags and the `*r = *r.WithContext` mutation deleted.
- **Decision 2 — Capture stack**: `CaptureStack.Wrap/Add` + `CaptureHandle.Status/Body/Unlock`; install at the router boundary only (std `NewContext`, gin/echo `ServeHTTP` — the gin `WriteHeaderNow` edge dies by construction); layers are positionless (two captures see identical bytes by construction); `RequestLogger` becomes Add-only with one documented behavior delta; the full deletion set (`SetResponseWriter`, `InstallCapture`, `CaptureWriter`, `requestLogResponseWriter`, `recordCaptureMissing`, `EventIdempotencyCaptureMissing` + all 5 audit-touchpoint files) lands in one commit.
- **Decision 3 — Unified surface**: two-return `RequestStateOf` attach semantics; tenant single-lookup with `ResolveTenantID` retained as a one-line registry-first adapter (spec's own parenthetical); zero-query reject path when the slot is filled.
- **Delivery order** (1 → 3 → 2, each gated with `-race` + `make ci`) and a **"what could break the design"** section covering the 11 real hazards — including the two that are security-relevant (compression-position replay corruption, registry divergence via context rebasing).
- Four spec corrections flagged explicitly at the end, including the Go language finding.
