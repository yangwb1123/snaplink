Design doc written to `docs/auto/interfaces-adapters-direction1-design.md`. I re-verified every spec claim against the code first and surfaced three facts the spec missed that now drive the design:

**New evidence found during verification:**
1. **gin's `c.Writer` is `gin.ResponseWriter`, not `http.ResponseWriter`** — the spec's literal `c.Writer = w` proposal does not compile for a bare capture wrapper. The design adds a facade (`ginCaptureWriter` embedding the original gin writer, routing `Header`/`Write`/`WriteHeader` through the capture) that keeps `interfaces/middleware` gin-free.
2. **`server_token.go` is exactly 500 lines** — at the Go file budget ceiling. The design mandates net-negative edits there (assertion replacement −2 lines, inline-capture removal −40).
3. **The commit path's `ctx.ResponseWriter().(*idempotentResponseWriter)` assertion breaks under adapters even after step 2** — a spec gap. Capture retrieval moves to the request context (Decision 5), which is also what makes step 2's acceptance formally re-sequenced (wiring in step 2, end-to-end replay only provable in step 3).

**Design decisions (each a `##` heading):**
- **API surface**: `Abort()`/`Aborted()`/`Written()`/`SetResponseWriter` on `HandlerContext` (11→15 methods); compiler-enforced migration of exactly 4 production implementors + 2 test fakes; aliases unchanged.
- **Storage model**: `Aborted` as a per-request struct field in all three backends (gin's native abort deliberately unused); `Written()` via a permanent `trackingResponseWriter` in core that survives capture swaps by re-wrapping; gin/echo delegate to their own committed-state.
- **Chain-stop**: one `if ctx.Aborted() { break }` per middleware + guarded handler call in all three loops; opt-in so `TestGatedRouter_*` stays byte-identical; only `Auth`/`CORS` migrate.
- **Failure modes** table: 12 cases with fail-open/fail-closed classification, including misordered middleware replay (position invariant, not code property), capture loss (audited, Decision 7), and custom third-party routers that ignore the flag.
- **What could break it**: 10 risks — gin interface drift on upgrade, the 500-line budget, the SDK semver break for external implementors, the `*r = *r.WithContext` mutation pattern, audit cardinality, echo `Flush`/`Hijack` bypassing the swap, and more.

The doc also maps every spec acceptance check to where it's proven. No code was changed — this is design-only, per the request.
