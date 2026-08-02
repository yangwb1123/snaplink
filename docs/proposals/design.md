Design doc delivered. Two files:

- **`docs/requirements/adapters-delivery-path.md`** — the spec persisted per repo convention (so the design's `Design for …` reference resolves, matching the existing `docs/design/` pattern).
- **`docs/design/adapters-delivery-path.md`** — the design, with `##` decisions covering all four requested dimensions.

## Key decisions

1. **`testkit.WithRouter(r sso.Router) Option`** — pure addition; `WithRouter` already exists in `interfaces/sso` (options.go:23), so **zero changes to `interfaces/sso`** (at its 60-file ceiling). Nil → default StdRouter, matching `mountMiddleware`'s fallback. The matrix registers a probe route on the injected router before `NewServer` so a dropped pass-through can never silently degrade to a triple-StdRouter false green.
2. **`test/router_backend_matrix_test.go`** — `backendsemantics`-style table (std/gin/echo), fresh harness per subtest, 4 scenarios (auth-code+PKCE, refresh rotation with family-kill, DPoP, unmatched-route bytes) + a concurrent `Use()` subtest under `-race`. **Critical finding (F1):** the spec's literal "token 错误响应字节逐字节相同" is unachievable — verified that std/gin/echo render JSON through three different serializers (newline + charset differ), which `routertest` already documents. The matrix enforces byte-identity on the unmatched surface (where it is a real guarantee, baseline derived at runtime from the std backend) and a scoped semantic contract (status + JSON value + Content-Type prefix) for JSON error bodies; `docs/adapters.md` states the scope so declared contract and tests agree.
3. **`docs/examples/embed-gin` / `embed-echo`** — embedder-owned engine + `NewGinRouter(engine)` / `NewEchoRouter(engine)` + `/hello` coexistence + required comments (404 normalization, `RegisterGated`, post-construction override consequences). Each dir gets a smoke test driving its own `newServer()` (auth-code flow + `/hello` 200). I flagged an interpretation note: `appcore` is client-side; the relevant precedent is `basic/main.go`'s server wiring style.
4. **`docs/adapters.md`** — the five contract items plus an enforcement section, and a delivery-semantics sentence for `DIRECTORY_MAP.md:17`.
5. **Feature-matrix row `embedding.framework-routers`** — via `ops/build/capabilities.json` + `capabilities generate` (hand-editing the generated block is drift), following the `storage.production` SPI-surface precedent.
6. **`checks/adapters_check.py`** — 7 checks (scenario-inventory pin, suite wiring, matrix presence, example build, public-constructor discipline, doc presence, behavioral `go test` runs), registered in `cli.py`/`Makefile ci`/`CHECKS_REGISTRY`/`test_adapters.py`. The pinned scenario inventory is what makes "delete a routertest scenario → `make ci` fails" work — `go test ./...` alone can never see a deleted scenario.

## Storage model & failure modes

No runtime state; the "storage" is the artifact inventory (executable suite/matrix/examples vs. declared capabilities.json/adapters.md) with `adapters_check.py` as the declared↔executable reconciliation. Byte baselines are derived at runtime, never hardcoded. Eleven failure modes are tabulated with detection + mitigation; top risks: the F1 scope conflict, `conformance.go` at 474/500 lines (design deliberately adds no scenarios there), and `capabilities check`/`sdk-surface check` validation strictness (verify immediately after regeneration).

All file/line references were verified against the tree; no production code is touched by this design.
