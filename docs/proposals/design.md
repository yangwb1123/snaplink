Design doc written to `docs/auto/interfaces-adapters-direction2-design.md`. Before writing it I re-verified every spec claim against the code and found eight additional binding facts that shape the design:

**New ground truth beyond the spec**
- **gin fails byte-equality today too** — its `default404Body` is `"404 page not found"` without the trailing newline and without `X-Content-Type-Options: nosniff` that `http.NotFound` emits. The suite's byte assertions make gin red at baseline (a strengthening, not a conflict).
- **gin's `Abort()` is the only chain-stopper** — `Next()`'s loop advances on its own, so the route-level gate *must* call `c.Abort()` or the wrapped handler (and its sso middlewares) still run.
- **echo's `Response.Write` has no committed guard** — `http.NotFound(c.Response(), c.Request())` reproduces the stdlib bytes exactly; and `DefaultHTTPErrorHandler` early-returns on committed responses, so the gate sentinel is safe by default (a delegating wrapper covers embedder-replaced handlers).
- **Production wiring already does `Use()` before any route** (`server_routes.go:113-132`) — snapshot semantics change no production behavior.
- **`router_test.go` is `package core`** — importing `routertest` from it would be an import cycle, so the StdRouter hookup lives in `routertest`'s own smoke test (per the spec's file plan).
- gin `RouterGroup.Handle` / echo `Group.Add` make `RegisterGated` a two-liner per backend; `sso` aliases keep the adapters importing one Snaplink package; budget headroom verified (router.go 440→~465, adapters <260, `shared/core` 2 subdirs, auto-classified `shared`, no exemptions).

**Structure** — three `##` decisions, each with API surface, state/storage model (suite is stateless; middleware list becomes RWMutex + registration-time snapshot; no other storage), failure-mode tables, plus a 14-scenario matrix with today's baseline status per scenario, a 12-item "what could break the design" section (gin abort semantics, baseline-first discipline, the `WithFrameworkNotFound` divergence hatch, engine-level middleware boundary, framework-upgrade drift), delivery order (suite lands red → normalization → snapshot+gating), and acceptance mapping.

No code changed, so no gates were run — the artifact is the design doc itself.
