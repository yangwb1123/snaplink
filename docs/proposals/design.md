Design doc written to `docs/auto/interfaces-apidocs-direction1-design.md` (doc-only, no Go gates touched). I verified every evidence claim against source before committing it — including a few facts the spec didn't pin down and that materially shape the design:

**Grounded findings from verification:**
- `StdRouter.Group` accumulates prefixes internally (`shared/core/router.go:288`), so the recording wrapper must track its own prefix chain and mirror that rule — the child recorder reuses the parent's map+mutex, exactly as `StdRouter.Group` shares the route table.
- Layer ranks (`architecture_layer_test.go:41`: platform=1, interfaces=5) confirm `interfaces/sso → platform/buildinfo` is a legal downward import — no exemption.
- `interfaces/sso` is exactly 60 non-test files, and the placement table in the doc is budget-checked: `server_health.go` (443, +57) holds the recorder type, `server_routes_admin.go` (332, +168) the projection helper, since `server_routes.go` has only 12 lines of headroom.
- Options apply before `Mount` (`sso.go:82`), so the recorder wrap in `mountMiddleware` (:108) deterministically observes every registration; late option application degrades to verbatim per fail-safe.

**Per-decision coverage (each under `##`, each with API surface / storage model / failure modes / what could break):**
- **D1**: `Endpoint` + `Projection.Mounted` in apidocs; `recordingRouter` (embedded `core.Router`, prefix-aware `Group`) in sso; RWMutex-guarded set, per-request sorted snapshot + probe consts; parity test via an additive `--dump-routes` checker flag feeding a `testdata` fixture (testdata/`_test.go` don't count against the ceiling); flags the structural 81-op gap — fully-optioned builds still filter ~81 never-mounted documented operations, changing the served doc from spec-reference to deployment-inventory.
- **D2**: `ResolveIssuer` closure wired to `s.resolveIssuer` — no trust logic in apidocs; stateless; single-entry `servers` rewrite with nil/empty/sentinel fallback; calls out the issuer-vs-console-host topology divergence and pins it by test.
- **D3**: `Version` resolved once at option time via `buildinfo.Resolve("")`; empty/`(devel)` falls back to `0.1.0`; `specTitleVersion` picks it up with no template change; flags the non-semver edition-label risk for strict parsers.

**Cross-cutting**: one pipeline shared by all three decisions, sequencing 1→2→3, the gate sequence including the fixture-drift guard in `make ci`, and whole-design risks (served-doc semantics shift, budget pressure interaction between the 60-file ceiling and the 500-line gate, checker coupling).

One judgment call to surface: I recommended the `--dump-routes` checker flag + checked-in fixture as the parity mechanism (spec requires `check-routes` output unchanged — the flag is additive), rather than shelling out from Go tests, which would be fragile and cross-language.
