Design doc written to `docs/auto/interfaces-apidocs-design.md`. Here is a summary of what it decides:

## Design highlights

**Ground truth verified beyond the spec** (9 binding facts). The spec's evidence had three material inaccuracies that the design resolves rather than inherits:
- `kin-openapi` is **not** a go.mod dependency (only an unpinned `go run @latest` in the Makefile) → the diff tool reuses `cmd/gensdk`'s `goccy/go-yaml` parser, honoring "no new module dependency" over the spec's "reuse kin-openapi" wording
- `interfaces/sso` does **not** currently consume `platform/buildinfo` → the new import is legal (downward) but net-new, flagged for the architecture gate
- The 81-operation gap is **not** the analysis's family list (v2alpha/setup/WASM/CAEP/federation are all statically registered, hence inside the 241) → Decision 3's triage must enumerate the real set, and the runtime/reverse-check split is designed accordingly

**Decision 1 — projection**: instead of a hand-maintained option→path table, `mountMiddleware` wraps `s.router` in a ~55-line `core.Router` recorder (8-method interface, adapter-agnostic) capturing the byte-exact mounted set at the source; `Server.Handle` routes flow through it, so embedder-dynamic routes are free; `/livez`+`/readyz` added explicitly. `apidocs.New` takes a `Projection{Mounted func() []Endpoint, Version, ResolveIssuer}` struct — nil fields degrade to the unprojected spec. Budget-critical: all sso-side code lands in `server_routes_admin.go`/`server_resource.go` (60-file ceiling, `server_routes.go` at 488/500).

**Decision 2 — rendering**: per-op codes are extracted from response descriptions but filtered through a bounded `stableErrorCodes` vocabulary map (so `client_id` prose can never render as a code); the full catalog is a new `go:embed error-codes.md` in the rank-0 `docs` package; all rendering stays textContent-only, CSP-nonce-safe, offline-capable. Rejected `x-error-codes` spec annotations (258 ErrorResponse refs make completeness impossible).

**Decision 3 — lockstep**: the recorder makes runtime static exception lists unnecessary, so the exception inventory cleanly lives in `sdk-surface.json` (schema-extended) as the spec wanted; reverse check + embed-consistency (go-run hash helper, the route_contract.py precedent) run under the existing `route-contract` ci target; `cmd/sdkdiff` uses git-show snapshots and canonical schema fingerprints so cosmetic edits don't false-flag breaking changes.

Each decision section covers API surface, storage model, failure modes, and what could break it, ending with an acceptance-mapping table tying every spec acceptance check to a concrete design provision.
