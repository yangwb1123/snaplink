All verification complete. Here's the report.

# Verification report: `docs/openapi.yaml` servers edit

**Footprint:** `git diff --stat` shows exactly `docs/openapi.yaml | 2 deletions` — the localhost:8080 entry and its description. `grep -n 'localhost:8080' docs/openapi.yaml` → 0 hits; the `https://{host}` entry with `variables.host.default: sso.example.com` is retained; the line-30 `8088` docs-serve comment is untouched.

## 1. Validation under OpenAPI 3.0.3 — PASS

`go run github.com/getkin/kin-openapi/cmd/validate@latest docs/openapi.yaml` (the exact Makefile:189 command; v0.146.0 from module cache) → **exit 0**. Aggregate `make docs-validate` (route-contract + capabilities-check + kin-openapi) → **exit 0**. `make docs-check` → green (existence/cross-refs only).

**Nuance found:** `make ci` (Makefile:265) does *not* include `docs-validate`; its doc segment is `route-contract capabilities-check sdk-surface-check`. `kin-openapi validate` is reachable only via `make docs-validate`. Both paths verified green.

## 2. "No gate/generator consumes `servers:`" — CONFIRMED

| Consumer | `servers` refs | What it reads |
|---|---|---|
| `checks/route_contract.py` | 0 | `paths` only (`openapi_operations`, line 166) |
| `ops/scripts/sdk_surface.py` | 0 | `doc["paths"]` operationIds only (line 42) |
| `ops/scripts/capability_registry.py` | 0 | doesn't parse openapi.yaml at all |
| `cmd/gensdk` (all .go) | 0 | `parseSpec` → paths/info only |
| `interfaces/apidocs`, `server_routes.go`, `docs/openapi_embed.go` | 0 | serve embedded bytes verbatim |
| Repo-wide `"servers"` in non-test Go | 0 files | — |

Re-executed green: `check-routes` (241 routes/348 ops), `capabilities check` (34 caps), `sdk-surface check` (13 groups/316 ops/2 langs). R4 also holds: `sdk-surface generate` left `docs/sdks/` byte-identical (`git diff --exit-code` empty).

## 3. R3 type-assertion shape — CONFIRMED (probe then deleted)

Temporary probe in `cmd/gensdk` using production `parseSpec(docs.OpenAPISpec)` + real embed printed the actual shape: `doc["servers"]` → `[]interface{}` (len 1); entry → `map[string]interface{}` with `url` = `"https://{host}"` (string); `entry["variables"]` → `map[string]interface{}`; `variables["host"]` → `map[string]interface{}`; `host["default"]` = `"sso.example.com"` (string). Design C3 checks (no `localhost`/`127.0.0.1`/`8080`/`:\d+`/`{port}` variable) pass. One trap confirmed empirically: a blanket "no variables" regex false-positives on the legitimate `{host}` — C3 must target `{port}`-style variables only.

## 4. Header-named doc consumers — no breakage, no lost information

- Diff is 2 deleted lines: no path/operation/schema/tag touched, so ReadMe/Mintlify/Stoplight/Postman/Insomnia lose nothing asserted; server variables are standard 3.0.3 and kin-openapi (strict) accepts the file.
- The purged entry's information survives: `cmd/sso-server/config.yaml:27` still documents `base_url: http://localhost:8080`.
- swagger-ui `docs-serve`: mounts `docs/` read-only and serves the spec verbatim (server variables render as inputs). Live-container check was attempted but the image pull fails on environment egress (`auth.docker.io` IPv6 timeout) — an environment limit, not a file problem.
- **Observation (out of scope):** `ops/deploy/openresty/fullstack/static/docs/openapi.yaml` is a *separate, hand-maintained older copy* (different contact URL/coverage text; zero generator references) that still lists localhost:8080. No gate consumes it, but flag if the purge intent should extend to deploy-tree copies.

## 5. Baselines and pre-existing failures

Green: `go build ./... && go vet ./...`; `go test -count=1 ./cmd/gensdk/ ./cmd/sso-minimal/`; `go test -count=1 ./test/ -run 'TestDiscovery_'`; `make docs-validate`.

**Pre-existing failures, unrelated (reported per AGENTS.md §5.7):** `TestMaintainability_FileSizeBudget` — `infrastructure/defaultimpl/ed25519_jwt_issuer.go` is 539 lines at HEAD with zero diff; `TestArchitecture_DirectoryDepth` and `TestArchitecture_DirectorySubdirFanout` — caused by untracked pi-batch artifacts (`docs/architect-analysis/auto/runs`, 261 files) and untracked in-flight work dirs (root subdirs 24 > frozen 21). None can be influenced by a 2-line YAML deletion.

**State:** the docs edit is applied and verified; the design's three test functions (R1/R2/R3) remain the next stage's implementation — the R3 test's assertions were proven shape-compatible with the real embedded spec.
