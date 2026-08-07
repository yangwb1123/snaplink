All six dimensions validated empirically (scratch reproductions in `/tmp`, no repo edits — the in-flight worktree change is preserved). Full report:

## Validation report: test-only require+replace mechanics (operator vs mcp precedent)

**Key discovery first:** the working tree already contains this exact change in flight from a prior campaign run (mtime minutes ago, preserved untouched): `cmd/sso-operator/go.mod` has the mcp-style `replace … => ../../` + require annotated `// test-only parity import of shared/core`, plus 7 indirect version bumps; `go.sum` has the 36-line swap; `controller/root_consts_parity_test.go` (R1) is untracked. My scratch reproduced the identical tidy output **byte-for-byte** (same 9 modules, same 36 lines) — independent cross-validation of the mechanism.

### 1. Replace scope — module-wide, necessarily
Go has **no test-only `replace` directive**; it's module-graph-wide for build and test alike. What's genuinely test-only is the *import* (and thus the require's reason to exist): R1 imports only `shared/core` (verified: its closure is 100% stdlib — `internal/*`, `compress/*`, `mime/*`). The replace is inert for `go build ./...` purely because no non-test package imports the root. Local-path replaces record **zero** go.sum entries for the replaced module itself — mcp go.sum and the in-flight operator go.sum both have 0 `yangwb1123/snaplink` entries (evidence's claim holds).

### 2. tidy / go.sum impact — no balloon, but version churn
With R1's actual import set: `go mod tidy` keeps go.sum at **171 → 171 lines**, no new module paths. The only change: 36 lines swapped as 9 overlapping deps are MVS-aligned to root versions (cbor 2.9.0→2.9.2, x/mod→0.35, x/net 0.49→0.53, x/sync→0.20, x/sys→0.44, x/term→0.42, x/text→0.37, x/time→0.15, x/tools→0.44). go.mod gains only require+replace. The balloon risk is real but bounded by the import set: importing `platform/configaudit` instead grows go.sum 171→212 (+41 lines, +20 new paths: otel/grpc/gonum/…) — fully reversible by re-tidy. The design's choice of `shared/core` is the minimal-import optimum.

### 3. Generated-parity-file fallback — go.sum truly stable, with a freshness cost
Verified in a clean copy: with no require/replace, `go mod tidy` is a **byte-identical no-op** on both go.sum and go.mod (hash-equal). Mechanically the fallback guarantees stability. The trade-off is parity freshness: a committed snapshot catches drift only when regenerated from root source — it's literals-with-extra-steps unless regeneration is wired into a gate. It's a valid fallback, not an equivalent to the compile-time-checked live import.

### 4. build vs test resolution — binary stays root-free
Verified on the in-flight state: `go build ./...` → `go list -deps` contains **no root packages**; `go test -race` links `shared/core` into the test binary only. Both build and test pass *without* tidy too (pruned graph doesn't pull snaplink's requires for a stdlib-only import), and the committed tidied state is `go mod tidy -diff`-clean. Caveat to state precisely: the "test-only" claim covers root *packages* only — the 7 go.mod version bumps apply to the production binary's dependency versions (x/net 0.53 etc.). Same fingerprint as mcp (mcp go.mod shows x/net v0.53.0), same-major, root-aligned, cache-resident — benign but module-wide.

### 5. Toolchain — consistent
Root/mcp/operator all `go 1.26.1`; zero `toolchain` directives; CI `setup-go` uses `go-version-file: ${{ matrix.module }}/go.mod` per module (ci.yml:177), so each module self-pins. Local go1.26.5 + `GOTOOLCHAIN=auto` satisfies ≥1.26.1. The local replace adds no toolchain coupling.

### 6. CI interactions — all clear
- **ci-modules (Makefile:262-263)**: `cd cmd/sso-operator && $(GO) build ./... && $(GO) test -race -count=1 ./...` — both pass on the in-flight state.
- **mod-tidy-all** (not in `ci`): a no-op on the committed tidied state (tidy is idempotent, hash-stable on second run).
- **`python cli.py modules check`**: `validate_repository` (module_catalog.py:918) inspects only `snaplink.module.json` manifests/profiles — never reads go.mod. Passes; sso-operator isn't a catalog module.

### 7. Failure modes (empirically distinguished)
- **Replace removed, require kept**: fails **both** build and test, loudly — `missing go.sum entry needed to verify package … provided by exactly one module` (module-path-prefix collision with snaplink@v0.0.0-00010101000000-…; local replaces record no sums, and `go mod download` can't fix it remotely). Stronger/earlier than the design implies.
- **Require removed, parity test present**: build still passes; test fails `no required module provides package …/shared/core` — the exact "CI-only detection boundary for R1" (ci-modules runs test). Confirmed.

**Bottom line:** the mechanics are sound and match the mcp precedent exactly; the only precision correction for the design narrative is that the replace is module-wide by language design (inert for build only because nothing production imports the root), and the production footprint is 7 indirect dependency-version bumps — not zero. Rollback for the in-flight state remains revert go.mod/go.sum + delete the untracked parity test.
