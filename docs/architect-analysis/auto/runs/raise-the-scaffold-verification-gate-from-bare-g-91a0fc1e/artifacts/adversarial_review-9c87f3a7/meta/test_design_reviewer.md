All review inputs are now grounded. Here is the review.

# Review of the scaffold_contract_test.go plan

**Note on sourcing:** the design artifact (`task-1-design.md`, 20 lines) compresses the m1–m9 table rather than enumerating it, so I reconstructed the mutation set from requirements acceptance cases 3/4/6 + the R2a/R3a/R4a fix surface, then verified every load-bearing claim against HEAD and by live experiment.

## 1. m1–m9 → named assertion mapping — holds, with 3 caveats

Reconstructed mapping (4 named assertions from requirements §7: `assertRegisteredErrorCodes`, `assertNoLegacyPathPort`, `assertNoPathLiterals` incl. Path\* existence, `assertFormContentTypeGuard`):

| # | Mutation | Assertion | Pre-fix (HEAD) | Post-fix |
|---|---|---|---|---|
| m1 | `ErrorBody("not_implemented")` in a 501 stub | A1 registered-codes | FAIL (emitted today ×4) | PASS |
| m2 | `ErrorBody("method_not_allowed")` in 405 branch | A1 | FAIL (emitted today) | PASS |
| m3 | `ErrorBody("create_failed")` in POST example | A1 | FAIL (emitted today) | PASS |
| m4 | `ErrorBody(core.ErrNoSuchConst)` | A1 const-resolution path | — (mutation-only probe) | FAIL |
| m5 | `/authenticate` (unquoted comment) | A2 legacy-path/port | — (mutation-only) | FAIL |
| m6 | `8080` literal | A2 | — | FAIL |
| m7 | quoted `https://host:8080/...` | A2 (regex `https?://[^"/]*:[0-9]+`, also catches `:8080:0`) | — | FAIL |
| m8 | `router.GET("/path", ...)` literal | A3 path-literals | FAIL (the one existing offender) | PASS |
| m9 | guard dropped from POST example | A4 form guard | FAIL (no guard exists at HEAD) | PASS |

Verified against repo: the 3 banned codes have **0 rows** in `docs/error-codes.md` (250 rows total); all 6 codes the fixed templates emit (`invalid_request`, `invalid_grant`, `internal_error`, `not_found`, `no_token_strategy`, `not_supported`) are registered; `PathUserInfo` exists (consts.go:29); 133 string-valued `ErrX` consts + 16 `errors.New` (design's corrected registry numbers confirmed); auth/store templates contain zero `ErrorBody`; filename rules (`%s.go`, `%s_store.go`, `%s_handler.go`, `%s_grant.go` — generate.go:55–82) give each kind subtest a deterministic file to scan.

**F1 — message granularity is what makes m1–m3 non-equivalent.** All three hit A1; they are distinguishable only if the assertion's failure message names the offending code per occurrence. The requirements mandate this ("naming the violated invariant and the offending literal/code"), but the plan must pin it — a "found unregistered code" aggregate message makes m1≡m2≡m3 and the mutation pass cannot prove "exactly the corresponding named assertion" (case 6).

**F2 — m5 insertion style determines single-assertion firing.** Inserting `/authenticate` as a *quoted* literal (`"/authenticate"`) trips A2 **and** A3 (the `"\/`-anchored literal pattern), violating "exactly the corresponding named assertion fails". The mutation pass must insert it unquoted. m6/m7/m8 are safe: `"8080"` doesn't start with `/`, the URL starts with `h`, `"/path"` matches only A3.

**F3 — A4 must check shape + ordering, not just the literal.** If `assertFormContentTypeGuard` tests only the media-type literal's presence, a mutation that keeps the literal but neuters the actual check is an equivalent mutant (passes silently). R4 requires all three: the literal, the `Header.Get("Content-Type")`/`HasPrefix` check, and `strings.Index` ordering before `ctx.Bind(`. Verified the fixed template can satisfy this: the guard is commented teaching text before the sole `ctx.Bind` (templates_handler.go:73), and the commented `strings` import (C1) keeps the compile gate green.

Also confirmed: the slash-literal regex must be anchored on the literal's **first character** (`"\/`), not "any quoted literal containing a slash" — the authenticator template's `"https://idp.example.com/auth?state=%s..."` (templates.go:98) is emitted verbatim into generated output scanned for all kinds, and would false-positive under the loose form. It is safe under the anchored form (verified).

## 2. TestRunExitCodes — exit 0/1/2 + skip — sound

- **exit 2**: unknown kind (`Run(["bogus"])`), missing `--name`, missing `--package` — all normal `return 2` paths, no subprocess needed. **Caveat:** the flagset is `flag.ExitOnError` (cmd.go:39), so the test must never pass a malformed flag *value* (`--name` with no argument) — that `os.Exit(2)`s the test binary instead of returning.
- **exit 1**: hermetic probe via the C4 quirk — absolute `--output` outside the main module makes `go build` fail with "outside main module or its selected dependencies". I reproduced this live from inside the repo cwd (build exit 1), and **`go vet` on the same target fails identically** — so the widened error sentence ("does not build or pass vet") is honest and the probe needs no template mutation.
- **exit 0**: requires `chdir` into a real module — reproduced live: `go build` and `go vet` on an absolute in-module directory both pass offline.
- **`--skip-build-check`**: same outside-module setup + flag → exit 0; since the identical setup exits 1 without the flag, a 0 proves **both** build and vet were skipped (either one running would exit 1). This is the cleanest possible hermetic proof.

## 3. Kind-subtest vet exec — hermetic/offline confirmed

Reproduced live in a `newBuildableModule`-identical scratch module (replace snaplink → repo root, copied go.sum): `GOFLAGS=-mod=mod GOPROXY=off go vet ./...` passes with zero network. Scope is exactly the generated package — `./...` matches only the scaffold module's tree; the replaced snaplink packages are outside it (design's "operator-package blast radius unchanged" holds). The scratch go.mod declares the repo's `go` directive (1.26.1) vs installed 1.26.5, so no GOTOOLCHAIN download; the environment profile is byte-identical to the existing build gate, adding no new network surface. `t.Parallel()` concurrency is safe (per-module dirs, cache file-locking).

## 4. Absolute-output unit test + C4 chdir — confirmed, one strengthening

The chdir is mandatory, not cosmetic: I reproduced that from the repo cwd, `go build /abs/out` fails "outside main module" even for valid generated code (the C4 quirk), while from inside the scaffold module both build and vet on the absolute in-module path pass. `t.Chdir` is available (Go 1.26.5). Two constraints: **F5 — the negative probe must be a vet-ONLY violation** (`fmt.Printf("%d", "not a number")`; reproduced: build passes, vet exits 1). The design's feasibility note ("injected unused variable") is build-breaking and would be caught by the build step first, proving nothing about vet; with the vet-only probe the test can also assert the returned error names "go vet". **F6 — the chdir-using tests must not run `t.Parallel()`**, since `os.Chdir` is process-global; only the kind subtests (which use `cmd.Dir`, no chdir) may stay parallel.

## Verdict

**PASS with required plan amendments** — the mutation→assertion mapping, exit-code coverage, hermeticity, and chdir handling all verify against the repo and live experiments, provided the plan pins: per-code failure messages in A1 (F1), unquoted `/authenticate` insertion in the mutation pass (F2), the three-part A4 check shape (F3), first-char-anchored literal regex (F4), vet-only negative probe (F5), and serial execution for chdir-using tests (F6). No test in the new file needs template mutation — the C4 quirk supplies the exit-1 probe — keeping m1–m9 as the sole template-mutation surface.
