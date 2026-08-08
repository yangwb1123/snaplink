All verification complete. The design doc has been corrected in place. Here is the full validation.

---

## Verdict

The contradiction is real and confirmed: **§6's R2 row is unimplementable as written — a plain `NotContains("!= discovery issuer")` fails on the intended behavior** because the variance probe's own row 3 (§2.5) re-emits the standard discovery diagnostic for mint 2. The design's §2.5 and §6 contradict each other; §6 loses. I resolved it by replacing the row with a count- and value-scoped assertion (mint-2's rows are self-tagging via the variance host value), pinned the full stderr signature in §2.6, and additionally found **one factual error in E11/§3/§9**: `TestSweep_TokenEndpointSuffix` is *not* an iss-misalignment row and R5 cannot repair it.

## 1. The contradiction — resolution and exact assertion

**Why §6's row is broken.** On the `hostDerivedIssuer` fixture (no `WithIssuer`), `ck.doc.Issuer` = `http://127.0.0.1:PORT` (request-base-derived), mint-1 `iss` = same (lockstep — silent), mint-2 `iss` = `http://sweep-host-variance.invalid`. Per §2.5 assertion 3, mint 2 fires the standard `claims: iss "http://sweep-host-variance.invalid" != discovery issuer "http://127.0.0.1:PORT"` row. So stderr *does* contain `!= discovery issuer` on a correct implementation, and "for the first mint" is unimplementable: mint-1 and mint-2 rows share the identical `claims: iss %q != discovery issuer %q` shape, no mint tag exists, and there is no stderr delimiter between the two row sets (both are `claims:`-prefixed lines from different functions onto one stream).

**Why the alternatives don't work.** *Scope to the pre-variance block*: not implementable — no block marker exists, and on this fixture the pre-variance block is empty (mint-1 is silent), so a block-scoped NotContains would be vacuous. *Tag second-mint rows*: implementable, but deviates from the design's deliberate "same diagnostic shape as `verifyIssuerClaims`" (operator recognition) and duplicates the format for one failure class. The correct mechanism is the one the design already has: **the variance host value is the mint-2 tag** — no other row can carry `http://sweep-host-variance.invalid`.

**Exact assertion** (now written into §2.6 of the design):

```go
varianceISS := "http://" + hostVarianceHost
if n := strings.Count(errOut, "!= discovery issuer"); n != 1 {
    t.Errorf("stderr has %d discovery-mismatch rows, want exactly 1 (mint-1 green, mint-2 only):\n%s", n, errOut)
}
if !strings.Contains(errOut, fmt.Sprintf("claims: iss %q != discovery issuer", varianceISS)) {
    t.Errorf("stderr missing mint-2's discovery row: %q", errOut)
}
if strings.Contains(errOut, fmt.Sprintf("claims: iss %q != discovery issuer", srv.URL)) {
    t.Errorf("mint-1 fired the discovery row — lockstep blind spot not reproduced: %q", errOut)
}
want := fmt.Sprintf("claims: iss %q differs across Host variance\n"+
    "claims: iss %q != discovery issuer %q\n"+
    "claims: iss %q != declared issuer %q\n",
    varianceISS, varianceISS, srv.URL, varianceISS, srv.URL)
if errOut != want {
    t.Errorf("stderr = %q, want pinned signature %q", errOut, want)
}
```

The three predicates are individually meaningful: count==1 asserts the blind spot (mint-1 emits zero discovery rows) *and* that mint-2's row-3 exists; the Contains pins that the single row is mint-2's; the third pins that mint-1's form (`claims: iss "<srv.URL>" != discovery issuer`) is absent — i.e. the fixture misbuilt with `WithIssuer` or a broken stamping would fail the test, not silently pass.

## 2. The full stderr signature to pin (exactly one discovery row, from mint 2)

Ordered per §2.5's assertion order (2→3→4) and runT8a's wiring (mint diags → JWKS → verifyClaims → variance → revoke; all silent except the variance rows):

```text
claims: iss "http://sweep-host-variance.invalid" differs across Host variance
claims: iss "http://sweep-host-variance.invalid" != discovery issuer "<srv.URL>"
claims: iss "http://sweep-host-variance.invalid" != declared issuer "<srv.URL>"
```

stdout: `discovery: OK\nmint: FAIL\ninvalid_scope: OK\nintrospect: OK\ncheck FAIL\n` — exit 1. Deterministic: the only dynamic value is `srv.URL`, which the test computes from its own fixture. Note the pin deliberately bakes in row-3's redundancy ("explicit beats implicit"): if a future change drops row 3 as redundant, the count pin must be updated deliberately — that is the point.

**One strengthening for §6's R1 row** (also applied): `TestExpectIssuer_Mismatch` as originally specced (Contains `!= declared issuer`) would **not** fail if mint-1's R1 row regressed away while the variance leg's row 4 survived — the Contains is satisfied by row 4 alone. Pin `strings.Count(errOut, "!= declared issuer") == 2` (one per mint), and declare `--expect-issuer https://u:p@other.example` so the C2 redaction acceptance is actually asserted (`!= declared issuer "https://other.example"` present, `u:p` absent).

## 3. Fixture mechanics — re-derived end-to-end, all confirmed

| Mechanism | Verification |
|---|---|
| **ctx-stash propagation** | `token_client_credentials.go:50` is exactly `ti.Issue(ctx.Request().Context(), ...)`. A fixture middleware doing `r.WithContext(context.WithValue(r.Context(), stashKey, r.Host))` around `srv.Handler()` is visible to `Issue` via the router's `Request() → .Context()`. Feasible ✓. Added a robustness requirement to §2.6: `Issue` must error when the stash is absent, never mint `http://` + empty host. |
| **Shared-key coherence** | `WithEd25519Key` (ed25519_jwt_issuer.go:203), `WithEd25519KeyID` (:273), `WithEd25519TokenTTL` (:182) all exist. Per-request instances sign with `h.key`/`h.kid`; `base` (same key/kid) serves `Validate`/`Revoke`/`JWKS` — `ed25519_validate.go` checks revoked, header alg/typ, signature-by-kid, exp/nbf only (**never `iss`**); `base.revoked` is the deny list shared across requests; JWKS handler probes `core.JWKSProvider` (accessors.go:392-396), so `hostDerivedIssuer.JWKS` is required and present. ✓ |
| **No-WithIssuer lockstep** | `sso.NewServer` defaults `s.issuer = DefaultIssuer` (sso.go:67, `"snaplink-sso"`); discovery issuer falls back to `requestBaseURL` (server_discovery_config.go:62/144, override only at 264-265), which is `middleware.BaseURL` = `scheme://r.Host` with no trusted proxies. Fixture stamps `"http://"+r.Host` → mint-1 `iss` == discovery issuer exactly; `verifyIssuerClaims` and the R1 row are both silent. ✓ |
| **Variance mint on a real server** | Bare `sso.NewServer` has no Host-validation middleware (net classifier, mesh authz, DPoP, tenant middleware all opt-in and unwired); routing is path-based. `req.Host` override lands on the wire as the Host header; server `r.Host` reflects it. `stubCheck`'s `r.Clone` preserves `Host` (plain field), so the posture test's request filtering works. ✓ |

## 4. Per-row regression matrix

| Row | Passes on intended behavior | Fails on regression |
|---|---|---|
| `TestExpectIssuer_Mismatch` | exit 1; exactly 2 `!= declared issuer` rows, userinfo stripped; `mint: FAIL` | Flag unwired → exit 2; R1 row dropped → count < 2 (with the new pin; the old Contains would *pass* — see §1); C2 echo → `u:p` visible |
| `TestExpectIssuer_HostVarianceFails` | exit 1; 1 discovery row (variance host); 3-row pinned signature | Old NotContains fails on correct impl; count≠1 when the blind spot isn't reproduced (mint-1 row) or row 3 is dropped; `differs` row missing |
| `TestHostVariance_Posture` | green run: exit 0, `goldenGreenStdout`, silent stderr; variance request has empty `Authorization`, `Host == sweep-host-variance.invalid`, URL == advertised token_endpoint, redirect target receives 0 hits | Host not applied (no recorded variance request); bearer attached; wrong target URL; redirect followed (target hits > 0) |
| `TestMint_TenantIDExpectation/dup-in-ext` | exit 1; exactly the static dedup row (`ext` decodes to `map[string]any` ✓); no `t1` echoed | R3 absent → exit 0; value echo in the row |
| `TestMint_TenantIDExpectation/ext-only` | exit 1; `claims: tenant_id absent`; no `strip missing` | Over-broad R3 (dedup fires without top-level match) → both rows. Note: passes trivially without R3 — it is the negative guard for the dup row's premise, as designed |

**Determinism:** all new rows emit constant stdout (`goldenGreenStdout` on green; the constant FAIL shape otherwise — `CheckRun` does not short-circuit T-8d/T-9 after a mint failure, verified in check.go) and constant stderr modulo the fixture's own `srv.URL`; `jti`/kid/ports never reach output; the variance leg adds no stdout; `TestStdoutDeterministic` with `--expect-issuer` stays byte-deterministic.

## 5. Additional finding — E11 miscategorization (corrected in doc)

`TestSweep_TokenEndpointSuffix` is **not** an iss-misalignment row. Running it in isolation shows its stderr has no iss diagnostic: the stub advertises `/oauth2/token`, which satisfies `strings.HasSuffix(path, "/token")` — the suffix diagnostic can *never* fire — and the stub mounts no `/oauth2/token` handler, so the truthiness row 404s first. R5 cannot repair it; the test is impossible under any correct implementation. The design's "seven iss-misalignment rows flip green via R5" (E11, §3, migration step 1) overstates: it is **six**. Corrected in the doc: E11 regroups, §3/migration-step-1 say six, and the recommended one-line fixture fix (advertise `/oauth2/tokenz`, update the expected diagnostic — in-file with the other `check_test.go` edits) is recorded, with tracking-as-out-of-scope as the fallback.

## Doc edits applied

`docs/architect-analysis/cmd-sso-ctl-b4-1-claims-gate-design.md`:
- **§2.6** — added the pinned stderr signature block, the count/value-scoped assertion code, and the fixture robustness requirement (Issue errors on missing stash).
- **§6 R2 regression row** — replaced the broken NotContains with the implementable count+value assertion.
- **§6 R1 mismatch row** — `== 2` declared rows (both mints) + userinfo-declared value to make C2 assertable.
- **§1 E11, §3 Test state, §5 migration step 1, §9** — corrected seven→six rows; `TestSweep_TokenEndpointSuffix` reclassified as a stale-expectation row with its fixture fix.

No production code was touched; the gates (`go build`, `TestMaintainability_`) are unchanged in their red state — the C1 budget failures (`CheckRun` 66 lines, `verifyClaims` 58/19) and the pre-existing `ed25519_jwt_issuer.go` 539-line failure were re-confirmed by running.
