All checks complete. Here is the audit.

---

# Audit: 18-case acceptance mapping (B4-3/T-2 design, `cmd-sso-ctl-b4-3-t2-design.md`)

**Basis:** re-verified every load-bearing mechanism against the tree, plus a live probe (real stock server built per `test/oidc_discovery_test.go`). Router, discovery assembly, configcmd entry points, fan-out, and the prior gate-run must-pins (`3fca04ef`) all re-checked.

## Verdict

The mapping's router corrections (C1/C2) are **verified correct**; but the claimed "18 cases" are really 16 G/W/T rows **plus two must-pins that do not exist as acceptance cases**, and the third must-pin (`--timeout <= 0` → exit 2) is **entirely absent from the design body**. Seven failure-mode-table rows have no dedicated test; the summary's C5 correction asserts a mechanism the implemented server **cannot produce** (empirically disproven). Detail below.

## 1. Failure modes / exit codes without a dedicated test

| Design §4 row | Exit | Coverage in §6 | Status |
|---|---|---|---|
| Sweep exceeds `--timeout` | 1 | none | **MISSING** — no hanging-endpoint test, no pin on the `sweep timed out after <dur>` message or its exit-1 (not 2) classification |
| `--url` trailing slash **or path component** | 1 | none | **MISSING** — see §3.1; also the "no cascading" claim is false for path components |
| Redirect chain to a 404 | 1 | none | **MISSING** — no redirect-handler test; POST-retry-after-301/302/303 semantics (net/http converts to GET) unpinned |
| Config-load failure **with allowlist present** | 1 | none | **MISSING** — the "loader error wins, allowlist never masks" row is untested (cases 11/12 only cover successful loads) |
| Fetch: 404 on the well-known path, TLS/DNS/proxy failure | 1 | case 8 covers only 500 + non-JSON | **PARTIAL** |
| Probe: dial/read error (unreachable advertised endpoint) | 1 | case 4 covers only 404-both | **PARTIAL** |
| Shape: advertised non-http(s) scheme, empty host, port > 65535 | 1 | case 6 covers only `:0` and `:8080:0` | **PARTIAL** |
| `--url` unparseable value, non-http(s) scheme, empty `""` | 2 | case 16 covers only missing `--url` + unparseable `--timeout` | **PARTIAL** |
| `--timeout <= 0` (parses fine: `0s`/`-1s`) | 2 | **not in the design at all** (see §2) | **MISSING** |
| 401/500 on probe passes; 501 PAR/device passes | 0 | only incidental via case 1's stock server | **PARTIAL** — no dedicated pins |

Exit-code inventory: **exit 0** fully pinned (1, 7, 10, 13, 15); **exit 1** pinned for 2–6, 8, 11, 12 only; **exit 2** pinned for 14, 16 + pre-existing only.

## 2. The three must-pins: claimed resolved, artifact says otherwise

The summary asserts "all three must-pins resolved", but:

- **Pin 1 (canonical violation order + byte-exact multi-violation test):** no acceptance case asserts exact stderr bytes for a doc with multiple *simultaneous* violations. Case 3 is one-violation-per-field. Cross-pass ordering (equality → shape → probe within one doc) is unpinned. "Slice-driven field table, never map iteration" appears **only in the summary** — §2.1's body never states the iteration mechanism, and §2.3's checker signature even takes `doc map[string]any`.
- **Pin 2 (empty stdout on allowlist failure):** cases 11/12 pin stderr content but not stdout emptiness. The `config OK: …` print (configcmd/main.go:104) sits between `config.Load` and `--print`; no test would catch a regression that places the gate after it. No `--print` + failing-allowlist variant either.
- **Pin 3 (`--timeout <= 0` → exit 2):** **absent from the design body.** §2.1 says only "Parse failure → usage error (exit 2)"; §4 F7 lists only "unparseable"; case 16's `BadTimeout` covers only unparseable. As written, `--timeout 0s` yields an immediately-expired shared ctx → every probe fails → exit 1 "timed out" — precisely the operator-confusing runtime failure the gate run flagged. This must be folded into §2.1/§4/§6 with a dedicated two-sub-case test (`0s`, `-1s`).

## 3. Mechanism-producibility findings

### 3.1 C5 is empirically false — the summary asserts a mechanism the server cannot produce

Live probe (real `newDiscoveryServer` replica, WithIssuer set): `issuer = https://sso.test` but **every endpoint = `http://127.0.0.1:46219/*`** (request base). `applyMFAIssuerSigning` (server_discovery_config.go:264-265) overrides only `cfg.Issuer`; `buildBaseMetadata` (142-161) always uses `base = requestBaseURL`. C5's claim — "WithIssuer yields `https://sso.test/*` endpoints … would fail acceptance case 1" — cannot be produced. And since the sweep deliberately never equality-checks `issuer` (§7) and never probes it (C1b), the WithIssuer'd stock server **passes case 1 anyway**. The correction is harmless, but §6's helper spec ("WithIssuer + …") and the summary's C5 directly contradict each other, and §6's version is the correct one. Resolve before implementing; drop the false premise from the summary.

### 3.2 C1/C2 verified correct against the implemented router

`StdRouter.ServeHTTP` (shared/core/router.go) skips method-mismatched routes and falls through to `http.NotFound` — confirmed live: `GET /token` → **404**, never 405. The corrected case-7 mechanism (GET-404 → POST-non-404) is producible; the spec's original "405 proves the route" mechanism is correctly repudiated. Bonus datum: `GET /auth/login` → **200** on the stock server (registered for GET), so case 1's authorization-endpoint probe passes without the POST retry.

### 3.3 Remaining cases

Cases 2–6, 8–16 all use hand-built docs / httptest handlers / `url.Parse` semantics that the design's own checker can produce. No other mechanism mismatch found. (The doc-fetch 404 → well-known route's `matchPath` segment comparison: a double-slash URL from a trailing-slash base genuinely 404s — the C1-era empirical list holds.)

## 4. Edge cases named in the brief — all unpinned

- **Trailing-slash/path-component base (exit-1 vs exit-2; no-cascading):** the exit-1 classification is asserted but unenforced — an implementer validating the base in flag parsing (exit 2) would pass every test in the mapping. The no-cascading claim holds **only for a single trailing slash**; a path-component base (`http://host/v1`) leaves the trimmed base containing the path → 4 equality violations cascade (and the fetch against `…/v1/.well-known/…` 404s first). Also unspecified: the base check is not one of the four pipeline passes — if fetch runs first with `base + "/" + Path`, a trailing-slash base yields a double-slash fetch-404 diagnostic, not the base violation. No test pins any of this.
- **Sweep timeout expiry:** no test (see §1). Needs a blocking handler + short `--timeout`.
- **Redirect-chain-to-404:** no test; also the POST-retry-after-30x conversion semantics are unpinned.
- **IPv6-literal bases:** zero coverage — no green (`--url http://[::1]:PORT` matching a server's doc), no trailing-slash variant, and the port-shape check's mechanism is unspecified (must be `url.Port()`-based; a naive `strings.Split(host, ":")` breaks on `[::1]`). Same family: a `--url` with query/fragment isn't excluded by the "no path" rule and would cascade.
- **Allowlist whitespace trimming:** asserted in §2.2, untested (`" a , b "`); `"a, ,b"` (whitespace-only entry → empty after trim) is undefined: usage error per the `",,"` rule, or skipped?
- **Multi-entry duplicates:** `"a,a"` membership works, but the error's `[%s]` rendering of the raw list (dedup? canonical order?) is unspecified and untested.

## 5. Recommended pins to add (smallest set closing every gap)

1. `TestCheckDiscovery_TimeoutExpiry` — hanging handler, `--timeout 50ms`, exit 1 + message (F2).
2. `TestCheckDiscovery_BaseTrailingSlash` and `_BasePathComponent` — pin exit 1, the winning diagnostic, and the violation *count* (1 vs cascading 4) — which forces the no-cascading claim to be fixed to single-slash-only or implemented with a pre-fetch base short-circuit.
3. `TestCheckDiscovery_RedirectChainTo404` — GET 302→404, POST 302→404 → exit 1 (F14).
4. `TestCheckDiscovery_TimeoutNonPositive` — `0s` and `-1s` → exit 2 (must-pin 3, folded into §2.1/§4).
5. `TestCheckDiscovery_MultiViolationExactBytes` — one doc with token-mismatch + `/authenticate` + `:0` port; assert full ordered stderr bytes (must-pin 1).
6. `TestRun_Validate_IssuerAllowlist_Mismatch_EmptyStdout` — with and without `--print`; assert stdout `""` (must-pin 2, incl. placement before the `config OK` print).
7. `TestCheckDiscovery_IPv6Base` (green + trailing-slash red), `TestRun_Validate_IssuerAllowlist_Whitespace` (`" a , b "`, `"a, ,b"`), `TestRun_Validate_IssuerAllowlist_Duplicates` (`"a,a"`).
8. Fill the F1/F3/F5/F7 partials: fetch-404, fetch-dial-error, probe-dial-error, advertised non-http(s)/empty-host/port-65536, `--url "://"`, `--url ftp://x`, `--url ""`.
9. Fix C5: restore `WithIssuer` in the §6 helper or state explicitly that it's omitted for simplicity — the current summary-vs-§6 contradiction must not survive into implementation.

**Bottom line:** 10 of the 18 claimed cases are adequately pinned; the trailing-slash/path-component, timeout-expiry, redirect-to-404, IPv6, whitespace/duplicate, loader-interaction, and all three must-pin behaviors have **no dedicated test**, and the design must be amended (not just the summary) before migration step 1 — otherwise the "no cascading violations", "byte-exact deterministic ordering", "empty stdout", and "`--timeout <= 0` → exit 2" claims are unenforceable, and C5 propagates a mechanism the server cannot produce.
