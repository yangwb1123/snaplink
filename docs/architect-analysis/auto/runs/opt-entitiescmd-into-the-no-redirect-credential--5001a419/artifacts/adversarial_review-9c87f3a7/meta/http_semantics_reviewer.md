Verification complete. Report: `docs/architect-analysis/auto/runs/opt-entitiescmd-into-the-no-redirect-credential--5001a419/artifacts/verification-3692645e/task-1-verify.md`

## Results per question (Go 1.26.5 source + empirical harness in /tmp/verify-redirect)

**1. ErrUseLastResponse body handling — NO leak in entitiescmd.**
`ErrUseLastResponse` returns the 3xx with err **nil** and the body **unclosed** (client.go:704-705); the caller must close it. Empirically: drained+closed → keep-alive reuse (1 conn/3 reqs); close-without-drain → conn torn down, no leak; never-closed → conn stays open. All three entitiescmd helpers (`fetchList`/`fetchOne`/`doWrite`, tenants.go:254-312) route every response through `apiclient.ReadBody` (defer-close + ≤1MB read), so the 3xx body is both drained and closed on every path. Only caveat: a >1MB 3xx tail isn't drained — connection torn down, still no leak.

**2. CheckRedirect coverage — full.** Every request funnels through `c.http.Do` (apiclient.go:123); `WithNoRedirect` pins the whole client. The three client constructions in the package are all pinned: `ck.client` (check.go:148), `probeClient` (check.go:327), T-9's bare client (token.go:417). Health checks = the check sweep only (discovery sweep.go:118 + probe rows), all pinned. No retry client or custom RoundTripper exists in cmd/sso-ctl. Sibling surfaces (tui/tokens/sessions/clients) remain zero-option — matches design F5.

**3. Method behavior — exactly as documented.** Post-fix, no follow exists at all for any 3xx (the sentinel short-circuits before the second send). Pre-fix empirical table: 301/302/303 → POST→GET, body dropped; 307/308 → method+body replayed; bearer forwarded same-host (ports irrelevant), stripped hostname→IP/cross-domain. The "307/308 bodies, same-host/subdomain Authorization" doc rationale is accurate.

**4. Surfaced error — status yes, Location NO (finding).** Helpers print `list failed (HTTP 307): <body>`; the Location header is never read or printed. Go-generated redirect bodies echo the target in an HTML anchor, but realistic gateways return empty bodies → operator sees no destination. Non-blocking; recommended one-line follow-up: append `resp.Header.Get("Location")` in the three non-200 branches (sweep diagnostics share the gap).

**5. No follow path remains (post-fix).** users.go constructs nothing; its only network path is the three shared helpers, which the design pins. Go's Transport never follows redirects — redirect logic lives solely in `http.Client.CheckRedirect`, and the fix eliminates the only nil-CheckRedirect construction in entitiescmd.

**Test state:** entitiescmd 16 tests green; redirect pins (`TestNew_NoRedirect`, `TestWithNoRedirect_StopsFollowing`) green; the two failing apiclient tests (`TestCheck_AddrValidation` no-scheme/empty-host, `TestSweep_GreenPath` wrong-bytes) are diagnostic-text drift, unrelated to redirects — confirming the design's pre-existing-failure claim. No repo `.go` files were modified.
