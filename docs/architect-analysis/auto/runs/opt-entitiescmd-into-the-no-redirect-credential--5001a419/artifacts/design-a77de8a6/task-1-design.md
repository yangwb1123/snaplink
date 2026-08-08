All verification and the design artifact are complete. Summary:

## Verification results — all 7 evidence claims confirmed

| Claim | Verdict |
|---|---|
| `tenants.go:254/275/298` zero-option `apiclient.New()` | ✅ Exact lines in `fetchList`/`fetchOne`/`doWrite` |
| `users.go` shares helpers (118/151/174/198/223), zero direct construction | ✅ `apiclient.New()` appears nowhere in users.go |
| `apiclient.go:79-92` `WithNoRedirect`/`rejectRedirect` + "never forwarded" rationale | ✅ Doc :79-87, func :84-87, policy :90-92 (`http.ErrUseLastResponse`) |
| Probes opted in: check.go:111→**148**, token.go:352→**417** | ✅ Line drift confirmed; check.go:327 uses same policy |
| `tenants_test.go:15-27` `withMockAdmin` | ✅ (:15-21, returns server, sets `SSO_ADMIN_ADDR`) |
| oauthwire strict binder absent | ✅ No `bind_strict.go`; zero `StrictBind` matches repo-wide |
| apiclient_test.go mirror coverage | ✅ `TestNew_NoRedirect` :126, `TestWithNoRedirect_StopsFollowing` :179, two-server + counter |

**Independent repro (evidence's was deleted, so re-run):** on Go 1.26.5, `RunTenants(["list"])` behind a 307 → **exit 0** with `Authorization: Bearer` forwarded to the target; `set-status` → exit 0 with bearer **and** replayed `{"status":"suspended"}` body. Threat model is real. Temp repro deleted; build/vet clean; entitiescmd 16 tests green; apiclient redirect pins green; the claimed pre-existing failures (root depth/fanout gates from `docs/architect-analysis/auto/runs` accumulation, `TestCheck_*`/`TestSweep_*`) confirmed unrelated on the pristine tree.

## Design artifact

**`docs/architect-analysis/auto/runs/opt-entitiescmd-into-the-no-redirect-credential--5001a419/artifacts/design-a77de8a6/task-1-design.md`**

- **API changes:** none exported — 3 one-line edits (`apiclient.New(apiclient.WithNoRedirect())`); CLI contract: any 3xx becomes visible `HTTP 307` error, exit 1 (was silent exit 0). No Err*/endpoint/config docs per AGENTS.md §5.6.
- **Compatibility:** fail-closed only on 3xx; non-3xx byte-identical; redirecting admin gateways now hard-error (operators point `SSO_ADMIN_ADDR` at canonical origin); independent of the unlanded oauthwire binder.
- **Failure modes:** F1 pre-fix silent leak (repro-verified, eliminated); F2 legit gateway redirects break (intended); F3 regression pin at subcommand boundary; F4 tests must use 307 not 302; F5 sibling surfaces (tui/tokenscmd/sessionscmd/clientscmd — verified same pattern) as follow-up; F6 server binder as separate direction.
- **Migration:** single commit, 3 edits + 4 tests, no flag (fail-closed precedent), release note for operators.
- **Acceptance mapping:** A1–A3b (307 two-server tests through `RunTenants`/`RunUsers`, exit 1 + target counter 0, pre-fix FAIL repro-verified), A4 (16 existing tests byte-identical), A5/A6 (build/vet/gates + apiclient pins), each with pre/post-fix expected results and exact commands.
