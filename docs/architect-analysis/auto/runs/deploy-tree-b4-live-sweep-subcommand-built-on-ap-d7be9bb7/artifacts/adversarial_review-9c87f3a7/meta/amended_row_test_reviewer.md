Done. The test-mapping doc has been revised to cover the amended failure surface.

## Deliverable

**`docs/architect-analysis/auto/cmd-sso-ctl-apiclient-test-mapping.md`** (rev 2, 223 lines — doc-only, no `.go` edits, so no build gates triggered).

### §0 — Amendment surface mapped
New section tying each amendment to its mapped failure modes: security-review items 1–4 (no-redirect pin, URL validation, redaction, crypto/rand) plus CLI-conventions F-3 (effective-addr preflight).

### New test entries for every amendment-introduced failure mode
- **3xx-on-content-rows semantics** → `TestSweep_3xxContentRowFails` (six content rows — discovery/jwks/mint/revoke/introspect-401/invalid_scope-400 — fail on any 3xx) and `TestSweep_3xxTruthinessPasses` (five truthiness rows pass on 3xx without following, preserving A3's login-page-302 case).
- **Redirect coercion** → `TestSweep_RedirectNotFollowed`: 302/307 targets receive zero requests (covers the 307/308 body-exfiltration and same-hostname bearer-forwarding vectors in one assertion).
- **userinfo/empty-host/query rejection** → `TestCheck_AddrValidation` (7-case exit-2 data-driven matrix; rejection never echoes the value).
- **bad-env `SSO_ADMIN_ADDR` preflight** → `TestCheck_EnvAddrValidation` (env wins over flag per apiclient.go:60-62; zero requests on rejection).
- **redactURL/sanitizeBody behavior** → `TestRedactURL_RedactsUserinfo` + `TestSanitizeBody_RedactsSensitiveFields` (unit) + `TestDiagnostics_NeverEchoSecrets` (integration: neither `--client-secret` nor a minted token ever reaches stderr; 200-with-missing-token branch prints only the decode error).
- **WithNoRedirect contract** → `TestWithNoRedirect_StopsFollowing` in `apiclient_test.go` (option stops following; absence preserves default — existing subcommands untouched).
- **Extended row-2 advertised-endpoint-userinfo** → `TestSweep_AdvertisedURLRejection` (userinfo/relative/empty-host → failed-as-skipped, zero requests, redacted diagnostic).

### Coverage verification
- All 25 design-§5 rows mapped (rows 2, 7, 19, 22, 23, 24 extended in rev 2; the eight rev-1 gaps stay closed) — zero gaps.
- All 8 amendment rows M-1..M-8 mapped — zero gaps.
- All A1–A8 mapped in §3, with A1's registration test pinned to `dispatch_test.go` and A8's exit-2 matrix extended with the addr cases.

### Load-bearing correction found during verification
`crypto/rand.Read` **never returns an error** on Go 1.26.5 (it crashes irrecoverably — verified via `go doc`), so the design's "rand failure → exit 1" pin is only implementable as `io.ReadFull(crypto/rand.Reader, …)`. This is now pinned in §1 (with `rand.Reader`'s swap-ability verified) and in the M-8 test criterion, so the implementation can't silently use the crashing API.
