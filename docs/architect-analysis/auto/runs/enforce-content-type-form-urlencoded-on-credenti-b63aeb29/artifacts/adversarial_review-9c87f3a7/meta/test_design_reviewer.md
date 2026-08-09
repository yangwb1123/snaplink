Audit complete. Report: `docs/architect-analysis/auto/runs/enforce-content-type-form-urlencoded-on-credenti-b63aeb29/artifacts/r7-test-delta-audit.md`

## Verdict: sound mechanism, but the design doc as written is vacuous — the control arm is under-specified

**Working-tree state first:** the R7 delta is **not implemented**. `assertQuotaTokenRequest`/`assertRetentionTokenRequest` (`cmd/snaplink-billing/quota_relay_test.go:149,94`) still assert only BasicAuth + `PostForm`; no `billing_form_e2e_test.go` exists (the untracked sibling `test/audit_provisioner_form_e2e_test.go` drives one real source, form-arm only). Baseline verified green. The strict surface has landed (opt-in `WithCredentialFormOnly`, `ErrFormOnly`, 415 plain `{"error":"invalid_request"}` at all eight sites).

**Q1 — fails against a non-strict server?** R7.2's form arm alone is **vacuous**: both real sources hardcode canonical form CT (`oauth_token_source.go:200-210`, `platform_token.go:151-162`), so strict and non-strict servers both return 200. Only the JSON control arm fails against a non-strict server — and **the authoritative design doc §3.7 never specifies it** (it exists only in the evidence summary). R7.1 is a server-independent client-contract pin; its marginal value over PostForm is the parameterized-CT case (`; charset=UTF-8` parses via Go's HasPrefix `parsePostForm` and binds on the strict server — exact-CT assert is the only detector).

**Q2 — control arm drives the same mint path?** Impossibility correction: the sources cannot emit JSON — the control arm must be a raw JSON POST with the same TokenURL + same BasicAuth creds. The pair is load-bearing: bind precedes client auth (`server_token.go:30` → `:35`), so the form arm's 200 proves creds valid while the JSON arm's 415 isolates media-type enforcement. Assert exact 415 + `exact415Body` (landed envelope; design doc's "400" is drift).

**Q3 — fresh-source-per-identity defeats cache masking?** Yes, and it's structurally required: both sources cache with mutex + singleflight (second call = zero HTTP). Three constructor sites (`relay.go:45-52`, `quota_relay.go:347-352, 420-428`) = three independent caches = three real mints. Recommended belt-and-braces: reuse `mintCountingIssuer`, assert exactly 3 `Issue` calls (also proves the JSON arm never minted).

**Q4 — CT end-to-end?** R7.1 as designed asserts the wire header at the stub server — yes, end-to-end, closing the exact R7 gap. R7.2's server side is already pinned by the landed 415 rows (valid creds, never-mints, exact bytes).

**Four drifts to fix before implementation:** (1) 400→415 in the doc; (2) strict-default-true in the doc vs landed opt-in false — `WithCredentialFormOnly(true)` is mandatory, not robustness; (3) add the control arm to §3.7; (4) file-name drift (`billing_form_e2e_test.go` vs `billing_strict_form_e2e_test.go`).
