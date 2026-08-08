Done. The evidence-backed requirements specification is complete.

## Deliverables

- **Canonical spec**: `docs/architect-analysis/auto/cmd-sso-ctl-entitiescmd-requirements.md`
- **Pipeline artifact**: `docs/architect-analysis/auto/runs/opt-entitiescmd-into-the-no-redirect-credential--5001a419/artifacts/requirements-10762e10/requirements.md` (+ meta.json with fingerprint)

## Verification summary

**All 8 citations checked** — confirmed with minor line drift, documented in §1:

| Citation | Verdict |
|---|---|
| `tenants.go:253/274/297` `apiclient.New()` zero-options | Verified at :254/:275/:298 (fetchList/fetchOne/doWrite) |
| users.go shares helpers | Verified — users.go:118/151/174/198/223, zero direct client construction |
| `apiclient.go:79-92` WithNoRedirect/rejectRedirect + rationale | Verified — exact "never forwarded to a redirect target" doc |
| `check.go:111`, `token.go:352` probes opted in | Verified (drift → :148, :417) |
| `tenants_test.go:15-27` withMockAdmin | Verified — returns server, redirector-capable |
| oauthwire strict binder absent | Verified — no `bind_strict.go`, zero matches |
| apiclient_test.go mirror coverage | Verified — `TestNew_NoRedirect`/`TestWithNoRedirect_StopsFollowing` (two-server pattern) |

**New evidence produced**: a temporary pre-fix repro against the real `RunTenants` path showed the 307 was followed with **exit 0** while the target received `Authorization: Bearer` + replayed `{"status":"suspended"}` body — confirming the threat model on Go 1.26.5 (same-hostname/subdomain bearer forwarding, 307/308 body replay). Repro file removed; build/vet clean.

**Two substantive corrections documented** (scope kept per instruction):
1. "One credential-bearing surface not opted in" is false — `tui/run.go:38`, `tokenscmd`, `sessionscmd`, `clientscmd` share the zero-option pattern; recorded as out-of-scope follow-up.
2. "T-8e" is campaign lineage, not a repo symbol; acceptance's testable core is the apiclient_test.go mirror.

**Acceptance preserved verbatim and made testable**: REQ-1..REQ-4 → A1–A6 criteria — GET + 307-write no-follow tests in both test files (target counter == 0, exit non-zero, target returns 200 so tests fail pre-fix), byte-identical regression of the 16 existing mock-admin tests, plus build/vet/maintainability gates.

**Pre-existing failures reported separately** (unrelated, untouched): `cmd/sso-ctl` `TestSubcommands_CheckIsWired` and apiclient `TestCheck_*`/`TestSweep_*` (sweep-surface trace_id/issuer issues). `entitiescmd` is fully green.
