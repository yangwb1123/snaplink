All details verified — the design's asserted fake locations match reality. The deliverable is complete.

## Summary

**Task**: Treat the evidence as untrusted claims, verify them, and produce a concrete design with API changes, compatibility constraints, failure modes, migration steps, and testable acceptance mapping.

**Verification results** — every citation checked against the working tree (HEAD `61455c06`):
- **Exact**: `oauthwire/bind.go:30-45` dispatch (form :38-42, JSON-default :43-46); PKCE constant-time compares at `auth_code_handler.go:83/:85`; `constant_time.go` / `apikey.go:76`; four bind sites (`server_token.go:30`, `handle_introspect.go:120`, `handle_revoke.go:75`, `handle_par.go:66`); all four compose-tree `/token` consumers form-encoded (provisioner `platform_token.go:151-162` incl. CT at :162, stripe `billing.go:157-165`); `run.go:50-58`; bench :74/:89; Deps/option/config seams; no strict-mode knob (zero hits repo-wide); entry 3 of the analysis JSON with T-8(a-e) verbatim.
- **Drifts found** (all disclosed): requirements pin stale HEAD `1881c55d` (ancestor of current HEAD; tree still matches); `IntrospectDeps` at :29 not :27; `bind.go` 158 lines not 140; new finding — `errorBody` is trace-aware (`ErrorBodyWithTrace`), which pins the 415 to the plain `core.ErrorBody` shape.

**Deliverable**: rewrote `docs/architect-analysis/cmd-snaplink-audit-provisioner-b4-4-credential-form-only-design.md` as Revision 2, superseding the stale default-ON design (entry 2) and matching the re-selected opt-in requirements:
- **API**: `oauthwire.BindParamsFormOnly` + exported `ErrFormOnly` sentinel (resolves the [PROPOSED] naming), `oauth` aliases, `s.bindCredentialParams`, `sso.WithCredentialFormOnly` seeded `false` in `NewServer`, `RequireFormContentType()` on three Deps interfaces, `server.require_form_content_type *bool` (nil → option not appended).
- **Compatibility**: default-off byte-identical baseline; non-credential consumers, device/MFA/CIBA, `/register`, `/auth/login` untouched; openapi JSON variants stay; `interfaces/sso` 60-file ceiling respected (no new files; field in `sso_protocol.go:38`).
- **Failure modes**: F1-F9 incl. 415 envelope oracle safety, malformed-percent-encoding not `ErrFormOnly`, double-flip-point drift guard, pre-existing RED `TestSdkForm_PARClaimsThreaded` (sibling condition, not ours).
- **Migration**: ship-off → single compose flip (`config.yaml:9-16`) → sweep assertion → boot-time rollback by key removal; helm/baremetal/k8s stay default-off.
- **Acceptance mapping**: T-8(a-e) → 20 Given/When/Then cases → concrete new test files (`bind_strict_test.go`, `credential_content_type_test.go`, `audit_provisioner_form_e2e_test.go`, `deploy_form_only_sweep_test.go`) + which existing tests must pass unmodified, and the Deps-fake updates (`handle_{introspect,par,revoke}_test.go`).
