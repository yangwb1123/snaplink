## Verification verdict

I independently re-checked all 15 evidence rows against the tree. **Every claim confirmed**; both corrections (C1, C2) verified. Key confirmations:

- **E1/E2** — TS `requestOptions` (:35-41) has no `form`; `gen_ts_runtime.go:154-160` computes `authenticatedBody` (Basic-strip first) then JSON-encodes. Python `_request` (:87-91, :102-104) is JSON-only.
- **E3** — `tsUsesClientAuth` four-op predicate at `gen_ts.go:99-109`, case list at :101.
- **E6** — `BindParams` (bind.go:28-53): form path is body-only via `r.PostForm`; JSON/missing-CT default; `BindFormParams` = 0 matches repo-wide.
- **E7 (C1)** — only `postToken` (openapi.yaml:1102) is form-only; introspect/revoke/PAR declare both media types.
- **E9** — approved spec REQ-2.1-2.6 present (:82-114), unimplemented (`Operation` has no `FormBody`).
- **E12/E14** — `TestFormEncoded_JSONStillWorks` (test/oauth_bind_test.go:272) asserts JSON→200; no-store headers set before binding at all four sites (server_token.go:22, handle_introspect.go:112, handle_revoke.go:68, handle_par.go:55).
- **E13/E15** — `withClientAuthentication` at :183 (C2 correct); sdk-surface.json = 13 groups / 316 ops including the device ops.

Four additional observations surfaced (A1-A4, none contradicting): a second no-store site at handle_revoke.go:182; all four request schemas are flat (strings + string arrays only — `resource`/`audience`/`tokens`/`authorization_details`); Python's four methods emit `body=body)` with no `auth=True`; `URLSearchParams` is already a runtime dependency.

## Design delivered

`docs/architect-analysis/cmd-gensdk-tokenfamily-form-emission-design.md` contains:

- **API changes** — `Operation.FormBody` populated in `extractOne` by a shared `usesFormBody` predicate (operations.go); `form: true` part in `tsEmitRequestOpts`; `, form=True` in `pyEmitMethod`; TS runtime `requestOptions.form` + a form branch encoding the **Basic-stripped** `authenticatedBody` via `URLSearchParams`; Python `_request(form: bool = False)` with `urlencode(body, doseq=True)` (doseq is load-bearing for repeated keys). Exact insertion points and code sketches for each.
- **Compatibility constraints** — no SDK-consumer API change; safe before and after the B4-4 server flip (server accepts both today); must land *before* enforcement; JSON branch byte-for-byte for the other 312 ops; `sdk-surface check` blind spot noted.
- **10 failure modes** with mitigations — the strip-before-encode ordering (F1, credential leak), missing `doseq=True` (F2), `"undefined"` literals (F3), fixture drift (F5), diff sprawl (F6), scope creep (F7), sequencing breakage (F8).
- **Migration steps** — 7-step ordered plan plus the dependency-gated B4-4 server steps (T-9(d)/(e) inversion, REQ-6 openapi text).
- **Testable acceptance mapping** — T-9(a)-(e) with exact commands and pass criteria, plus a REQ-to-test map.
