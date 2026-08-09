Design written to `docs/architect-analysis/cmd-gensdk-b4-4-credential-form-design.md`. Summary:

## Verification verdict

All 13 evidence claims re-verified against HEAD — **12 confirmed, 1 imprecise** (cmd/gensdk has 7 non-test `.go` files, not at a 10-file ceiling; the "extend `emit_test.go`" constraint is still adopted). The requirements spec's own five corrections (postRevokeAll body-less; 400 not 415; T-8 label mapping; 7-op surface; spec-driven mechanism) all check out against the sibling strict-binder design and campaign gate.

## New corrections surfaced by this review (the value-add)

- **C1 — `MFACompleteRequest.params` must not be JSON-string-encoded.** The requirements spec's design lists it among JSON-string values, but the sibling decisions doc F3 makes any form `params` key a guaranteed `400 mfa_invalid` (and a silent drop today). The generated `postMFAComplete` must fail loud client-side instead.
- **C2 — the bool failure mode is silent denial, not a 400.** `bind.go:115` coerces non-`"true"`/`"1"` to false silently; Python `urlencode` emitting `True` would silently *deny* `postDeviceVerify.approve` — worse than the evidence's "rejects" claim.
- **C4 — real merge-order window:** the shared decoder has no `json.RawMessage` form branch yet, so form PAR `claims`/`authorization_details` are wire-correct but inert until the sibling's F1 lands (same-campaign interlock).
- **C5/C6/C7:** Python has no client-auth path (body creds stay in the form body — valid); zero responses declare form (preference flip provably inert for responses); `/auth/mfa` rejects JSON with `mfa_invalid`, not `invalid_request`.

## Design shape

- **API:** generator-internal `Operation.ContentType` + `FormBlockedFields` (schema-driven, not the `tsUsesClientAuth` hard-coded list); `contentSchema` preference flip; hand-written runtime form serializers (TS `URLSearchParams`, Python `_form_encode`) with per-value rules: scalars/bools coerced, `string[]` → repeated keys, objects/array-of-objects → single JSON-string key, `undefined`/`None` skipped.
- **Compatibility:** generated SDK signatures unchanged; `postRevokeAll` and JSON-only ops byte-identical; server untouched; single-commit generator+artifacts rollback.
- **Failure modes:** 10 enumerated (F1–F10), each with detection and mitigation, including the pre-sibling PAR-claims drop window, the bool silent-denial, and the `params` guard.
- **Migration:** 8 steps from generator change through `make ci`, with the sibling merge interlock spelled out.
- **Acceptance:** AC1–AC4 mapped to concrete testable gates — `TestContentTypeSelection`, TS/Python emission tests, `test/credential_sdk_form_test.go` (form `/token` → 200, repeated-`resource` `/par` → 201, JSON control → 400), and `client.test.mjs:53` form assertions.
