All independent verification is complete. Summary of what I confirmed against the tree:

**Blocking findings — confirmed real and NOT resolved or rejected in the design:**

1. **PAR `json.RawMessage` silent drop (G1/Gap A)** — `setFormField` (oauthwire/bind.go:112-134) has a Slice case only for `Elem.Kind()==String`; `parRequestForm.AuthorizationDetails/Claims` are `json.RawMessage` (handle_par.go:100,105) and are silently skipped. Form-only enforcement makes this the *only* path: RFC 9396 RAR/claims payloads vanish without error. The par-reviewer's ruling (a) (store-verbatim RawMessage binding + 12 tests) was never folded into the design (0 mentions of RawMessage).
2. **Migration surface is 36 sites / 15 files, not 35/14** — confirmed `test/introspection_jwt_test.go:61-75` `postIntrospectAccept` posts JSON to `/token/introspect` (3 RFC 9701 tests). Design E15/C3/M4/F3 still say 35 sites in 14 files.
3. **`rcovPostJSON` surface** — confirmed 68 `/token` + 12 `/token/introspect|revoke|par` JSON posts via the helper at `rootcov_flow_test.go:154-172`; the design's "no JSON callers outside `test/`" claim is false, and its own section-8 command `go test ./interfaces/sso/...` would fail under enforcement. Design has 0 mentions.
4. **`docs/examples/quickstart/main.go:164`** — confirmed JSON post to `/token`; uncovered by M4, and `make examples` only builds.
5. **No `TestGeneratePython*`** — confirmed 0 matches in emit_test.go; AC-2 names no Python emission test (rated blocking).
6. **Nullish encoding (G3)** — 0 design mentions; Python `urlencode(doseq=True)`/TS would emit literal `"None"`/`"undefined"`.

Non-blocking only: Gap C (hardcoded `usesFormBody` — explicitly justified, though the justification is inverted), C7 citation, and the untracked static-tree scoping sentence. Pipeline state confirms no revision loop: DECISIONS.md ends at adversarial_review (10:13); the design doc (09:56) predates the reviews; no patch stage ran; the design_gate artifact is empty (this task).

VERDICT: FAIL - six blocking findings (PAR RawMessage silent drop, the 36th/introspection_jwt_test.go site, the ~80 rcovPostJSON sites in interfaces/sso, quickstart main.go:164, the missing TestGeneratePython emission test, nullish skipping) are confirmed in code, absent from the design, and neither resolved nor explicitly rejected, so the design is not ready for implementation.
