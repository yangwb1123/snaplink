Revised design folded and verified. All reviewer findings are now integrated into `docs/architect-analysis/cmd-gensdk-tokenfamily-form-emission-design.md` — I re-verified every claim against the tree before writing (the reviewer's openapi anchor `:15034-15037` was itself off; the "single JSON-string element" contract is at `:15049-15051`).

**What changed in the revision:**

1. **F-A (blocking) fixed** — verified `parRequestForm` (handle_par.go:100/:105) binds `json.RawMessage` fields, `setFormField` (bind.go:111-137) has no such case → form PAR silently drops RAR/claims. The design now special-cases objects/object-arrays as single JSON-string elements in both form branches (RFC 9396 §7.1.1, shape-driven generic rules in §3.3/§3.4), adds the `json.RawMessage` case to `setFormField` (§6 step 8a, additive), and a form-PAR RAR/claims test that fails today (§6 step 8b, T-9(g)). Sequencing re-derived: the server fix is now a prerequisite of releasing the regenerated clients, closing the silent-drop window.

2. **F-B resolved by mirroring** — Python form branch filters `None` scalars (`if v is None: continue`), matching the TS skip and the query path's existing filter (gen_py.go:97-99); `[None]` array items documented as out-of-contract divergence.

3. **client.test.mjs** — §3.7: JSON.parse deepEqual (:53) replaced with `URLSearchParams` + Content-Type assertion; new F1 pin (exact body `grant_type=client_credentials`, no `client_id`/`client_secret` substrings), F3 pin (no `"undefined"`), and an F-A pin (single JSON-string elements on `postPAR`). CI-blindness caveat documented.

4. **T-9(a) strengthened** — new `TestTSRuntimeFormEncoding`/`TestPyRuntimeFormEncoding` pin the encode input (`Object.entries(authenticatedBody)` — catches `opts.body` bugs), the skip predicate, `doseq=True`, the JSON-string lines, and whole-output counts (`form: true`/`form=True` exactly four).

5. **Citations corrected** — `extractOne` :116-138 (not :171-190), `pyEmitMethod` :151-174 (not :163-178), `tsUsesClientAuth` :99-106 (not :99-109); A2 now names `audience` plus the two object-shaped PAR fields.

6. **Migration + acceptance re-derived** — steps 1-7 (module) + 8a/8b (server prerequisite) + 9-12 (enforcement); T-9(a)-(g) with exact commands, pass criteria, anchors, and a full F1-F10/F-A/F-B → failing-test matrix where each pin provably fails on the buggy implementation (verified per row in §7).

No `.go` edits were made (docs-only change), so no mandatory build gates apply; the pre-existing gate failures (ed25519_jwt_issuer.go 539 lines, docs fanout) are reported separately in the doc as inherited, per AGENTS.md §5.
