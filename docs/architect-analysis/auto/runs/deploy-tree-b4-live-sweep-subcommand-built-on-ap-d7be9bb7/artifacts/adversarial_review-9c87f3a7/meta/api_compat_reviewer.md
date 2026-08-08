Verification complete. Report written to `docs/architect-analysis/auto/runs/deploy-tree-b4-live-sweep-subcommand-built-on-ap-d7be9bb7/artifacts/adversarial_review-9c87f3a7/meta/wire_compat_reviewer.md` (doc-only; no `.go` edits, no gates triggered).

## Verdict: APPROVE on all four axes

**1. 16 subcommands' redirect behavior byte-for-byte unchanged — ✅**
Census: only 6 of the 16 map entries use apiclient, via exactly 10 non-test call sites, **all zero-option `apiclient.New()`** (clientscmd ×2, entitiescmd ×3, sessionscmd ×2, tokenscmd ×2, tui ×1). The other 10 entries never import the package (auditverify hand-rolls `&http.Client{Timeout}` at main.go:414). `WithNoRedirect()` as an `Option` (`func(*Client)`, apiclient.go:67) applied in the opts loop can only affect explicitly opted-in clients; every existing caller keeps `&http.Client{Timeout: 30s}` with `CheckRedirect == nil` — Go's default policy, structurally identical to today. No `apiclient.Client{` literals bypass `New`; zero `CheckRedirect` anywhere in the package or its consumers.

**2. env-wins ordering preserved — ✅**
`New` (:47-62): opts loop :55-57 → `SSO_ADMIN_TOKEN` fallback :58-59 → `EnvAddr` override :60-61. The option mutates only the `http` field — it cannot touch `token`/`baseURL`, and in the pure-option variant `New`'s body is untouched entirely. The design's `--addr` contract ("env wins, per apiclient.New") holds.

**3. Narrowed 'untouched' claim accurate — ✅**
`Do` (:81-111), `Get`, `Post`, `ReadBody` (:134-142) need zero changes: the policy lives on the `http.Client`, inherited transparently, and `ReadBody`'s close/drain is exactly the contract `ErrUseLastResponse` 3xx bodies need. Amendment = one exported Option (~4 lines) + at most one wiring line.

**4. A3's 302-login-page pass case preserved — ✅ (empirically on go1.26.5)**
`ErrUseLastResponse` returns the 3xx with **nil error** (`status=302, err=nil`), so truthiness rows see the true first-hop status: `302 != 404` → pass by construction — for `authorization_endpoint` and `end_session_endpoint` (a real 302: `oidc.HandleEndSession` → `ctx.Redirect(StatusFound)` at handle_end_session.go:130). Content rows (discovery/jwks) fail under both semantics identically. Bonus: the pass becomes target-independent (a 302→404-target was a latent A3 false-negative under follow semantics). Threat model re-confirmed: default following forwards 307 POST bodies verbatim cross-host (`body={"client_secret":"TOPSECRET"}`) — the pin is load-bearing.

**Two required test additions** (currently missing from the test-mapping doc): `TestNew_DefaultFollowsRedirects` + `TestWithNoRedirect_StopsAt3xx` (the byte-compat regression boundary, REQ-6 set) and `TestSweep_302Passes` (3xx-pass on truthiness rows + no request to the `Location` target, REQ-2 set).
