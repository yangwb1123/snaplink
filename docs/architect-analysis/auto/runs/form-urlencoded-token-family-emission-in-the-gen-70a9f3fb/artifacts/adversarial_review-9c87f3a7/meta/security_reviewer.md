Review complete — artifact at `docs/architect-analysis/auto/runs/form-urlencoded-token-family-emission-in-the-gen-70a9f3fb/artifacts/credential-review-<review>/credential-review.md`. Summary:

## Verdict: design is sound on all four mandated checks, with one blocking gap

**1. Basic-strip-before-encode ordering — confirmed at every emission path.**
- TS: `request()` computes `authenticatedBody` via `withClientAuthentication` (gen_ts_runtime.go:154/:183) **before** the body branch; the proposed form branch keys on `authenticatedBody`, so the urlencoded body can only see the stripped object. Public clients keep `client_id` in the body (RFC 6749 §2.3.1-correct); confidential clients move both credentials to the Basic header.
- Python: no Basic path exists at all (`_request` is body-only; the four methods emit `body=body)` with no auth) — nothing to strip, no new exposure; same bytes as today's JSON path.
- Leak surfaces: neither runtime logs or echoes request bodies/headers into `SSOError`; the JSON branch is unreachable for the four form ops except the F4 fallback, which encodes the already-stripped body.

**2. Encoding semantics — empirically validated against the server parser.** `URLSearchParams` and `urlencode(doseq=True)` both emit `+` for spaces (Go's `ParseQuery` maps `+`→space; matches Go's own `Values.Encode()`), repeated keys as `k=a&k=b` (matches `formIntoStruct`/`formStringSlice` on all four `[]string` fields), UTF-8 both sides. Arbitrary secrets round-trip unmangled. `doseq=True` is confirmed load-bearing (without it: `%5B%27a%27...`).

**3. No-store/no-cache — unaffected.** All five sites verified set headers before binding (server_token.go:22, handle_par.go:55, handle_introspect.go:112, handle_revoke.go:68/:182); the module touches only the generator + committed clients.

## Findings

- **F-A (BLOCKING)** — Design claim A2 is **false**: `PARRequest` has `authorization_details` (array of objects) and `claims` (object). As sketched, TS emits `[object Object]`, Python emits reprs — and the server's `setFormField` has **no `json.RawMessage` case** (reproduced), so the fields bind `null` and the PAR **silently issues without RAR/claims** — a silent wrong-grant regression vs today's working JSON delivery. Fix: special-case both as single JSON-string elements (RFC 9396 §7.1.1, already the documented openapi contract at :15034-15037 — currently unimplemented server-side, i.e. drift), add a `json.RawMessage` case to `setFormField` + a form-PAR RAR test to the B4-4 server steps.
- **F-B (minor)** — F3's skip covers TS only; Python `urlencode` renders `None` as literal `"None"` (verified). Fails closed (no leak) but silently changes `null` semantics; mirror the TS skip or document.
- Cosmetic: E10 line numbers off by one; `sdk-surface check` blind spot confirmed.
