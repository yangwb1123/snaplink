All verification complete. Here is the report.

## Verdict: AC-1..AC-6 are concretely and reliably testable as mapped — with 3 factual corrections and 3 construction pins required (all verified live)

I verified every mapped assertion against the tree at HEAD `807719ea`, with live wire probes (`test/` harness) and a live timing probe in `shared/security`. The two scrutinized items hold up — AC-2's re-anchoring is assertable without flake (once `nbf` is added to the exclusion set), and the 1024-char timing construction is not just anti-flake but load-bearing: measured regression ratio 150.75x vs 1.5x bound, while a 16-char secret would give only 1.24x (false-pass trap).

### A. AC-2 structural-equivalence re-anchoring: assertable, with 3 corrections

1. **C1 confirmed and the re-anchor is sound.** `jti` is `crypto/rand` (ed25519_issue.go:35-43); byte-identical success bodies were impossible. The structural re-anchor decomposes into fully deterministic assertions:
   - **Claims set**: live token from the harness client shows exactly `{iss, sub, exp, nbf, iat, client_id, jti}` — no `aud` (emitted only when `Subject.Resources` set, absent for plain client_credentials), no `scope` (omitempty), no `ext`. **Correction required: the exclusion set must be `{jti, iat, nbf, exp}` — the design lists only jti/iat/exp, but `nbf` = iat = now is equally time-derived** (issue_payload.go:21-40; verified `nbf==iat` in the probe). Key-set equality + value equality on the remaining claims is deterministic.
   - **TTL**: exactly assertable, no tolerance needed — `expires_in: 60` (int of 1-min TTL) and `exp-iat == 60` both verified byte-exact in the probe.
   - **Signature**: implementable — `Ed25519JWTIssuer.PublicKey()` (ed25519_jwt_issuer.go:454) + `ed25519.Verify`, precedent `test/introspection_jwt_test.go:122`.
   - **Headers**: `Date` is stamped by net/http per response (verified present, second granularity) — **the AC-2(b4) enumerated subset `{Cache-Control, Pragma, Content-Type}` is the correct construction; AC-4's "full header set byte-identical" must be pinned to that subset + no-`WWW-Authenticate` (+ optional name-set equality minus `Date`)**. Live-verified 400 header set is exactly `Cache-Control: no-store, Pragma: no-cache, Content-Type: application/json, Date, Content-Length` — no `X-Request-Id`/`X-Trace-Id`, because `middleware.Tracing()` (the only `core.WithTraceID` caller) has zero call sites in the SDK chain; the default harness therefore emits plain error envelopes with no `trace_id`, so cross-server error-body byte-comparison works.

2. **Factual error in AC-2(b3)**: the revoke 200 body is **not empty** — `ctx.JSON(http.StatusOK, map[string]any{})` produces `"{}\n"` (3 bytes, live-verified). Cross-mode byte-identity still holds (same code path), but the golden must be `"{}\n"` or compare across modes only.

3. **Golden literals need the trailing newline**: `ctx.JSON` uses `json.Encoder.Encode` → the 400 body is `{"error":"invalid_request"}\n` (28 bytes, live-verified), not `{"error":"invalid_request"}`. The AC-1/AC-2(b2)/AC-4 byte-exact goldens in the design would fail as written.

4. **Pin the discriminating payloads**: permissive mode 200s on `text/plain`+JSON and absent-CT+JSON (the `default:` branch decodes anything as JSON — bind.go:45-48). AC-1 rows must therefore carry **JSON payloads** under the rejected CTs; a form payload under `text/plain` 400s in both modes (no contrast). Likewise AC-2(b2)'s "permissive bind-failure 400" must be pinned to permissive + `text/plain` + form/garbage (JSON-decode failure), never permissive + JSON (which succeeds). With those pins, strict-400 vs permissive-400 and the 401 `invalid_client` (plain `errorBody`, no challenge, no random element — verified) are byte-identical by shared code path.

### B. 1024-char anti-flake construction: meaningful, empirically validated

Live probe on this machine (median of 30×1000-iter batches, pre-built wrong secrets, positions 0/512/1023):

| Implementation | 1024-char ratio (end/pos0) | Verdict vs 1.5x |
|---|---|---|
| `ConstantTimeStringEq` (current) | **0.99** | passes with ~50% margin, no flake |
| Simulated early-exit regression | **150.75x** | fails loudly |
| Early-exit, 16-char secret (counterfactual) | **1.24x** | regression would PASS — the false-pass trap 1024 chars avoids |

So the construction is load-bearing: at 1024 chars the byte loop dominates fixed overhead, making the 1.5x bound meaningful (150x separation); short secrets compress the regression under the bound. Two hardening pins for the mapping:

1. **Pre-build the three wrong secrets as constants.** Per-iteration construction (e.g., `string([]byte{...})`) adds an O(n) copy to every position and compresses the regression ratio to ~2.7x — detectable but with 56x less margin (measured).
2. **Round-robin interleave batches across positions.** The constant-time leg measures 0.99x only if all positions share the same load profile; sequential measurement invites thermal/frequency drift inflating later positions — the one plausible flake. The design's median-of-batches + warmup + no `t.Parallel()` are right; ~2KB/iter allocation churn (~180MB at 30×1000×3) hits isolated batches only, which medians absorb.

### C. Everything else checked out

- **AC-1/AC-3/AC-6 harness feasibility**: `core.NewContext(httptest.NewRecorder(), req)` is exported and satisfies `HandlerContext` for the oauthwire unit tests; `oauthwire` has exactly 6 non-test files (fan-out claim correct); the new test file is free.
- **AC-3 regression lock**: `TestToken_ClientCredentials_HappyPath` + `TestToken_BadJSON_400` (handle_token_test.go:59,87) and the introspect/revoke JSON tests (:89, :237) all POST JSON against default servers — pass unmodified with default-off.
- **Deps-interface growth**: `introspectDeps`/`parDeps`/`revokeDeps` exist at the cited lines (handle_introspect_test.go:28, handle_par_test.go:17, handle_revoke_test.go:19) and are the only compile-impacted structs.
- **`normalizeContentType` extraction** preserves the inline `ct[:i]`-then-trim semantics (bind.go:31-34) — the AC-6 `; charset=` and uppercase cases are covered; absent CT → `""` → rejected.
- **No trace flake**: the new test file must simply not wire any tracing option in its harness (verified the SDK default chain never calls `core.WithTraceID`).

**Bottom line**: the mapping is implementable and flake-free, but the design document needs the edits in A1-A4/B1-B2 before implementation: add `nbf` to the exclusion set, fix the revoke-200 "empty" claim to `"{}\n"`, add the `\n` to golden literals, pin the `Date`-exclusion and the discriminating JSON payloads, and specify pre-built secrets + round-robin interleaving in the AC-5 construction.
