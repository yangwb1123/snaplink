All evidence gathered. Here is the validation verdict.

# Validation report: `PostForm` wire semantics + T-8e matrix

**Overall: the design's five headline claims all hold against the working tree, the RFC, and the server's actual error contract.** I independently reproduced the red baseline (11 top-level + 9 subtests, matching the six enumerated root causes) and verified every server-side writer the pins depend on. Two minor imprecisions found, neither affecting correctness.

## 1. `values.Encode()` determinism and key sorting — ✅ CONFIRMED

- Stdlib source (`$GOROOT/src/net/url/url.go:994`): `slices.Sort(keys)` then emits `key=value&...` per key, per value — lexicographic, map-insertion-order-independent, **never fails** (no error return). Empirically verified: same content built in different insertion order encodes byte-identically; order is `client_id < client_secret < grant_type < resource < scope`.
- Empty values encode as `key=` — secret presence survives (`r.PostForm.Has("client_secret")` at server_token_clientauth.go:99), matching the JSON path's `req.ClientSecret != ""` for the real (non-empty) secrets the probes always send.
- **One imprecision (design §3)**: the claim "`scope` … (`%20` on the wire)" is wrong — `QueryEscape` encodes space as `+`, so the wire bytes are `scope=read+write`. The round-trip is unaffected (`ParseForm` decodes `+`→space; `formStringSlice` then space-splits), so the compatibility conclusion stands; only the cited wire byte should be corrected.

## 2. Form content-type and `Accept: application/json` headers — ✅ CONFIRMED

- `net/http` never auto-sets a request Content-Type (no sniffing on `NewRequest`), so the explicit `Content-Type: application/x-www-form-urlencoded` set is both required and correct; `Content-Length` is auto-derived from the `strings.Reader`.
- Bearer only when `c.token != ""` (all five sites use `probeClient`, token `""` → no header — required: a non-Basic Authorization header makes `/token` reject outright); `Accept: application/json` mirrors `Do`; `c.http` carries the `rejectRedirect` pin (apiclient.go `WithNoRedirect`/`probeClient` confirmed).
- RFC grounding is right: §3.2 (token endpoint) and §4.1.3 (auth-code request) both mandate POST + `application/x-www-form-urlencoded`; revoke/introspect legs cite RFC 7009 §2.1 / RFC 7662 §2.1 correctly. The T-8e row probes *server* enforcement, which is policy (the strict-mode campaign's contract), not RFC client behavior — the design is honest about this (§8).

## 3. 'Class not code' rule tolerating strict-mode `400 invalid_request` and `trace_id` — ✅ CONFIRMED

- Strict-mode contract verified in the owning campaign's requirements (requirements-0a8df02f R3/R5, lines 83-109): any non-form CT at `/token`, `/token/introspect`, `/token/revoke`, `/par` → byte-identical `400 {"error":"invalid_request"}`.
- `trace_id` enrichment is real per docs/error-codes.md:43-52 (via `errorBody` → `core.ErrorBodyWithTrace`, interfaces/sso/handlers.go:399-402, only when tracing middleware populated it). The envelope check (4xx + JSON object + non-empty string `error`) ignores extras by construction — `json.Unmarshal` into `struct{Error string}` tolerates `trace_id`/`error_description`.
- Bonus verification: the T-8d byte pin `{"error":"invalid_scope"}\n` is safe because both server writers use **plain** `core.ErrorBody` (token_client_credentials.go:38-41; the scoperegistry path per the server_token.go comment "never errorBody, whose trace_id would drift the byte-compat baseline"). T-9's `invalid_client` goes through `errorBody` — trace_id possible on a tracing-enabled server, but that is pre-existing and flip-neutral.

## 4. Byte-identical pins for the five token.go flips — ✅ CONFIRMED

All three endpoints bind through `BindParams` (server_token.go:30, handle_introspect.go:120, handle_revoke.go:75), which normalizes JSON/form into the same struct — so the flips change nothing server-observable beyond the wire format:

| Site (token.go) | Pin | Verdict |
|---|---|---|
| mint :72 | no byte pin; claims matrix downstream | ✅ (JWT decode untouched) |
| revoke :244 | status-200 only | ✅ |
| post-revoke introspect :259 | `{"active":false}` | ✅ (bind at handle_introspect.go:120, struct fields populated by `formIntoStruct`) |
| T-8d :297 | `{"error":"invalid_scope"}\n` (:310/:326) | ✅ plain `core.ErrorBody`, no trace_id |
| T-9 :353-357 | `{"error":"invalid_client"}\n` (:366-367), no bearer | ✅ bare client + `rejectRedirect` + 30s timeout unchanged; REQ-0.6 `%q`→`%s` at :368 confirmed against the failing subtest output |

Client-auth paths for revoke/introspect read the *bound struct* (not `r.PostForm`), so the form flip is safe there too.

## 5. T-8e cannot misclassify 3xx/5xx/non-JSON/missing-error as PASS — ✅ CONFIRMED

The pass predicate is conjunctive: status ∈ [400,499] **AND** JSON-object decode succeeds **AND** non-empty string `error`. Every fail class is structurally excluded:

- **3xx**: out of range; `rejectRedirect` observes, never follows (no credential/token forwarding).
- **5xx**: out of range → FAIL.
- **non-JSON**: HTML pages, JSON arrays, `{"error":42}` all fail `json.Unmarshal` into the struct → FAIL.
- **missing/empty error**: `{}`, `{"ok":true}`, `{"error":""}` → `Error == ""` → FAIL.
- **200** (incl. a 200 carrying a JSON error shape): out of range → FAIL, and the body is never echoed (real token) — the mint `bodyEcho` rule applies.

The one theoretical leak — a **4xx + JSON envelope from a non-enforcement gate** — is doubly neutralized: (a) `401 invalid_client` on bad creds is the documented vacuous pass; (b) any gate that 4xxes the T-8e legs on a permissive server (tenant mismatch, rate-limit 429, FAPI rejection, inactive client) 4xxes the form mint/T-8d too, so the sweep is **already red via T-8a/T-8d** — a T-8e false-PASS can never flip a green verdict. I confirmed this across every server gate in `handleToken`'s path. The 429 case (per-grant limiter at exactly-1-per-window) is the only unenumerated row in the design's failure-mode table; worth a line, not a fix. `415 + JSON envelope → pass` is deliberate class semantics matching REQ-8.4.

## Extra confirmations

- **8-case matrix** (REQ-8.4) matches the design's §2.3/§6 acceptance exactly: both-400 pass, trace_id-400 pass, 415 pass, 200-fail-no-echo, 302-fail, 500-fail, non-JSON-fail, mixed-legs-fail — plus skip → INCOMPLETE/exit 1.
- **Stub wire coupling** (V12): `handleToken`'s raw `sweep-probe-` discrimination survives the flip — verified empirically that `QueryEscape` leaves `A-Za-z0-9-` untouched. `handleIntrospect`'s JSON-only `"client_id"` substring **requires** the REQ-8 wire-agnostic fix for the post-revoke leg (the T-9 leg carries no `client_id` and routes correctly either way) — correctly identified in the design.
- **Golden** at check_test.go:32 and `TestSweep_GreenPath` :446 confirmed; extended golden order (`content_type` between mint and invalid_scope) matches the proposed `CheckRun` wiring.
- **Budgets**: 205/413/277/284 lines confirmed; 5 non-test files after the new file; `token_contenttype.go` split into `runT8e` + ≤50-line leg helper satisfies the function gate.
- **Taxonomy note** (cosmetic): the proposal marks T-8(b/c/e) exact semantics unclaimed (audit-contract-batch-snaplink.md:18); the strict-mode campaign maps T-8(e) to its constant-time test while this direction labels its wrong-CT row T-8(e) per its own requirements spec, which documents the sibling collision (finding 7). Naming drift between campaigns, documented, no wire impact.

## Bottom line

The design is implementable as written. Two non-blocking corrections before landing: (1) design §3's "`%20` on the wire" → `+`; (2) add the 429 rate-limit row to the §4 failure-mode table for completeness. Everything else — the five flips, the byte pins, the class rule, and the 8-case classification — is confirmed against RFC 6749 §3.2/4.1.3, the strict-mode campaign's R3/R5 contract, docs/error-codes.md, and the live server code paths.
