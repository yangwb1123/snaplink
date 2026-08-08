Baseline established — and it's important: the gates are **already red on pre-existing drift** (`ed25519_jwt_issuer.go` 539 lines, root subdir count 24 > 21), unrelated to this change's edit set. The review verdict below separates the delta from the baseline.

---

## Feasibility review: verdict — **landable as designed, no split required**, with two prescriptions

### 1. Budget verification (all claims held)

| Gate | Measured | After change | Verdict |
|---|---|---|---|
| `sso_protocol.go` ≤ 500 | 500 exactly (`oauth21Strict bool` at :184) | Combined `oauth21Strict, strictCredentialContentType bool` on the same line → **500, net +0** | ✓ Legal; gate fails only on `> 500` (`n > maxFileLines`, maintainability_budget_test.go:98) and counts `\n` bytes — the combined-field trick is valid Go and line-neutral. **Prescription: this file may receive zero other edits.** |
| `interfaces/sso` fan-out | 60/60 (frozen ceiling 60, directory_fanout_test.go:24) | All 6 edits land in existing files; new files are `_test.go` (excluded by `collectDirFanout`) | ✓ At ceiling, no growth |
| `protocols/oauth` fan-out | 12/12 (frozen ceiling 12, :25) | `BindParamsFormOnly` lands in **`oauthwire/bind.go`** (nested package, own count 6/10) — direct count untouched | ✓ Correct placement; an alias line in aliases.go:97 is not a file |
| Per-file growth | options.go 490→498/499, server_jar.go 422→~438, accessors.go 494→495, server_token.go 495→~496, config_metrics_security.go 227→~235, build_app_oidc.go 482→~490, aliases.go 125→126, bind.go 158→~185 | All ≤ 500 | ✓ **Tightest margin is options.go (490 + 8–9 = 498–499): the `WithStrictCredentialContentType` block must stay ≤ 9 lines (4-line doc + blank + 3-line func).** No fallback file exists — interfaces/sso is at 60/60, so a doc-comment trim is the only lever if it overflows. |
| No new exemptions | — | `layerExemptions`, `fileSizeExemptions` (empty), `dirFileCountExemptions` all untouched | ✓ |
| Layer/depth | — | No new packages, no new dirs (`oauthwire` is depth 3) | ✓ |

### 2. `normalizeContentType` extraction is behavior-identical — verified against bind.go:29-37

Current inline sequence: `IndexByte(';')` strip → `TrimSpace(pre-;)` → `ToLower(TrimSpace(whole))`. The extracted function must preserve exactly that order; the design's sketch does. `BindParams`' `default:` branch (JSON for `application/json`, text/plain, absent CT) stays untouched, and `errors`/`strings` imports already exist. AC-6's accept/reject matrix (form CT with `; charset=`, case variants, trailing `;`; rejection of quoted CT, comma lists, multipart) is *implied* by this normalization — **the task design doesn't carry the reference design's AC-6 unit pin** (oauthwire has no `bind_test.go` today; adding one is a test file, fan-out-free). Recommend adding it, since it's the only test that locks the shared-helper extraction against drift.

### 3. `handle_token_test.go` migration — verified safe, `TestToken_BadJSON_400` is mode-proof

- All 8 `postToken` call sites (lines 74–241) use **string-only map values** — `url.Values`/`http.PostForm` is a drop-in; response parsing (`json.Unmarshal`) unchanged.
- **Presence-flag semantics survive the form migration.** `TokenRequest.UnmarshalJSON` (token_request.go:64-79) sets `ClientSecretPresent`/`ClientAssertionPresent` only on the JSON path, but the form path's compensation is already production-shipped at the authn site: `bodySecret: ... || r.PostForm.Has("client_secret")` (server_token_clientauth.go:99), and `PostForm` is populated by `ParseForm()` in both binders before `authenticateTokenClient` runs (server_token.go:35). Every leg's outcome (500/401/401/200/401/501/501/400/…) is byte-equivalent under form. This is not new behavior — it's the path every real form client already uses.
- `TestToken_BadJSON_400` (lines 85-96) posts explicit `application/json` + `{not json` **outside** `postToken`, asserts **status-only 400**: strict mode rejects at the CT gate (before any decode), permissive at JSON decode — 400 in both. Mode-proof confirmed (A4 held).
- `TestToken_MissingDeps_500` survives: `requireDeps` (server_token.go:24) precedes bind (:30) — and its helper usage migrates for uniformity as designed.

### 4. Golden permissive-comparison — the logic exists in the reference design; the task design must make it an *explicit assertion*

Reference AC-2(b2) (verified in 0a8df02f): cross-mode 400 golden uses **permissive + `text/plain` + non-JSON body** — deliberately *not* JSON, because permissive + JSON **succeeds** (default branch) and would produce no 400, making the comparison vacuous. The task design's failure-mode table repeats this correctly. **Prescription for `credential_strict_test.go`** — write it so the permissive leg cannot silently pass:

1. Assert `permCode == 400` and `string(permBody) == "{\"error\":\"invalid_request\"}\n"` — the literal 28-byte golden (verified: `ctx.JSON` → `json.NewEncoder.Encode`, router.go:141-146; `errorBody` → `ErrorBodyWithTrace` with empty trace → no `trace_id`), **byte-compared, never decode/re-encode**.
2. Assert `strictCode == 400` and the same golden, then `bytes.Equal(strictBody, permBody)` + header subset `{Cache-Control, Pragma, Content-Type}` (exclude per-response `Date`) + no `WWW-Authenticate`.
3. Keep the discriminating contrast legs (strict + `text/plain` + **JSON-shaped** → 400; strict + absent CT + JSON-shaped → 400) — these prove the contrast the form-payload legs can't (form under a rejected CT 400s in both modes).
4. Comment the non-JSON-payload choice at the permissive leg: "permissive + JSON succeeds → no 400 → comparison would be vacuous" — this is the anti-copy-paste guard that keeps the logic asserted, not assumed.
5. Relocated permissive pin (default server + `application/json` client_credentials → 200) must live in the same file so JSON acceptance coverage isn't lost.

### 5. Prescriptions (the delta on top of the design)

1. **`sso_protocol.go` gets exactly one edit** (the combined field at :184) — nothing else.
2. **options.go block ≤ 9 lines** (498/499); doc-comment trim is the only fallback (60/60 file ceiling forbids a new options file).
3. **Add the oauthwire `bind_test.go` AC-6 matrix** — the task design drops the reference design's only test locking the `normalizeContentType` extraction against drift (case, charset, comma-list, quoted-CT behavior).
4. **Permissive-contrast leg asserts status + golden explicitly** (item 4), not just cross-response equality.

### 6. Baseline caveat — report separately

`go test -run 'TestMaintainability_|TestArchitecture_' .` currently **fails on pre-existing drift**: `infrastructure/defaultimpl/ed25519_jwt_issuer.go` (539 lines) and root subdir count 24 > 21. Neither file nor directory is in this change's edit set; the design's §4/§8 correctly classify this as pre-existing and out of scope. `make ci` will therefore show red at handoff regardless — the acceptance bar for this change is *no new violations* and a before/after diff of the gate output.

**Bottom line:** the combined-field trick is sound, `BindParamsFormOnly` in `oauthwire` correctly sidesteps the 12/12 ceiling, the form migration is semantics-neutral (presence flags already compensated via `PostForm.Has`), `TestToken_BadJSON_400` is mode-proof, and the golden comparison is anchored on a 400 the permissive leg demonstrably produces — provided the four prescriptions above are folded in. No split or extraction step is required.
