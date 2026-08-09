All verification complete. Here is the validation report.

---

# Validation: cmd/gensdk B4-4 form-emission design vs strict-binder sibling (F1 interlock)

Every claim below was re-measured against HEAD/worktree today, including a live regeneration run and a clean-checkout TS build.

## 1. F1 merge-order window — confirmed real; **doc-gated, acceptable, with two caveats**

- **Window is real (measured):** `oauthwire/bind.go` `setFormField` has no `[]byte`/RawMessage branch — `case reflect.Slice` handles only `[]string` (`bind.go:127-133`); a form PAR carrying `claims`/`authorization_details` binds successfully with values silently dropped. The gensdk runtime's JSON-string single-key emission is exactly the RFC 9396 §3 encoding F1 will accept → wire-correct but inert pre-F1. Confirmed.
- **Gating:** stated in two places — §4 F1 row (detection: "a form-PAR-with-claims E2E would show a 201 with claims absent at login") and §6 ("Order the campaign so F1 lands with or before this change"). The design deliberately keeps its own AC3 form arm green pre-sibling (no claims-positive in its E2E), so the F1 pin correctly lives in the sibling's suite (`TestPAR_AuthorizationDetailsSurvivesIntoAccessToken` migration + PAR-claims positive + malformed/repeated negatives, decisions doc §2.3). The window is **not** test-gated from this side and **not** campaign-enforced: the two directions are separate analyses/runs (`cmd-gensdk-4ffda121.json` vs `cmd-sso-ctl-entitiescmd-631f0c1d.json`); `docs/campaigns/tasks-compose-2026-017.yaml` contains no ordering constraint. All weight rests on the doc statement.
- **Caveat 1 (acceptability risk):** the sibling run's own design gate currently **FAILED** (run `b4-4-enforce-…-c399c070` DECISIONS.md, 21:02, verdict FAIL on F2/F4/F5 + defects). If F1 never lands, the "window" becomes permanent silent drop for SDK PAR callers. The gensdk change should not merge ahead of the sibling's gate passing.
- **Caveat 2 (hygiene):** C4/§4 F1 cite "§6.5" but the interlock section is §6 (no 6.5) — dangling cross-reference; fix on commit.

## 2. 8-step migration — executable in order, **one concrete gap (step 4)**

| Step | Verdict |
|---|---|
| 1 Generator change | OK (design-level; no budget risk: 7 non-test files, largest 361 lines — verified) |
| 2 `emit_test.go` | OK — file exists; `TestEmit` is a real trap: `go test ./cmd/gensdk/ -run TestEmit` currently matches nothing (sibling's own gate reviewer flagged the same); the design correctly names `TestContentTypeSelection` etc. instead |
| 3 Regenerate | **Verified live**: `go run ./cmd/gensdk --lang=all` → output byte-identical to both HEAD and worktree for `client.ts` (157,596 B) and `client.py` (133,390 B) |
| 4 `bun run build` + `bun test` | **GAP**: `bun run build` fails in a clean checkout — `tsc: command not found` (no node_modules, no devDependencies, no lockfile, no global tsc). `bunx tsc -p tsconfig.json` works on demand (verified, TS 7.0.2). Fix: write step 4 as `bunx tsc` or add typescript as devDependency + commit lockfile. `bun test` passes 9/9 (incl. the `client.test.mjs:53` confidential-token test — the AC3 TS arm's target, verified at line 53) |
| 5 Docs | OK — both READMEs committed; TS README:71-74 "the client always sends JSON" confirmed verbatim |
| 6 Contract/E2E | OK — `test/e2e_test.go` is package `ssotest` with an `httptest.Server` harness; `TestE2E_*` exists; `test/credential_sdk_form_test.go` is a create |
| 7 Gates | OK — `make ci`, `python cli.py sdk-surface check`, `go test ./test/ -run TestE2E -v` all exist |
| 8 Interlock | Doc-level only (see §1) |

## 3. Single-commit rollback — **complete on artifacts; one unstated ordering hazard**

- All rollback targets are committed: `client.ts`, `client.py`, `dist/*.{js,d.ts}` (6 files), `client.test.mjs`, both READMEs — verified via `git ls-files`. Reverting the one commit restores generator + artifacts + tests + docs together. ✓
- **Unstated hazard:** if the sibling binder has landed and you revert *only* the gensdk commit, the SDK reverts to JSON emission on the seven ops → every credential SDK call 400s against the strict binder. Rollback order must be sibling-first (or both together). The design's rollback line covers only the sibling's independence, not this direction. Also note dist/ cannot be rebuilt in a clean env (step 4 gap) — revert must come from git, not `bun run build`.

## 4. Byte-identical claims — **hold**

- Measured: regeneration is byte-identical today (above). Structurally sound post-change: `postRevokeAll` has no requestBody → no form flag → `{ auth: true }` unchanged (`client.ts:2918` verified); JSON-only ops (postLogin `client.ts:2818` verified) keep `ContentType` empty → JSON branch untouched; all 8 dual ops are `required: True` (F10 verified); zero responses declare form (C6 verified — scan returned NONE).
- Caveat: `make ci` runs **no** gensdk regeneration diff today (no gensdk step in Makefile/cli.py). AC4's stale-copy detection explicitly defers to the separate regeneration-drift direction (design-gate PASSED but not implemented) — so the byte-identical guarantee is design-argued + manually checkable, not CI-pinned yet.

## 5. Drift vs sibling F1 decoder semantics — **F1 alignment is clean; the drift is in the sibling's own SDK step and in a three-way admin-op gap**

**Aligned (verified semantics):** single JSON-string key for `claims`/`authorization_details` (F1: exactly one value + `json.Valid`; `JSON.stringify` output always valid; runtime never repeats keys for object fields); repeated keys for `string[]` (`formStringSlice` multi-value); bools → `"true"`/`"false"` (binder verbatim `bind.go:115`); `undefined`/`None` skipped ≡ JSON null/absent; empty `string[]` → no key ≡ JSON `[]`. The C1 guard is grounded: `SSOError` exists in both runtimes with matching arity (TS `client.ts:30`, Python `client.py:23`).

**Drift A — HIGH, op scope + file collision:** sibling R5.3/§3.3/§3.6-case-15/§3.4-F6 pins SDK form emission to the 4 `tsUsesClientAuth` ops with "JSON emission stays for all other operations"; gensdk does all 7 dual-content ops via `op.ContentType`. Both workstreams edit the *same* files (`gen_ts_runtime.go:158`, `gen_py.go:103`) and commit the *same* artifacts. The sibling's 4-op scope breaks its own ten-site enforcement (postDeviceCode/postDeviceVerify/postMFAComplete → 400); its own design gate FAILed on exactly this (reviewer F2). **Reconciliation:** sibling must drop its SDK step/R5.3/case-15 and defer SDK emission to the gensdk workstream.

**Drift B — HIGH, serializer mechanics:** sibling step 4 says "URLSearchParams (TS) / urllib.parse.urlencode (Python)" with no value rules. That ships the exact failure modes the gensdk design corrects: Python `urlencode` emits `True`/`False` → silent denial on `postDeviceVerify.approve` (C2); dict/list values break (urlencode raises; TS `set` → `"[object Object]"` → `json.Valid` fails → 400 post-F1). The sibling's step-4 text as written would produce a broken PAR-with-claims client *even after F1 lands*.

**Drift C — HIGH, three-way gap on the admin compromise ops:** `adminCompromiseCredential` (`client.ts:2126`, `client.py:1659`) and `adminReportCryptoKeyCompromise` (`client.ts:2136`, `client.py:1667`) **are generated**, target two of the sibling's ten strict sites, and their openapi request bodies are **`application/json` only** (verified). Neither design covers them: gensdk's seven-op set excludes them (schema-driven — no form variant to select), the sibling's four-op set excludes them, and the sibling's openapi step edits "seven paths" (not these two). Post-both-land: those two SDK methods send JSON → guaranteed 400 `invalid_request` with no contract-defined form fallback. The gensdk design's "7-op surface (spec correction 4)" claim is therefore **incomplete against the sibling's ten-site list**. Resolution options: (recommended) sibling scopes the two admin:write control-plane endpoints out of the strict surface — the RFC mandate (6749 §3.2, 7009, 7662, 8628, 9126, 9396) governs OAuth credential endpoints, not bearer-admin APIs whose declared contract is JSON-only; or gensdk adds both ops to the form set + openapi gains form variants.

**Drift D — MINOR, guard predicate mismatch:** gensdk C1 guard fires only on non-empty `params` (`Object.keys(body.params).length > 0`); sibling F3 rejects on **any** key presence (`PostForm.Has("params")`, decisions doc §3.2). `params: {}` passes the guard, formSerialize treats it as a plain object → emits `params=%7B%7D` → 400 `mfa_invalid` post-sibling (silent drop pre-sibling). The serializer should skip `FormBlockedFields` keys entirely, or the guard must match key presence.

**Drift E — MINOR, sibling-internal:** sibling openapi step says "seven paths" but there are **8** dual-content ops — `/backchannel-authentication` (CIBA) also declares JSON and stays declared while the server rejects it. Gensdk counts 8 correctly; no gensdk impact (CIBA not in surface), but the sibling's contract edit is incomplete.

## Bottom line

- F1 window: confirmed, doc-gated (two places), acceptable **if** the sibling gate passes before merge — currently it has not (FAIL), and no campaign mechanism enforces the order.
- Migration: 8 steps executable except step 4 (`bun run build` broken in clean checkout; use `bunx tsc`).
- Rollback: complete for artifacts; add the sibling-first revert ordering.
- Byte-identity: holds, verified live; CI pin deferred to the separate drift-gate direction.
- **Blocking drift before both land:** Drift A (4-vs-7 op scope + same-file collision), Drift B (naive urlencode/URLSearchParams in sibling step 4), Drift C (two admin compromise SDK ops break against the ten-site binder with JSON-only contracts) — the last one invalidates the gensdk design's "7-op surface" completeness claim. Drift D (empty-`params` leak) and the §6.5 dangling reference are one-line fixes.
