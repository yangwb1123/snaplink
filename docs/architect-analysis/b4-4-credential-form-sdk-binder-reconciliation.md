# Reconciliation: B4-4 credential-form SDK emission (cmd/gensdk) × strict form-only binder (sibling) — binding decisions, amended scope, merge order

- Campaign: `snaplink-b4-trust-path` (`docs/campaigns/campaign-snaplink-b4.yaml`, gate table `docs/campaigns/implementation-gate.md`)
- Status: **binding**. The two workstream designs are amended to conform (§7); no code was changed by this document.
- Parties:
  - **Gensdk workstream** — `docs/architect-analysis/cmd-gensdk-b4-4-credential-form-design.md` (+ requirements), run `emit-form-urlencoded-bodies-on-the-credential-en-85cbe797` (design passed; adversarial review complete; design_gate not yet recorded)
  - **Sibling workstream** — `docs/architect-analysis/cmd-sso-ctl-entitiescmd-b4-4-credential-form-only-{requirements,design,decisions}.md`, run `b4-4-enforce-application-x-www-form-urlencoded-o-c399c070` (**design gate: FAIL**, 2026-08-06)
- Merge order (binding, §6): sibling design-gate PASS → sibling implementation merge → gensdk implementation merge.

## 1. Campaign-file note (authority correction)

`docs/campaigns/tasks-compose-2026-017.yaml` — the file cited as the "strict-binder sibling" — is the **COMPOSE-2026-017 vault.file.delete** task (permission-catalog registration, output `docs/proposals/compose-2026-017-snaplink.md`). It contains no B4-4 content and no ordering constraint. The B4-4 strict-binder workstream's artifacts are the `cmd-sso-ctl-entitiescmd-b4-4-credential-form-only-*` docs and run `c399c070`, driven by the `snaplink-b4-trust-path` campaign, whose config (`campaign-snaplink-b4.yaml`) also expresses **no ordering constraint** between the binder direction and the gensdk emission direction. This reconciliation is the authority that closes that gap (§6). Prior reviewer citations of `tasks-compose-2026-017.yaml` as the sibling campaign were inaccurate but immaterial: the absence of an ordering constraint was real.

## 2. Drift verification (re-measured against HEAD, 2026-08)

| # | Drift | Measured reality | Severity |
|---|---|---|---|
| A | Sibling's 4-op `tsUsesClientAuth` SDK scope vs gensdk's 7-op `ContentType` scope, both editing `gen_ts_runtime.go:158`/`gen_py.go:103` and committing the same artifacts | `tsUsesClientAuth` = {postToken, postIntrospect, postRevoke, postPAR} only (gen_ts.go:99-106, verified). Sibling requirements R5.3 (case 15), design §3.3 SDK bullet, §3.4 F6, §3.5 step 4, §3.6 case 15 all scope SDK emission to those 4 ops and commit `client.ts`/`client.py`. Gensdk design does all 7 in-surface dual ops via `op.ContentType` (spec correction 4). Both name `gen_ts_runtime.go:158` and `gen_py.go:103` and both commit `docs/sdks/typescript/client.ts` + `docs/sdks/python/client.py` | HIGH (same-file collision; 4-op scope breaks postDeviceCode/postDeviceVerify/postMFAComplete → 400) |
| B | Sibling step 4's naive `URLSearchParams`/`urlencode` serializer text | `urllib.parse.urlencode` emits `True`/`False` for bools → binder `SetBool(raw[0]=="true" \|\| raw[0]=="1")` (bind.go:116-117) **silently coerces to false** → silent denial of `approve`/`trust_device`; `urlencode` raises on dict values (`claims`); TS `URLSearchParams.set` stringifies objects to `"[object Object]"` → `json.Valid` fails → 400 post-F1. The sibling's own four-op set includes postPAR (claims/authorization_details) and postIntrospect/postRevoke/postToken arrays (`resource`/`audience`/`tokens` need `doseq=True` repeated keys) | HIGH (ships the exact failure modes the gensdk design corrects) |
| C | `adminCompromiseCredential` (client.ts:2126 / client.py:1659) and `adminReportCryptoKeyCompromise` (client.ts:2136 / client.py:1667) — generated JSON-only SDK ops targeting two of the sibling's ten strict sites | Both ops in `ops/build/sdk-surface.json` (verified, admin.control-plane group). Request bodies declared `application/json` only (openapi verified). Sibling strict sites server_admin_handlers.go:293 + options_admin.go:414. Neither design covers them: gensdk's 7-op set is schema-driven (no form variant to select); sibling's 4-op set excludes them; sibling openapi step edits "seven paths" (not these two). Post-both-land they send JSON → guaranteed 400 with no contract-defined fallback | HIGH (completeness gap in the 7-op claim) |
| D | Guard predicate must match presence-based `PostForm.Has` semantics | Sibling decisions doc §3.2 pins `r.PostForm.Has("params")` — **key presence, any value**. Gensdk design §2.4 guard `body.params && Object.keys(body.params).length > 0` (TS) / truthy (Python) lets `params: {}` through → `params=%7B%7D` emitted → silent drop today, guaranteed `400 mfa_invalid` after the sibling lands | MINOR but real bug |
| E | Sibling's 7-vs-8 dual-op count; CIBA `/backchannel-authentication` | openapi scan (verified): exactly **8** dual-content operations — the 7 plus `postBackchannelAuthentication`. Sibling design says "seven paths" in §1 row 24, §3.3, §3.5 step 5; requirements R5.4/§9 repeat it; the negative matrix (§3.6 case 7) covers "the four main endpoints" only. CIBA is already a strict site (handle_ciba.go:87) and all CIBA tests already send form — only the contract edit and negative rows are incomplete. CIBA is not in sdk-surface (verified) → no gensdk impact | MINOR (sibling-internal contract incompleteness) |

Additional verified facts the reconciliation relies on: `/token/revoke-all` has no requestBody and is bearer-only (outside both scopes, unchanged); the RFC mandate anchoring B4-4 (6749 §3.2, 7009, 7662, 8628, 9126, 9396) covers OAuth protocol endpoints — the two admin compromise paths are not RFC-mandated; `TestEmit` does not exist in `cmd/gensdk/emit_test.go` (the sibling gate's `-run TestEmit` line passes vacuously); maintainability gates `TestArchitecture_DirectoryDepth`/`DirectorySubdirFanout` are RED at HEAD (pre-existing, unrelated to both workstreams).

## 3. Binding decisions

### D1 (Drift A) — SDK emission is the gensdk workstream's exclusive deliverable; the sibling drops its SDK step

The sibling workstream removes its SDK emission scope: requirements **R5.3** (case 15), design **§3.3 SDK-compatibility bullet**, **§3.4 F6** row, **§3.5 step 4**, **§3.6 case 15**, and the **§4 gate line** `go test ./cmd/gensdk/... -run TestEmit -v` (which is vacuous — `TestEmit` does not exist; the sibling's own gate FAIL defect 1). `cmd/gensdk/*` and `docs/sdks/*` (generator, runtimes, `client.ts`, `client.py`, `dist/`, `client.test.mjs`, both READMEs) become **do-not-modify** for the sibling change. SDK form emission — all seven in-surface credential ops, driven by `op.ContentType` (not `tsUsesClientAuth`) — is delivered by the gensdk workstream with its own named tests (`TestContentTypeSelection`, `TestGenerateTS_FormBranch`, `TestGeneratePy_FormBranch`).

Rationale: two workstreams editing the same runtime lines and committing the same artifacts with different scopes is an unresolvable merge collision; the 4-op scope demonstrably breaks postDeviceCode/postDeviceVerify/postMFAComplete (a sibling gate FAIL item); the gensdk design's schema-driven mechanism is the reviewed, complete answer. The sibling keeps only the server-side assertions (JSON → 400 at the eight strict sites, §5 D1 amendments), which is what its mandate (T-8(b)(c)(e)) actually requires.

### D2 (Drift B) — Serializer mechanics are single-sourced in the gensdk design; the sibling documents server-side contract only

The sibling's step-4 serializer text (naive `URLSearchParams`/`urllib.parse.urlencode`) is withdrawn with the step. The binding value rules are the gensdk design §2.2/§2.3 (`formSerialize`/`_form_encode`): bools → lowercase `"true"`/`"false"`; `string[]` → repeated keys; non-string arrays/objects → single JSON-string key; `undefined`/`None` skipped; `FormBlockedFields` keys never emitted (D4). The sibling's openapi/contract step documents only the server-side wire contract and cross-references those rules (wording must not restate mechanics): `/par` `claims`/`authorization_details` = single JSON-string key (RFC 9396 §3, sibling decisions F1); `/auth/mfa` `params` key → `400 mfa_invalid` (decisions F3); bools bind as `"true"`/`"1"` only.

### D3 (Drift C) — The two admin:write compromise endpoints are excluded from the strict form surface (non-RFC-mandated); the 7-op claim is updated, not extended

**Decision: exclusion.** `/api/v1/admin/credentials/{type}/compromise` and `/api/v1/admin/crypto/keys/{id}/compromise` (sites server_admin_handlers.go:293 and options_admin.go:414) are **not** switched to the strict binder; they keep dual-mode `bindOAuthParams` exactly as today. The strict surface is the **eight RFC-mandated OAuth credential endpoints**: `/token`, `/token/introspect`, `/token/revoke`, `/par`, `/device/code`, `/device/verify`, `/auth/mfa`, `/backchannel-authentication`.

Rationale:
1. **RFC mandate**: the B4-4 Content-Type hardening derives from RFC 6749 §3.2 / 7009 / 7662 / 8628 / 9126 / 9396 — OAuth protocol endpoints. The two admin paths are bearer-admin control-plane APIs whose declared contract is JSON-only (openapi); no RFC defines their wire format.
2. **Oracle safety is unaffected**: their bind errors already collapse to the site's canonical 400; dual-mode creates no distinguisher. The strict binder's purpose at those sites was wire-shape hardening, not oracle safety.
3. **Compatibility**: the generated SDK ops stay JSON byte-identical; out-of-tree admin clients (console) unaffected; no openapi edit for the two paths; the sweep shrinks.
4. **Gate hygiene**: the sibling gate FAIL's F2 sub-issue for these two ops disappears; `bindOAuthParams` keeps real callers (the admin pair), which also resolves the gate's dead-code justification defect.

Consequences (amended into both designs): sibling requirements T-8(b) case 4 and R1 rows for the two admin paths become an explicit **non-goal** (pinned by a do-not-switch code-review grep); sibling design's "ten sites" becomes **eight** everywhere; gensdk design's completeness claim becomes: *"the 7-op surface is the complete SDK form surface for the credential family; the two generated admin compromise ops stay JSON-only by decision (D3) — they are excluded from the strict surface, not omitted by accident."* Gensdk AC2(a) additionally asserts `ContentType` stays empty for the two admin ops.

### D4 (Drift D) — The C1 guard is presence-based; the serializers never emit blocked keys

- Guard (gensdk design §2.4, amended): TS `if (body.params !== undefined && body.params !== null) { throw new SSOError(...) }`; Python `if body.get("params") is not None: raise SSOError(...)`. This fires for `params: {}` — matching the sibling's `PostForm.Has("params")` presence semantics (any value).
- `null`/`None` are treated as absent (guard passes, key not emitted) — byte-equivalent to the JSON wire, where `"params": null` decodes to a nil map and behaves as absent.
- Defense in depth: `formSerialize`/`_form_encode` **skip `FormBlockedFields` keys entirely** (before any value rule), so a blocked key can never reach the wire even if guard emission were missed for a future map field.
- Golden set gains: `{"params": {}}` → client-side throw, no wire attempt; `{"params": None}` → key dropped; TS `formSerialize({"approve": true})` → `approve=true`.

### D5 (Drift E) — The dual-content count is 8; CIBA joins the contract edit and negative matrix

Sibling design/requirements: "seven paths" → **eight** (add `/backchannel-authentication`) in §1 row 24, §3.3 OpenAPI bullet, §3.5 step 5, requirements R5.4 and §9; the unexpected-CT negative matrix (§3.6 case 7) extends from "the four main endpoints" to **all eight strict sites**; a CIBA JSON-rejection row is added to `test/credential_content_type_test.go` (the sibling gate FAIL defect 2). Gensdk AC2(a) keeps pinning `postBackchannelAuthentication` not-in-surface (verified: absent from sdk-surface.json) — no gensdk change.

### D6 (Merge order and artifact ownership) — binder first, mechanically enforced

1. **Order rule (binding)**: the gensdk implementation must not merge ahead of the sibling workstream's design gate passing (currently FAIL — §5 lists the required amendments) and the sibling implementation merge. Within the campaign batch: sibling change-set (binder + eight-site switch + sweep + contracts) merges first; the gensdk change-set (emission + artifacts + E2E) merges second. The intermediate state (JSON-emitting SDK against the strict binder) is red by construction and never released — same posture as the sibling's own "one change-set, intermediate states are red" rule.
2. **Artifact ownership**: `cmd/gensdk/*` + `docs/sdks/*` → gensdk only; `protocols/oauth/oauthwire/bind*.go`, the eight handler bind sites, `test/credential_content_type_test.go` → sibling only; `test/credential_sdk_form_test.go` → gensdk (new file, no collision).
3. **Mechanical backstop (code-level)**: the gensdk change carries `TestSdkForm_PARClaimsThreaded` in `test/credential_sdk_form_test.go` — a claims-positive form-PAR E2E that is **deliberately not skipped** and stays **red until the sibling's F1 decoder (bind.go `json.RawMessage` form branch) lands**. CI-green-before-merge therefore mechanically blocks the gensdk merge pre-sibling (binder_conformance G4). The JSON→400 rejection assertions are the sibling's own T-8(b) tests; the gensdk AC3 control arm asserts them only post-sibling (C7 preserved — never `invalid_request` on `/auth/mfa`).
4. **Rollback ordering**: if both changes have landed, revert sibling-first (or both). Reverting only the gensdk commit after the strict binder lands returns the SDKs to JSON emission → every credential SDK call 400s. Also: `dist/` cannot be rebuilt in a clean checkout (`tsc` is not vendored; step 4 of the gensdk migration must use `bunx tsc`), so rollback must come from git, not a rebuild.
5. **Campaign record**: a row is added to `docs/campaigns/implementation-gate.md` (B4-4 SDK emission depends on the strict binder's design-gate PASS; shared-artifact ownership; binder-first merge), and both designs carry a pointer to this document.

## 4. Amended scope tables (post-reconciliation)

### Server-side strict surface (sibling)

| Site | Wire post-change |
|---|---|
| `/token`, `/token/introspect`, `/token/revoke`, `/par`, `/device/code`, `/device/verify`, `/auth/mfa`, `/backchannel-authentication` | form-only; JSON/missing/unexpected CT → canonical 400 (`mfa_invalid` on `/auth/mfa`) |
| `/api/v1/admin/credentials/{type}/compromise`, `/api/v1/admin/crypto/keys/{id}/compromise` | **unchanged dual-mode** (JSON accepted; non-goal D3) |
| `/token/revoke-all` | bearer-only, body-less, unchanged (both designs) |

### SDK emission surface (gensdk)

| Op | Wire post-change |
|---|---|
| postToken, postIntrospect, postRevoke, postPAR, postDeviceCode, postDeviceVerify, postMFAComplete | form (7-op set, `op.ContentType`) |
| adminCompromiseCredential, adminReportCryptoKeyCompromise | JSON (excluded by D3; not form-capable) |
| postRevokeAll | body-less, byte-identical (AC1/F7) |
| postLogin, postRegister, all other ops | JSON byte-identical |
| postBackchannelAuthentication | not in surface (AC2(a) pin) |

## 5. Gate verification of the merged plan

### 5.1 Sibling workstream (design gate currently FAIL — 9 items)

| Gate FAIL item | Status after reconciliation |
|---|---|
| F1 (PAR RawMessage) / F3 (MFA params) | Already resolved by the decisions doc — unchanged |
| F2 — SDK emission scoped to 4 ops, breaking 5 more ops | **Resolved by D1 + D3**: SDK emission removed from the sibling change entirely (gensdk owns all 7); the two admin ops excluded from the strict surface (stay JSON, keep working) |
| F4 — `handleDeviceVerify` lacks the no-store stamp | **Carried as a sibling implementation requirement** (now explicit in §3.5 step 3 + a §3.6 regression-pin row): `tokenNoStoreHeaders` in server_device.go:228-267; AGENTS.md requires no-store on credential endpoints |
| F5 — sweep inventory misses `introspection_jwt_test.go:70` and `frontend_contract_test.go:106` | **Carried into §3.5 step 3** (both are JSON posts to credential paths) |
| Defect 1 — `TestEmit` does not exist; the `-run TestEmit` gate passes vacuously | **Resolved by D1**: the gate line is withdrawn; SDK emission tests are the gensdk workstream's named tests |
| Defect 2 — CIBA eighth OpenAPI path / negative rows missing | **Resolved by D5** |
| Defect 3 — pre-existing maintainability RED unreported | **Carried**: §3.5 step 6 reports `TestArchitecture_DirectoryDepth`/`DirectorySubdirFanout` RED at HEAD (auto/runs depth 8, fanout 89, root 24>21) as pre-existing, separate from this change |
| Revoke-all acceptance row missing | **Added** (§3.6 REGRESSION-PIN row: bearer-only, body-less, byte-identical) |
| `bindOAuthParams` dead-code justification false; count drift | **Resolved by D3**: the admin pair keeps `bindOAuthParams` (real callers); strict switch = 8 sites (4 protocol-layer + 4 interfaces/sso); boundary = 8 strict + 36 dual-mode non-credential |

Remaining sibling gates (unchanged, all must pass before merge): `go build ./... && go vet ./...`; unit surface (`bind_strict_test.go`, RawMessage + map-silent-skip pins); 16+2-file sweep + inverted `TestFormEncoded_JSONRejected`; `test/credential_content_type_test.go` (T-8 cases 1-8 over all eight sites); RAR-over-PAR migration (F1) + PAR-claims positive; MFA `params` rejection row; `make ci`; T-9 401 regression.

### 5.2 Gensdk workstream (adversarial review complete; design_gate pending)

| Reviewer finding | Status after reconciliation |
|---|---|
| Security review (oracle-safety, no-store, PKCE, C1-C7) | **PASS** — no changes required; C1 corrected by D4, C4/C5/C6/C7 carried |
| Binder conformance G1 (presence-based guard) | **Resolved by D4** |
| G2 (no emission-level C5 pin for Python) | **Folded in**: AC2(c) gains a string assertion that generated `post_token` keeps `client_id`/`client_secret` in the body (Python has no Basic path) and adds `form=True`; TS Basic-strip-before-serialize ordering already pinned in AC2(b) |
| G3 (golden harness; `bun` out of `make ci`) | **Folded in**: AC2(c) goldens execute via node/python3 (no `t.Skip` — skip is a silent pass) or relocate to `client.test.mjs` + a Python test; `bun test`/`bun run build` remain out-of-band of `make ci` and are documented as such; migration step 4 uses `bunx tsc` |
| G4 (F1 window has no failing test) | **Resolved by D6** (red-until-F1 `TestSdkForm_PARClaimsThreaded` arm, never skipped) |
| G5 (no regeneration-drift gate in `make ci`) | **Folded in — resolved by deferral (as amended in the design)**: no duplicate drift test in `emit_test.go`; the T-9 `sdk-drift check` (`checks/sdk_drift.py`, direction `add-a-regeneration-drift-and-deploy-tree-sweep`) is the single implementation — its regeneration leg byte-compares regenerated `client.ts`/`client.py` against committed, exactly the stale-copy scenario. Until T-9 lands, byte-identity is enforced by AC1's regeneration-diff step + the single-commit rule; `dist/` staleness is covered by the commit rule (T-9 excludes `dist/` by design) |
| G6 (golden-list gaps) | **Folded in**: F10 empty-element case (`{"resource": [""]}` → `resource=`), TS bool golden, exact form header string `"application/x-www-form-urlencoded"` (no charset, F9), `request()` form branch mirrors the JSON branch's `body !== undefined` guard |
| Sibling-interlock drifts A-E | **Resolved by D1-D5**; caveat 1 (acceptability if F1 never lands) → D6 ordering; caveat 2 (§6.5 dangling reference) → fixed to §6 |

Remaining gensdk gates: `go build ./... && go vet ./...`; `TestContentTypeSelection` (exact 7-op set + admin pair empty + CIBA not in surface); TS/Python emission tests; `test/credential_sdk_form_test.go` (form `/token` → 200, repeated-`resource` `/par` → 201, claims-positive arm, JSON control → 400 post-sibling); `client.test.mjs:53` form assertions; `python cli.py sdk-surface check`; `make ci`; `go test ./... -race`.

### 5.3 Shared gates

- `go build ./... && go vet ./...`: clean at HEAD for both change surfaces.
- Maintainability/architecture: RED at HEAD pre-existing (directory depth/fanout) — both workstreams report separately per AGENTS.md; neither change adds packages or breaches budgets (`bind_strict.go` ≤ 500 lines; `cmd/gensdk` 7 non-test files, no new file beyond `emit_test.go` extension).
- `make ci`: full gate for both; note it runs **no** regeneration-diff and **no** bun step today (G3/G5) — covered by the in-`emit_test.go` drift test until the T-9 drift gate direction lands.
- Wire/oracle invariants (AGENTS.md §3): unchanged by construction — no new `Err*`; `params` rejection reuses the `mfa_invalid` envelope; the admin pair exclusion introduces no new distinguisher; no-store/bearer-challenge ordering untouched (plus the F4 stamp).

## 6. Merge-order and ownership record (binding)

```text
1. Sibling design-gate PASS (c399c070 rerun, verdict line) — precondition for gensdk implement/merge.
2. Sibling implementation merge (binder + 8-site switch + sweep incl. CIBA + contracts + F4/F5 items).
3. Gensdk implementation merge (emission + artifacts + E2E incl. the red-until-F1 claims arm).
   Mechanically enforced: TestSdkForm_PARClaimsThreaded fails pre-sibling → gensdk CI cannot go green.
4. Rollback: sibling-first (or both); never revert gensdk alone after the binder has landed.
5. Artifacts: cmd/gensdk/* + docs/sdks/* owned by gensdk; server binder + credential_content_type_test.go
   owned by sibling; test/credential_sdk_form_test.go owned by gensdk (new file).
6. Recorded in docs/campaigns/implementation-gate.md (new B4-4 row) and both designs (§7 amendments).
```

## 7. Amendments applied to artifacts

| Artifact | Amendments (all applied in this change) |
|---|---|
| `cmd-sso-ctl-entitiescmd-b4-4-credential-form-only-design.md` | ten→eight sites (§1 row 19, §3.1, §3.2); §1 row 24 + §3.3 + step 5: seven→eight paths (CIBA); §2 reconciliation note; §3.3 SDK bullet → D1 deferral; §3.4 F6 → deferral, new F13 (admin do-not-switch); §3.5 step 2 (8-site switch list), step 3 (CIBA rows, F4 no-store, F5 sweep files), step 4 → deferral, step 6 (pre-existing RED report; `TestEmit` line withdrawn); §3.6 case 4 → non-goal, case 7 → all eight sites, case 15 → DEFERRED, revoke-all REGRESSION-PIN row added; §4 gate line replaced |
| `cmd-sso-ctl-entitiescmd-b4-4-credential-form-only-requirements.md` | R1 table: admin rows removed, "ten sites" → eight; R3 admin pair clarification; T-8(b) case 4 → non-goal; T-8(c) case 5 → eight endpoints; R5.3 → D1 deferral; R5.4 → eight paths + admin non-touch; §7 files: cmd/gensdk lines moved to do-not-modify; §8 compatibility list drops the admin pair; §9 openapi line → eight paths |
| `cmd-sso-ctl-entitiescmd-b4-4-credential-form-only-decisions.md` | §5: "ten-site switch" → eight-site (admin pair stays dual-mode per D3); F3 rationale unchanged |
| `cmd-gensdk-b4-4-credential-form-design.md` | §1.1 C1/C4: presence semantics, §6 refs fixed; §2.2/§2.3: FormBlockedFields keys never emitted; §2.4: presence-based guard (non-null); §2.5/§3: admin-pair exclusion; §4 F1/F2 rows updated; §5 steps 2/6/8: golden harness (exec, no skip), red-until-F1 arm, merge-order enforcement; §6: D6 ordering bullet; §7 AC1/AC2/AC3: admin pair empty-ContentType assertion, Python C5 pin, exact form header, expanded goldens, claims arm. (Concurrent amendments: step 4 `bunx tsc`, sibling-first rollback, T-9 `sdk-drift` deferral — G3/G5) |
| `docs/campaigns/implementation-gate.md` | New B4-4 SDK/binder ordering + ownership row (§6) |

## 8. Non-goals and open items

- Non-goal: form variants for the two admin compromise endpoints (rejected with D3; re-open only with a product/RFC mandate).
- Non-goal: CIBA SDK emission (not in sdk-surface) — the sibling contract edit covers the server side only.
- Open: wiring `bun test`/`bun run build` into `make ci` (G3) — documented out-of-band until wired; the regeneration-drift gate is in flight as the separate direction `add-a-regeneration-drift-and-deploy-tree-sweep` (T-9 `sdk-drift check`, design-gated, not yet in tree) — until it lands, AC1's regeneration-diff step + the single-commit rule are the backstop.
- Open: sibling-side F4 (no-store stamp) and F5 (two sweep files) are implementation requirements carried by this reconciliation, not re-decided.
