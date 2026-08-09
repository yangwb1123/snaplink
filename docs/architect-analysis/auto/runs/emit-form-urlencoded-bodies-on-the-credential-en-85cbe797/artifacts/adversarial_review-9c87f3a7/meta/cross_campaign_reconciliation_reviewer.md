The reconciliation is complete. All five drifts are resolved with binding decisions, both workstreams' artifacts amended to conform, gates verified, and merge ordering mechanically enforced.

## Deliverables

**Primary: `docs/architect-analysis/b4-4-credential-form-sdk-binder-reconciliation.md`** — binding decisions D1–D6 with re-measured evidence, amended scope tables, gate verification, and the enforcement record.

**Amendments applied** (each drift claim was re-verified against HEAD first — e.g. `tsUsesClientAuth` = 4 ops at gen_ts.go:99-106, admin ops at client.ts:2126/2136 + client.py:1659/1667 in sdk-surface with JSON-only bodies, 8 dual-content ops including CIBA, `TestEmit` nonexistent, sibling gate FAIL verdict):

| Drift | Decision | Where applied |
|---|---|---|
| **A** | Sibling drops its SDK step/R5.3/case-15/F6/§4 `TestEmit` gate line; `cmd/gensdk/*` + `docs/sdks/*` become sibling do-not-modify; 7-op `op.ContentType` emission is gensdk-exclusive | sibling design + requirements |
| **B** | Naive `URLSearchParams`/`urlencode` step-4 text withdrawn; serializer value rules single-sourced in gensdk §2.2/§2.3; sibling documents server contract only | sibling design step 4, requirements R5.3 |
| **C** | **Exclusion** (not form variants): the two admin:write compromise endpoints stay dual-mode — non-RFC-mandated (6749 §3.2/7009/7662/8628/9126/9396 govern OAuth protocol endpoints), SDK ops stay JSON byte-identical. Strict surface = 8 sites; both completeness claims updated | sibling design/reqs/decisions (ten→eight), gensdk §1/§2.5/AC2(a) |
| **D** | Guard becomes presence-based (`params !== undefined && !== null` / `is not None`) matching `PostForm.Has`; serializers never emit `FormBlockedFields` keys; goldens gain `params: {}` / `params: None` | gensdk §1.1/§2.2/§2.3/§2.4/§4 F2/AC2(c) |
| **E** | Count is 8: `/backchannel-authentication` joins the strict switch, openapi edit, and the negative matrix (case 7 → all eight sites) | sibling design/reqs (R5.4, §9) |

**Gate verification & ordering**: sibling gate FAIL items resolved here (F2→D1+D3, TestEmit→D1, CIBA→D5, dead-code→D3) vs carried (F4 no-store stamp, F5 two sweep files, revoke-all pin, pre-existing maintainability RED); gensdk review gaps G1–G6 folded (G5 aligned to the in-flight T-9 `sdk-drift` direction). Merge order is enforced three ways: a new **G5b row in `docs/campaigns/implementation-gate.md`**, the red-until-F1 `TestSdkForm_PARClaimsThreaded` E2E arm (never skipped — CI cannot go green pre-sibling), and sibling-first rollback/revert ordering in both designs.

One note: a concurrent session was also amending the gensdk design (its `bunx tsc`, sibling-first rollback, and T-9-deferral edits) — my edits coexist without conflict, and the reconciliation's G5/G3 rows reflect that combined state.
