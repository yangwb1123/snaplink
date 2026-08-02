# Gatekeeper Cross-Check — design vs. review findings

I re-verified every load-bearing claim against the current tree. The design doc (`docs/design/admin-list-keyset-pagination.md`) contains **no revision markers, amendment section, or review-response entries** — it is unchanged from the reviewed revision. Findings below are classified as **Resolved** (design addresses them), **Dismissed-with-reason** (acceptable deferral), or **Unresolved** (still blocking).

## Independent verification (all confirmed)

| Claim | Check | Result |
|---|---|---|
| `shared/core` 23 files, exempted at 23 | `ls` + `directory_fanout_test.go:63` | ✔ new file → regression failure |
| `shared/security` 10 files, **no exemption** | `ls` + exemption map | ✔ new file → cap violation |
| `interfaces/sso` 60/60; `aliases.go` = 500 lines | `ls` + `wc -l`; `fileSizeExemptions` empty | ✔ new aliases in aliases.go → size-budget failure |
| `domains/permissions` 10/10, `interfaces/snapshot` 14/14 | `ls` + exemption map (snapshot exempted, permissions not) | ✔ both block new files |
| `MemoryStore.List` + `FileStore.List` sort **CreatedAt desc** | `operations.go:95-109`, `file_store.go:87-109` | ✔ D10.5 "store order" claim is wrong |
| `tenantLess` supports only `""/id/slug/name` | `admin_tenants.go:163-171` | ✔ D5's `status` order is unsupported |
| `userLess` `created_at` has no tiebreaker | `admin_users.go:129-130` | ✔ drift vs. D5's id tiebreaker |
| `ListUserSessionsRequest` has `page_token=2/page_size=3`, handler ignores them | `users.proto:84-88`; `admin_users.go:210-228` | ✔ dead wire fields; scope says "9" but names 10, omits it |
| `rotation.enabled` registers webhook-HMAC rotator seeded from `audit.webhook.signing_secret` | `docs/config-reference.md:562` | ✔ design's proposed "stable" HKDF source is schedule-rotated |
| `oauth.*.lookup_hmac_key_file` (with previous-key window) and pairwise `salt_file` exist | `docs/config-reference.md:101,113` | ✔ D10.2's "no deployment-stable secret" premise is false |

## Findings cross-check

**Resolved or dismissed with reasons (acceptable):**
- **TotalSize `0`-when-unknown (M4/T2)** — design D7/D10.4 takes an explicit decision with rationale (proto "Approximate", memory stays exact, only `-1` durable backends affected) and flags the UI-regression risk. A reasoned design-level decision; the requirement-doc contradiction (3.1(c)) and owner sign-off remain open process items, not design blockers.
- **Pre-existing durable-stack gaps (db F2–F4, I2/I3: postgres CheckSchema unwired, session pruning, audit retention, missing indexes)** — reviews themselves classify these as follow-up-phase items; D5/D6 explicitly scope durable pushdown out. Dismissed with reason.
- **Collation parity, unused offset path, `int32` TotalSize overflow, stale `clients.proto:90` comment (I4, I5, F9)** — info-level follow-ups; acceptable.

**Unresolved — blocking (design not amended):**

1. **H1 — placement fails committed gates on commit 1** (arch F1/F2, QA Q10, BA-2). D1 still mandates new file `shared/core/pagination.go` (23/23 → regression), D2 still mandates new `shared/security/pagecursor.go` (10/10, no exemption → violation), D1/D12 still send aliases into `aliases.go` (500/500 → size-budget violation), D6 implies new files in `domains/permissions` (10/10) and `interfaces/snapshot` (14/14). The prescribed fixes (sub-package `shared/core/pagination`, codec in existing `constant_time.go`, aliases in `origin_validation.go`/`quota.go`) are **not** in the doc.
2. **H2 — MAC-key lifecycle unresolved; premise factually wrong** (sec F1, db F5, arch F8, BA-1). D2/D10.2 still propose HKDF from the audit-webhook secret — which `rotation.enabled` rotates on a schedule, killing cursors fleet-wide and diverging replicas; the "no stable secret exists" claim ignores `lookup_hmac_key_file` and pairwise `salt_file`. No decision recorded; D11 has no key-rotation test (QA Q7).
3. **M2 — ListOperations baseline mischaracterized; extension order flips key *and* direction** (db F1, arch F9, QA Q4). D10.5 still says "store order" (both stores sort created_at desc); D5/D3/D6 still specify id-asc. Extension and fallback would disagree on the same data.
4. **M3 — `0x00`-split payload framing** (arch F4, sec F3). D2 unchanged: NUL-separated fields collide with store-defined `after_bytes`; the in-tree tokenanomaly precedent explicitly rejected delimiter-joined encodings. Length-prefix fix absent.
5. **M1 — scope params unbound from token** (sec F4, BA-3). `ListPage(ctx, userID, q)` / `ListExpiringPage(ctx, cutoff, q)` unchanged; D9's table has no cross-scope-reuse row — silent incomplete windows on privileged sweeps.
6. **M5 — ListUserSessions omitted; "9 vs 10"** (arch F3, QA Q5). No scope decision; dead page fields remain the only admin List gap; count wrong in design (and `requirements.md`).
7. **L1–L4 — required hardening/corrections absent**: token length cap (16 MB recv ceiling inherited), package-global key-install race, tenant `status` order row (factual error in D5), `userLess` tiebreaker drift (D5 adds id, fallback comparator has none).
8. **QA Q1/Q2 — false test premises in D11**: claims filter/order error-code coverage ("fallback regression") and "REST pagination + TotalSize assertions unchanged" — both verified to have **zero** existing tests (grep: no `Filter`/`OrderBy`/`invalid page_token` hits in any grpcadmin or e2e test). The design's central drift detector (D6 extraction) is unguarded; Q1/Q2 pinning tests must land first.

## Verdict

The semantics are sound and every reviewer agrees, but **none** of the eight blocking findings were resolved or dismissed in the design — it still contains the gate-failing placements (H1), the wrong key source (H2), the mischaracterized ListOperations baseline and reversed extension order (M2), the NUL-framing collision (M3), the unbound scope params (M1), the unresolved ListUserSessions gap (M5), the required hardening items (L1–L4), and a verification plan resting on two false coverage premises (Q1/Q2). All are doc-level corrections plus four owner decisions (key lifecycle, TotalSize sign-off, ListOperations order, ListUserSessions scope), but the design must be revised before implementation starts.

VERDICT: FAIL - H1 gate-breaking placements (shared/core + shared/security new files, aliases.go overflow) unfixed; H2 MAC-key source is rotation-scheduled and premise false, no decision; M2 ListOperations order flips to id-asc against created_at-desc baseline; M3 0x00 framing collision; M1 scope params unbound from token; M5 ListUserSessions omitted with dead wire fields and wrong "9 vs 10" count; L1-L4 length cap, key-install race, tenant status order, userLess tiebreaker all absent; QA Q1/Q2 test plan rests on nonexistent filter/order and e2e coverage
