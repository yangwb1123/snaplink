All checks complete. Here is the verification report.

## 1. Contract-doc check (§5.6): "no new SPI/Err/endpoint/config knob" — **confirmed, with two nuances**

| Doc | Verdict | Evidence |
|---|---|---|
| `docs/error-codes.md` | ✅ Claim holds | No new `Err*` in the change. The doc's only event-type documentation is inline per feature section (`admin_user_lifecycle_changed` :705, `admin_credential_compromised` :628); sibling admin types (`admin_user_created/updated/deleted`) are **not** cataloged there, so `admin_user_imported` needs no entry by precedent. The audit bulk-export/SOC2 SDK-error sections (:416-434) are unaffected — no new sentinels; chain failures surface as existing descriptive `platform/audit` errors |
| `docs/config-reference.md` | ✅ Claim holds | No config knob added. The CLI table (:449-450) documents only `config schema`/`validate-schema`; the admin-API-client env section (:950+) doesn't cover `import`. Bonus: `audit.webhook.subscriptions[].event_types` (:417) wildcard `admin_*` already covers the new type — no doc change needed |
| `docs/feature-matrix.md` | ✅ Claim holds | Capability registry + RFC matrix; no event-type catalog. The change adds no capability/surface (import command isn't a matrix row; SCIM provisioning is a separate server surface) |
| `docs/openapi.yaml` | ✅ Claim holds | `admin_user_created` appears only in two `example:` arrays (:16807, :16824) — examples, not enums. `event_types` query params are open string allowlists; no enum anywhere. No endpoint added |

**Nuance 1:** the WebhookSubscription description (:16807) calls event types "the same vocabulary every audit consumer sees" — examples only, so no update required, but the new type is now part of that vocabulary. **Nuance 2:** the one genuinely new public surface is the `admin_user_imported` value itself, which needs no doc because no doc enumerates the event vocabulary.

## 2. Observability catalog entry — **not required; two hygiene notes**

`docs/observability.md` maintains a **selective** event catalog (Audit section: `feature_gates_disabled`, `auth_hook_*`, `client_secret_expiring`, `tenant_quota_store_failure`) — entries exist only for events with metric/fixed-log/PII-constraint coupling. `admin_user_imported` adds no metric and no fixed log message; its siblings are uncataloged. **No entry is mandated.** Two notes:

- The doc's Hard Constraint "Every Event carries W3C TraceID/SpanID" conflicts with the design's row shape ("no request/trace IDs"). I verified the precedent: `feature_gates_disabled` (interfaces/sso/sso.go:325-338) is recorded with empty trace fields — so the design's "matches system/bootstrap events" is accurate, but it should state this explicitly against the doc's constraint (one line in the design).
- If the D-3 correction lands (raw-vs-hashed `target_user`, below), that PII decision is exactly what the Audit section catalogs and would then warrant an entry.

## 3. Design doc: reviewer corrections — **none of the five are recorded** ❌

Checked `docs/architect-analysis/cmd-sso-ctl-importcmd-audit-chain-design.md` at HEAD `8598a26b`:

| # | Correction required | Design status |
|---|---|---|
| 1 | **Stale '+2' SIEM guard/comment** (event_classification_reviewer) | §2 C1 reproduces the guard as `len(allKnownEventTypes) != len(KnownEventTypes)+2` "`t.Logf` soft check" **as fact** — no record of the 44-type live bypass (129 vs 173), the inverted "+2" premise, or the fix (correct guard+comment in the same change; Files-touched lists only the `allKnownEventTypes` entry, no guard fix) |
| 2 | **Chain-fork hazard + DSN `busy_timeout` pragma** (database_transaction_reviewer) | F7 and §3.4 still say "single-writer caveat applies (same as `Prune`)". No mention of tip-read-once + plain-INSERT fork (two events, same PrevHash), the quiesce-or-fork operational constraint, or the `_pragma=busy_timeout` dependency (modernc ignores `_busy_timeout`) |
| 3 | **Crash-consistency FM row** (database_transaction_reviewer) | FM table has F3 (Record *errors*) only. No row for the process-death window (pair committed → no chain row, no stderr, silent), eventual attestation, duplicate chain rows on re-run, no checkpoint/resume marker |
| 4 | **D-3 'never email' PII wording** (security_engineer) | `newAuditEvent` comment (design :173) still asserts "Never … email, or any attribute material" — false as wired: `deriveID` falls back to `provider:email`, and CEF/OCSF export `meta.target_user` verbatim on replay. No raw-vs-hashed decision recorded |
| 5 | **Chainless→chained one-way transition** (security_engineer) | F4/§3.3 cover only genesis + whole-table verify break. Missing: `BuildExportBundle` self-verifies at build time → `audit-export` exits 1 with **no bundle** (§3.6 step 4's loop cannot run — fails at export, not verify); `--anchor-hash ""` rejected → segment verify needs a `--since` window; every chainless server write re-breaks the table → one-way transition (enable `cfg.Audit.HashChain` first) must be stated |

Also unrecorded (same reviewers, lower in your list but material): F1's "newer schema → fail fast" is false as wired (`migrate.Run` silently no-ops ahead — needs explicit `CheckSchema` gates, and postgres would be stricter than the server's own boot); F6 cross-host postgres clock skew (clamp ts to `max(now, durable head+1ns)`); F3's exit-0 hole (recording failures byte-identical to full attestation — count handler invocations, exit non-zero); AC1-postgres/AC2 whole-table assertions will false-fail under the shared-DSN convention (must be segment-anchored, own-row-scoped).

## Verdict

- **Contract hygiene claim (§5.6): PASS** — zero doc changes strictly required; no new SPI/Err/endpoint/config knob, and no doc enumerates the event vocabulary. The two nuances (TraceID constraint statement; D-3-dependent observability entry) are cheap to close.
- **Design-readiness gate: FAIL** — all five listed corrections, plus the four additional deltas above, are absent. The design must be amended to record them (the decision matrix in §3/§5 and FM/F4/F7/F1 rows, plus the AC1-postgres/AC2 assertion rework) before implementation per AGENTS.md §5.7's "design records corrections before implementation" intent.
