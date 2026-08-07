Verification complete. All claims below are measured against the tree and live `net/url` probes (go1.26.5), not inherited from the review artifacts.

## Headline finding: the expanded suite does not exist yet

`docs/architect-analysis/cmd-sso-ctl-configcmd-b4-1-issuer-allowlist-requirements.md` (mtime Aug 6 19:16, pre-adversarial-review) still contains the **16-case pre-revision suite**. No revised copy exists anywhere (`rg -l userinfo|query.?fragment|empty.?port` over `docs/architect-analysis/` non-auto files: zero hits in this deliverable; no file under `docs/` modified after the review). The run's `design_gate` stage is pending. So the verification target is absent — here is the exact delta, per required path.

## 1. Required rejection paths → pin status (measured)

| Rejection path | Rule in R2 | Acceptance case | Empirical status (probe) | Verdict |
|---|---|---|---|---|
| query/fragment | **absent** — checks 1/3 test only scheme+host | **absent** | `https://sso.example.com?x=1` → `RawQuery="x=1"`, host non-empty, exact-match membership passes → **exit 0** | **UNPINNED** (HIGH-1 open) |
| userinfo | **absent** — `u.User` never inspected | **absent** | `https://user:pass@sso.example.com` → `u.Host` == clean host (`origin-equal: true`) → R2-5 passes → **exit 0** | **UNPINNED** (HIGH-2 open) |
| empty port | **absent** — no `HasSuffix(u.Host, ":")` | **absent** | `https://sso.example.com:` parses, `Port()==""`, `Host="sso.example.com:"` → with `base_url` unset (skip) + mirrored allowlist → **exit 0** | **UNPINNED** (MED-5 open) |
| non-member after canonicalization | partial: R2-4 trim rule exists, but blanket "`//`-suffixed values remain distinct and fail" is wrong for `//`-vs-`//` (both trim to `/`-suffix — matches) | partial: case 7 pins member-after-trim (0), case 4 pins plain non-member (1); no case exercises trim-then-still-non-member (`//`-suffix, `HTTPS://SSO.EXAMPLE.COM` case variant — membership exact vs origin-lowercased asymmetry never stated) | `//`-vs-`/` trims to distinct strings (fail-closed); case-variant is non-member (fail-closed) — but unpinned, so an implementer can "normalize" it into fail-open | **UNPINNED** (LOW-7 wording + MED-4 asymmetry open) |
| base_url origin mismatch | R2-5 present | **case 8** (exit 1, names both origins); bounded by 9 (path/`/` ignored → 0), 10 (unset → skip → 0), 16 (literal port → 1) | coherent with file reality (see §3) | **PINNED** ✓ |

## 2. Check-order and exit codes

- **"Corrected single check-order" is NOT present.** The deliverable still carries the self-contradictory pair the review flagged: "Order of checks: 1 → 3 → 2 → 4 → 5, so the most specific message wins per violation set; all violations are collected (not first-wins)". The reviewer's pinned single rule (collect all; skip 4/5 when check 1 failed; skip 4's scan when check 3 found malformed entries) is not in the text.
- **Exit codes of all 16 existing cases are correct** vs the 0/1/2 convention: 0 → cases 1, 3, 7, 9, 10, 12, 13, 14 (schema/validate-schema halves); 1 → cases 2, 4, 5, 6, 8, 11, 16, plus 14's unknown-key half; case 15 asserts the pre-existing codes unchanged. No case contradicts "any violation ⇒ 1; 0 only when no violations". No case combines two violations, so none exercises (or contradicts) the ordering.
- **HIGH-3 ordering unpinned**: `runValidate` prints `config OK` at `main.go:59-60` immediately after `config.Load`, before any gate; the deliverable says only "gate runs after config.Load", not before the OK print. No acceptance case asserts stdout emptiness on failure, so no direct contradiction — but the gate-before-OK ordering must be pinned or a failing config emits `config OK` with exit 1.

## 3. Migration-table regression (the prior self-inconsistency failure mode) — CLEAN

Re-verified all 8 rows against the files (line numbers and values match; `bin/config.yaml:17,22,23` → `:28898`; `ops/deploy/k8s/config.yaml:11,13,14` → cluster URL; rows 4–6 issuer == `base_url` string; rows 7–8 have no `base_url` → coherence skip per R2-5's documented rule). No row contradicts the gate as written. **New-class check**: none of the 8 replacement values (all plain `scheme://host[:port]`) trips any of the planned expansion rules — the revision will not re-introduce a table-vs-gate contradiction. (Standing scope note: §7's title "Deploy-tree configs" still overreaches — `ops/deploy/kustomize/base/config.yaml` (sentinel issuer, feeds `bin/k8s-rendered/dev/all.yaml`), the prod overlay, and `k8s-distributed` are deploy configs absent from the table that will fail R2-2/4; not an acceptance-case contradiction, but the title should be scoped.)

## Verdict

**FAIL — the expanded acceptance suite has not been applied.** Of the five required rejection paths, only `base_url` origin mismatch is pinned (case 8, exit 1). Query/fragment, userinfo, and empty-port are unpinned and empirically exit 0 today under the gate as specified; canonicalized-non-member is partially pinned only. The check-order self-contradiction persists, and R2-4's `//` claim is overstated. What *is* sound: all 16 existing exit codes, the migration table (regression-clean, both prior corrections hold), and the plan-compatibility of the migration values with the expansion. Minimum revision delta: add R2 rules + exit-1 cases for query/fragment (`RawQuery`/`Fragment`), userinfo (`u.User != nil`), empty port (`HasSuffix(u.Host, ":")`) — on issuer, allowlist entries, and base_url per HIGH-1/HIGH-2/MED-5; add one canonicalized-non-member case; replace the check-order sentence with the reviewer's single rule; pin the origin canonical form (`ToLower(scheme)+"://"+ToLower(u.Host)`) and the membership-vs-origin case asymmetry; pin gate-before-`config OK` ordering.

No Go files touched — no mandatory gate run triggered.
