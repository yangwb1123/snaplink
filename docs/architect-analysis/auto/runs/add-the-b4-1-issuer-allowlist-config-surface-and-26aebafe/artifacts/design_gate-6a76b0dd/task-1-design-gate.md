## Independent verification result

**Target**: `docs/architect-analysis/cmd-sso-ctl-configcmd-b4-1-issuer-allowlist-requirements.md` (mtime 2026-08-07 03:34:07 UTC — modified *after* the security review at 03:29:01 UTC, but only by the deploy-migration table expansion).

### Resolved with evidence

| Finding | Status | Evidence |
|---|---|---|
| Ops: 3 deploy configs missing from §7 table | ✅ **Resolved** | Table now has 11 rows (kustomize base, prod overlay, k8s-distributed added; rows relabeled "coherence N/A"). Config files verified edited: `ops/deploy/kustomize/base/config.yaml` (issuer→cluster URL, +allowlist, base_url at :14), `overlays/prod/config.yaml` (+allowlist), `k8s-distributed/config.yaml` (+allowlist) — git diff confirms 3 files/6 insertions. |

### Blocking findings NOT resolved and NOT explicitly rejected

The doc contains **zero** references to the adversarial findings (no hits for `fail-open|HIGH-|MED-|revised|rejected`), and the R2 rules/acceptance suite are unchanged from the pre-review version:

| Finding | Current document state | Verdict |
|---|---|---|
| **HIGH-1** query/fragment rejection | Zero `RawQuery`/`Fragment` hits; R2-1/R2-3/R2-5 test only scheme+host | **Open** |
| **HIGH-2** userinfo rejection | Zero `u.User != nil` hits (only "userinfo" = OIDC endpoint mention) | **Open** |
| **MED-5** empty-port suffix | No `HasSuffix(u.Host, ":")`; case 16 covers only `:443`-vs-none | **Open** |
| **MED-4** canonical origin form | No `ToLower(scheme)+"://"+ToLower(u.Host)` pinning; R2-5 prose verbatim | **Open** |
| **MED-4** membership-vs-origin case asymmetry | Never stated | **Open** |
| Check-order contradiction | Line 92 verbatim: "most specific message wins … all violations are collected (not first-wins)" | **Open** |
| R2-5 `//` blanket claim | Verbatim "`//`-suffixed values remain distinct and fail" (overstated: `//`-vs-`//` trims to match) | **Open** |
| **HIGH-3** gate-before-print + CI hook | §7 still says "call the gate after config.Load"; `main.go` prints `config OK` at :104 immediately after Load (:99), before any gate; acceptance 1 still pins byte-identical stdout shape; §1 still states "the new configcmd gate does not move CI"; no stderr-only-on-failure rule, no matched-entry success line | **Open** |

The acceptance suite is still the 16 pre-revision cases (no query/fragment, userinfo, empty-port, or canonicalized-non-member cases added). The only post-review change to the deliverable was the migration-table expansion made by the deploy-migration reviewer itself.

VERDICT: FAIL - the three missing deploy-config rows are fixed, but all four fail-open gaps (query/fragment, userinfo, empty-port, gate-before-print/CI) plus the unpinned canonical form, asymmetry, and contradictory check-order wording remain verbatim in the deliverable with no explicit rejection or evidence, so the design cannot proceed to implementation.
