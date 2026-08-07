Verification complete. Full report: `docs/architect-analysis/auto/runs/replace-the-host-derived-resolveissuer-fallback--6a26a2b3/artifacts/verify-issuer-allowlist-contract/task-1-verify.md`

## Verdict: PASS with 1 material gap + 3 minor drifts

The implementation has **not landed** (no Go file references `IssuerAllowlist`; `configcmd` has no `issuer_gate.go`), so this is design/contract verification with live boot checks where the existing path permits.

**1. Sibling spec consistency — verified, 1 material gap.** Key (`server.issuer_allowlist` ↔ `ServerConfig.IssuerAllowlist []string`) and normalization (single trailing-slash trim, `//` fail-closed, literal ports, `base_url` origin coherence with unset-skip) are identical to the sibling spec. All 11 replacement-table rows match current files exactly, including the corrected `bin/config.yaml` (28898, not 8080) and k8s cluster-URL rows. **Gap: the 12th config — `ops/deploy/helm/sso-server/values.yaml:162` (`issuer: sso-server`, `base_url: http://sso-server:8080`, rendered verbatim by `templates/configmap.yaml`) — is missing from the sibling table.** It fails the gate today and would fail boot unless migrated to `issuer: http://sso-server:8080` + allowlist. (Task's "section 2 table" is actually §7 — citation drift.)

**2. Deploy-tree migration + boot gate — verified.** 12 configs = 11 tracked config.yaml + helm values.yaml; renders (`bin/k8s-rendered/*`) are gitignored regenerated outputs already carrying the allowlist. 3/12 migrated in the worktree (kustomize base, overlays/prod, k8s-distributed). Live `--validate-only`: exit 0 for all three + control; the transient "unknown keys" warning comes from `decodeStrictWithFallback`'s lenient re-decode and self-heals when the field lands. Simulated boot gate: all 12 pass once values are members — every issuer equals its allowlist entry, no trailing-slash/port ambiguity, all `base_url` origins coherent.

**3. Docs — 1 gap.** `docs/config-reference.md` is **not** updated (no `issuer_allowlist` row; `server.issuer` row at :48 to amend; `base_url` undocumented); the design artifact's file table omits the docs obligation the requirements artifact lists. `docs/error-codes.md` correctly **unchanged** — the contract adds no `Err*` (boot rejection = config.Load error; SDK misuse = `NewServer` panic). The sibling R1 comment "key is not read at boot" goes stale and must be amended in the same change.

**4. Rollback — verified.** Absent key ⇒ nil slice ⇒ no new validation path, Host fallback preserved ⇒ byte-identical legacy. Deliberate asymmetry: after remove-key rollback, `sso-ctl config validate` fails closed (R2-2) — operator pre-check, not boot. Remove-key doesn't revert replaced issuer values (harmless, boot-valid).

**5. Wire/OpenAPI/Err\* invariance — verified.** No routes/headers/params; discovery JSON shape unchanged (values pin only under the gate); `docs/openapi.yaml` unmodified; no new sentinel errors; 60-file ceiling intact (test files don't count); placement counts all check out (`sso.go` 499 → exactly 500, flagged by design).

Minor drifts: "12" only holds if helm is counted (which the table omits); R-3's "reference + 12" double-counts `cmd/sso-server/config.yaml`; acceptance total 21→24 corrected and arithmetically sound. No Go files were edited, so no mandatory gates triggered.
