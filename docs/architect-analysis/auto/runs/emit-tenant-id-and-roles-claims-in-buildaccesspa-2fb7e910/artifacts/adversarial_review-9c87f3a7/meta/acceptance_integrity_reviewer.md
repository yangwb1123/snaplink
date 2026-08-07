Verification complete. Report written to `docs/architect-analysis/auto/runs/emit-tenant-id-and-roles-claims-in-buildaccesspa-2fb7e910/artifacts/design-a77de8a6/task-1-ac-verification.md`. Findings against HEAD `718345d6`:

## Line-budget arithmetic — all confirmed

- `server_login.go` **469** ✓, `server_finish_login.go` **500** ✓, `server_login_client.go` **500** ✓, `server_helpers.go` **498** ✓ — re-measured. The design genuinely needs no change to the two exactly-500 files: the chain `finishLogin:47 ensureJITMembership → finishLoginDispatch → finishLoginDirectMint (:167) → mintAndRecordDirectLogin (server_login_client.go:388) → mintAccessToken (server_login.go:99)` means the lookup lands in `mintAccessToken` and the JIT ordering claim is structurally true at HEAD.
- Realistic delta in `server_login.go` is ~+17 (helper ~16 + `Roles:` wiring +1), not +23 — the 492 estimate has only **8 lines of headroom** under the 500 gate. Tight; re-run `wc -l` per step.
- Net-zero seam refactor holds: server_oauth.go:205-211 (7 lines) → ~3-line call site, same log string, same metric, same value; `ErrNoMembership` stays silent (no log/metric) — that branch must survive extraction.
- `consts_wire.go` is itself at exactly 500 — the design correctly adds no consts (`KeyTenantID` :169, `KeyRoles` :277, drift self-flag confirmed).

## AC-1..AC-7 vs T-2 — two gaps

- (a)(b) per-issuer `tenant_id`/`roles`: covered by AC-1..3 + AC-6 end-to-end binding chain (harness exists: `TestRcov2L_RichLogin`, `rootcov_options_test.go:92-93` already wires `WithJITMembership`+`WithTenantUserStore`).
- (c)(d): **AC-4/AC-5 must be made explicitly per-issuer** — the three header structs are distinct (`ed25519Header`, `ecdsaHeader` :436, `rsaHeader` :433), so a single-issuer `strings.Count(header,"kid")==1` or byte-identity test doesn't falsify the other two issuers. The summary is ambiguous; amend before implementation.
- AC-7 (tag-vs-const guard) is falsifiable as stated.

## Narrative-only failure modes (no test hook)

1. **Store outage fail-open with logging — no hook at all.** `MemoryTenantUserStore.Get` can only return `ErrNoMembership` or nil; it cannot simulate an outage. An error-injecting `core.TenantUserStore` stub is required.
2. **No membership / no store / tenant-less client / JIT ordering** — all feasible and structurally sound, but only implicit in AC-6 (not stated). JIT ordering is provable via `WithJITMembership` + empty store → token carries `roles:["member"]`.
3. **Pairwise-keying claim (`result.UserID`, never `issuedSub`)** — no hook; needs a pairwise-client AC-6 variant or a regression to pseudonym-keyed lookup passes all ACs.
4. **Token-endpoint grants leave roles empty** — design decision, narrative-only, no lock (low severity, beyond T-2).

## New hazard found (not in the design)

`s.metrics.ObserveTokenPolicyRoleResolutionError()` (server_oauth.go:211) is unguarded, and `Server.metrics` is nil without `WithMetrics`. The seam is only reachable under token-policy wiring today; the extracted helper in the mint path has no such guard — **the outage test would panic before asserting unless the helper nil-guards `s.metrics` or the test wires `WithMetrics`**. Log capture is feasible via `WithLogger(spi.Logger)`.

Verdict: proceed with implementation after (a) making AC-4/AC-5 per-issuer explicit, (b) adding the error-injecting store stub + pairwise-keying variants, (c) resolving the metrics nil-guard.
