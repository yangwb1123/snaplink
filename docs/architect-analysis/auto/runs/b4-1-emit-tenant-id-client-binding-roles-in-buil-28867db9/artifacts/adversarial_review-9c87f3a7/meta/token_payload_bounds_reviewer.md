Design complete. Deliverable:

**`docs/architect-analysis/auto/runs/b4-1-emit-tenant-id-client-binding-roles-in-buil-28867db9/artifacts/design-a77de8a6/task-2-design.md`**

## Verified baseline (against committed code, not the evidence summary)

- **Confirmed**: `WithMaxTokenBytes` is enforced only in `validateTokenPreChecks` (`server_token_clientauth.go:367`) — inbound-bearer cap, nothing bounds issuance.
- **Confirmed**: all three signers assemble via the shared `buildAccessPayload` (`issue_payload.go:26-50`), and **all 10 mint sites + break-glass impersonation** funnel through `Server.issuerForClient` (`server_helpers.go:37-71`, wrap at :67) — the same funnel the `ClampingIssuer` wraps, so one envelope wrapper covers every access-token mint by construction.
- **Confirmed**: `Provider.Roles` (`memory.go:244`) is unbounded in cardinality and length; `Subject.Roles` is a new claim, so nonzero defaults are not a byte regression (AC-5 empty case untouched).
- **Budget findings**: all `options*.go` files are at 464–500 lines, `server_helpers.go` at 498, and the 60-file `interfaces/sso` ceiling is hard — the design folds the wrapper call into the existing return expression (**+0 lines**) and places `WithRolesLimits` in a file with headroom.

## Design decisions

- **Caps**: `RolesLimits{MaxRoles: 64, MaxRoleBytes: 128, MaxRolesTotalBytes: 4096}` in `shared/core` (zero dimension = unbounded; opt-out via `WithRolesLimits(0,0,0)`).
- **Policy**: deterministic fail-open truncation — `core.TrimRoles` (dedupe → **drop, never truncate**, over-long codes (collision safety: "admin"→"adm") → count cap → exact-serialized-size total cap), then `tokenpolicy.NewEnvelopeGuardedIssuer` (ClampingIssuer pattern, `spi.Logger`) applies claim caps as an idempotent backstop and, when `max_token_bytes` is set, guarantees the final signed token fits via binary-search re-issue over the roles prefix, with roles-omitted as the terminal floor — issuance never fails.
- **Signer/envelope consistency**: caps run above the signers (single enforcement point; `buildAccessPayload` stays verbatim pass-through, pinned by per-signer tests); the envelope is measured on the real signed JWS, so it's exact for every algorithm — no per-alg math. Worst-case sizing table included (~13 KiB ceiling guidance).
- **F2 interplay**: bounds are F2-agnostic — bounded at every mint whether roles are frozen or live-re-read.
- **Acceptance**: AC-4 gains per-signer roles-at-cap emission + kid unchanged + cross-signer claim-set identity; AC-5 gains empty-omission + single-`Issue` passthrough; two new checks (AC-6 envelope, AC-7 opt-out/determinism) with named test homes.
- **Contracts**: one config knob (`security.roles_limits`, pointer field so absent ≠ all-zero) → `config-reference.md` row; no new `Err*`, endpoints, audit event types, metrics, or `interfaces/sso` files.

No Go files were touched, so no gates were required for this analysis-only change.
