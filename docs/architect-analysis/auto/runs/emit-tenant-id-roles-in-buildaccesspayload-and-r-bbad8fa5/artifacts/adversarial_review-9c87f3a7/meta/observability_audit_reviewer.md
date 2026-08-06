Done. The amendment is written and self-verified. Summary:

## Deliverable

`docs/architect-analysis/auto/runs/emit-tenant-id-roles-in-buildaccesspayload-and-r-bbad8fa5/artifacts/design-689aebe1/task-1-design-observability-amendment.md` (435 lines) — a design amendment consumed by the design gate, addressing the security_reviewer's two open asks and the AGENTS.md "fail open with audit/logging" contract. No `.go` files touched (doc-only, per this run's pattern); pre-existing worktree changes preserved.

## Pins (each verified against the tree)

**Roles-issuance outage (fail-open)** — the contract surface:
- Audit: new `token_roles_lookup_failure` event via a nil-safe `audit.RecordTokenRolesLookupFailure` helper in `recorder_events.go` (354→~366), fixed `Reason: lookup_failed`, W3C trace IDs via `EventFromRequest`, error string log-only (P3)
- Metric: `sso_token_roles_lookup_failures_total`, zero labels, folded into `metrics_token.go` (platform/metrics is at its 10-file ceiling), construction-time enable as a one-line gated call in `populateHandlerDepsStores` (sso.go has zero headroom at 499→500)
- Log: fixed `roles claim lookup failed; omitting roles claim` with bounded keys
- Contract pin P1: missing `roles` is deny-eligible, never allow; P2: `ErrUserNotFound`/nil-provider = normal absence, zero observability — so a rising counter IS the open window

**Allowlist boot refusal (fail-loud)** — deliberately NO audit event and NO metric (process never serves; auditor may be unwired; supervisor alerting is the channel — same stance as the sentinel rejection at config_load.go:183-185). Log + remediation-naming panic pinned in `applyIssuerAllowlistGate`.

**Allowlist mint refusal (fail-closed)** — log + `sso_issuer_allowlist_refusals_total` (no labels) inside the shared `issuerNameAllowed` predicate; deliberately NO audit event, with two pinned reasons (resolution seam `IssuerForClient` has 15 call sites incl. nested modules — no ctx, no trace IDs; the 500 today has no audit event).

## Verified classification chain

`EventTokenRolesLookupFailure` requires all 8 touchpoints — const, `KnownEventTypes`, alias, OCSF/CEF maps, conformance list, severity override, and **CC7.2** in `control_areas.go` (beside `EventTenantQuotaStoreFailure`) — enforced mechanically by `TestKnownEventTypesIsComplete`, `TestConformance_EveryEventTypeHasCEFAndOCSFMapping`, and the drift test (no drift_test.go edit needed). Also reported: a pre-existing gap — `sso_token_policy_role_resolution_errors_total` exists in consts.go but is missing from observability.md's table.

## Trust-state probe

Documented with exact text for `docs/observability.md` (new prose line), `docs/config-reference.md` rows :48/:71 (discovery `issuer` is now a constant; the probe moves to `authorization_endpoint`/`token_endpoint`, still XFH-gated), and the design doc §3.3.

## Budget-verified

Full before→after table: `accessors_handlers.go` 477→~497, `sso.go` 500 (at ceiling), `server_helpers.go` 499, `metrics.go` 499, `sso_wiring.go` ~488 — all ≤500, plus the `Roles` signature amendment (`context.Context` → `core.HandlerContext`) documented as net-zero-line. Falsifiable acceptance additions: `TestRcov_TenantIDRoles_StoreOutageOmitsClaim` (outage vs `ErrUserNotFound` legs), extended mint-reject/boot tests asserting the counters, log lines, and empty-recorder.
