All citations check out. The hardened plan is delivered.

## Summary

**Deliverable:** `docs/architect-analysis/auto/runs/close-the-last-fail-open-tenant-isolation-class--41270b2a/artifacts/migration-hardening-be4a6d00/task-3-migration-and-rollback.md` — M0–M5 hardening with all four asks verified against the working tree.

**Verdicts:**

**(1) M1 — feasible, two gaps closed.** Enumeration is real: `sso-ctl clients list` (JSON `tenantId` omitempty / table `TenantID` column), backed by admin REST/gRPC (`clients.proto:11`, read-only). Bind surface is `clients[].tenant_id` in sso-server YAML (config_client.go:24 → build_app_core.go:91 → unconditional mint at server_login.go:119 / issue_payload.go:46). **Gap A**: client binding is boot-time — the SIGHUP reloader covers only quota sources + feature gates, so M1 is a config rollout, not a live mutation. **Gap B**: pre-binding tokens stay claim-less until expiry/rotation, so M1 needs an `access_token_ttl` aging gate (or forced re-login) before M2.

**(2) `checkout_created` — queryable, but no alert existed anywhere.** `snaplink_stripe_checkout_created_total` is a real per-process Prometheus counter at unauthenticated `/metrics`, incremented only on 201. `ops/deploy/grafana/alerts.yaml` has zero stripe-adapter rules (verified). The plan now ships two concrete PromQL rules in M1: a traffic-gated stall alert (`created rate == 0` AND `webhook_accepted rate > 0`, `for: 15m`) and a per-instance baseline-vanished page rule (`offset 1d` guard) — plus the explicit caveat that the adapter deliberately emits no 403 metric (anti-oracle byte-identity), so detection is absence-of-201 by design.

**(3) M4 — safe, with evidence.** Authz strictly precedes the first store write (`ReserveCheckout` serializable + `ON CONFLICT DO NOTHING`); the flip is the only version delta (machine/webhook/worker/billing paths claim-free and byte-identical); reservations converge on shared idempotency keys. Mixed-version 403/201 split is self-limiting and is itself the M1-completeness probe.

**(4) M5 — rewritten from "one-line" into a 10-item, same-commit, doc-coupled checklist.** Confirmed the fail-closed wording is already live in `openapi.yaml:20–31/176/214–225`, `error-codes.md:1057/1063`, `stripe-payment-adapter.md:38–46`. The rollback reverts code + A15/A16 test pins + all three doc wordings in one change (AGENTS.md §2/§5.6), excludes the machine path explicitly (a whole-commit revert would reopen both classes — HEAD lacks the machine claim check), keeps the mint-side A17/A18 e2e, decides the alert-rule fate explicitly, and ends with a negative probe (claim-less + bound → 201 restored).

Pre-existing gate failures (directory-depth/fanout on generated runs, `ed25519_jwt_issuer.go` file budget) are unchanged by this artifact and reported separately per AGENTS.md §5.7. No production Go was touched.
