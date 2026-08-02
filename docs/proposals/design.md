Design doc delivered: `docs/auto/domains-region-observability-design.md` (491 lines, 4 `##` decision sections). Every cited line was verified against source before writing; the design honors all three baked-in constraints and resolves the spec's ambiguities.

## What the design decides

**1. One observation choke point (improvement 1)** — `checkTenantResidency` gains a `surface` param with a documented call-site table (login ×4 sites, token_grant, mesh, userinfo, me — closed set). Key pinning decisions:
- Verdict mapping is an explicit `errors.Is` ladder onto `{allow, region_not_allowed, residency_violation}` — never `mapResidencyError`'s `access_denied` default, which would break the closed set.
- Cache `miss` = any fall-through past `cache.get` (including fail-open), so hit-rate literally measures store-round-trip avoidance; exactly one cache observation per `resolveResidencyPolicy` call.
- Early ladder returns (engine off, fail-open) emit **nothing** — that's what makes "unwired ⇒ series absent" true.

**2. Fail-open alerting (improvement 2)** — `store_unwired` fires per gated request (nothing is ever cached in that misconfiguration, so it's loud by design); `sso_residency_enabled == 1` boot gauge guards both alert expressions; cmd `wireRegion`'s OnError closure bumps `sso_region_resolution_errors_total` — the only layering-legal seam.

**3. Audit trail (improvement 3)** — the spec named only the auditreport classification, but I found **three more compile-enforced surfaces** a new EventType must touch: `KnownEventTypes` completeness test (AST-parses consts), the CEF/OCSF conformance test, and `aliases_spi.go`. The doc lists all five as a checklist — this is a five-edit change or CI fails.

## Risks flagged

- **`ResidencyDecision` signature change** is an exported SDK Go API break (spec's 4th call site forces it); all consumers are in-repo, with a documented fallback if SDK stability is demanded.
- **Test-harness unknown**: no `test/` e2e currently wires `WithMetrics` (verified by grep), so the mesh scrape assertion needs a test-only harness extension.
- `metrics_ctor.go` goes 497→498 lines — the register body must live in `residency.go`.
- `region` label cardinality relies on the existing middleware `AllowedRegions` allowlist — documented as an operator obligation in the observability section.
