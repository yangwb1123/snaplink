Spec written to `docs/auto/domains-tokenanomaly-direction1-spec.md`, following the `docs/auto/domains-tenant-direction1-spec.md` convention. All evidence was verified against source before writing.

## Requirements specification — direction 1: 打通 Geo 信号链路

Three evidence-backed improvements, each under a `## ` heading with name, problem, evidence (file/symbol), proposed behavior, and acceptance check:

**Improvement 1 — 五个 Offer 握手点写入粗粒度 GeoCountry（数据源打通，root fix）**
- Problem: `detectGeoVelocity` requires `len(o.geos) >= 2` but no production code path ever fills `Event.GeoCountry` — only test files assign it.
- Evidence: `interfaces/sso/server_helpers.go:428-453`, `protocols/oauth/handle_introspect.go:357`, `protocols/oauth/introspect_body.go:21`; the geo context already exists (`options_misc.go:55-58` `WithGeoProvider`, `platform/geo/middleware.go:99` `FromHandlerContext`) with precedent at `server_helpers.go:313` (login side).
- Behavior: one canonical `CountryCodeFromContext` extractor in `platform/geo` (importable by both layers, respecting import direction), routed through all five Offer sites; empty ⇒ byte-identical (fail-open).

**Improvement 2 — refresh-introspect 链路补齐 Thumbprint**
- Problem: even geo-enriched, the refresh-introspection Offer sets no `Thumbprint`, and `Detector.Record` only captures observations when `ev.Thumbprint != ""` (detector.go:257) — refresh presentations can never feed per-token geo findings; `RefreshToken` has no JTI field.
- Evidence: `oauthspi/refresh_token.go:25-43` (struct), `RefreshTokenInspector.Inspect` returns `*RefreshToken` (no interface change needed); `introspect_body.go:21-29` already stamps `Thumbprint: metering.Thumbprint(claims.JTI)` — the proven pattern.
- Behavior: stamp JTI at issue (new-family branch, `auth_code_handler.go:238-244`), propagate through rotation like `FamilyID`, set Thumbprint at `introspectRefresh`.

**Improvement 3 — 响应链激活：Geos 进 Threat.Evidence + 端到端契约测试**
- Problem: `dispatchThreat` (detector.go:405-426) drops `f.Geos` from `Evidence` (the entire basis of the finding), passes an empty `ThreatPolicy`, and no test proves a geo finding routes through `ThreatExecutors` → policy → `ActionRevoke`; `ThreatMultiGeo`/`ThreatVelocity` constants (threataction.go:109-110) are unreachable and untested.
- Behavior: carry `geos`/`count` into Evidence; add dispatch contract tests plus a policy-routing test (`WithDefaultAction` wiring at build_governance.go:338); document threat-type wire strings in config guidance.

Preserved invariants: coarse-geo-only privacy (never IP/city), zero-value byte-identity, off-path fail-open detection, no new imports/budgets crossed, no `layerExemptions`.
