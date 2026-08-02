Spec written to `docs/auto/domains-tokenanomaly-direction3-spec.md` (following the existing `direction1-spec.md` convention). Three evidence-backed improvements, each with name, problem, evidence (file/symbol), proposed behavior, acceptance check:

## Improvement 1 — FamilyID 进入 token 遥测（Event 字段 + 旋转握手点填充 + observation 捕获）
- **Problem**: `metering.Event` has no `FamilyID` (token_usage.go:45-77); the rotation grant drops `info.FamilyID` at `token_refresh.go:206` even though it's in scope (threaded into `IssueRefreshToken` at :232); `observation` (detector.go:59-68) captures client/subject only.
- **Proposed**: `Event.FamilyID` field (no bucket/migration change), family param through the `RecordRefreshTokenIssued` seam (`serverdeps.go:157` → `accessors_handlers.go:457` → `server_helpers.go:439`), rotation passes `info.FamilyID`, first-issue paths pass `""` (byte-identical), `observation.familyID` captured in `recordObservation`.

## Improvement 2 — FamilyID 贯穿 Finding→Threat→revoke（SubjectRevoker 仅作兜底）
- **Problem**: `Finding` (tokenanomaly.go:50-72) and `dispatchThreat` (detector.go:138-155) never set `Threat.FamilyID`, so `RevokeFamilyExecutor.Execute` (actions.go) always falls back to `DeleteAllForSubject` — a user-wide hammer for one stolen token; `SubjectRevoker`'s own doc calls the family path "a permanent no-op in production". `evidenceFor` also omits `family_id` for policy conditions.
- **Proposed**: `Finding.FamilyID`, `dispatchThreat` fills the Threat, `evidenceFor` gains `family_id`, executor code unchanged but family path becomes reachable; fallback stays byte-identical for family-less threats.

## Improvement 3 — rate_spike 窗口化 + 有界 subject 维度
- **Problem**: `spikeForClient` (detect.go:100-136) tests only `minutes[len(minutes)-1]` against the earlier mean — a burst starting before the current (partial) minute or subsiding before the sweep is missed; `foldClientMinuteRates` (detect.go:88-98) keys on client only since `Bucket` has no subject, hiding per-subject token-rotation bursts in high-volume clients.
- **Proposed**: scan every minute in the window (strongest candidate only, one finding per client per sweep), plus a capped per-(subject, client) rate table fed from `Record` events (no new Bucket dimension, preserving bounded cardinality).

The spec also documents preserved invariants (privacy, fail-open, zero-value byte-identity, import direction, file budgets — subject-rate logic goes in `detect.go` at 155 lines, not `detector.go` at 442), file modify/do-not-modify lists, and the verification plan. No `.go` files were changed, so no mandatory Go gates were triggered.
