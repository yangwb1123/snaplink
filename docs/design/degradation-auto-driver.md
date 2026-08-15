# Design: degradation — automatic degraded-mode transitions (auto read_only driver)

Design promoting the "Automatic degraded-mode transitions" **Deferred decision**
(`docs/deferred-backlog.md`) into an implemented, opt-in capability. All file/line
references were re-verified against the working tree before writing. Scope is
exactly the four decisions below: an in-process driver that polls the existing
storage-health seam and drives `SetMode(read_only)` through the SAME path the
admin `/api/v1/admin/dr/mode` toggle uses. **Policy/Mode semantics are untouched**;
with the auto flag unset (or `degradation.enabled` false) the build is
byte-identical to today.

Current state (verified):

- `platform/lifecycle/degradation/manager.go` — `Manager` is an atomically
  swappable mode with `OnChange` hooks fired outside the lock; its package doc
  says "a cluster drives every replica via its own health loop or admin call".
  There is no background loop in the package.
- `config/config_snapshot.go:356-376` — `DegradationConfig.AutoReadOnlyOnStoreLoss`
  is documented as an INTENT flag with "no clean seam to drive this
  automatically"; `cmd/sso-server/build_app_security.go:345-352` logs
  "no auto-driver seam" when it is set.
- The audit + metric side effects of a mode change already exist and are
  registered by `WithDegradationManager`
  (`interfaces/sso/options_httpstack.go:147-160` →
  `interfaces/sso/server_health.go:369-386` `onDegradationChange`: logger,
  `sso_degradation_mode` gauge, `audit.EventDegradationModeChanged` with
  `from`/`to` meta). A driver that calls `Manager.SetMode` inherits this path
  byte-identically — no new audit/metric wiring is needed.

---

## Decision 1: probe source — reuse the `StorageHealthSource` seam

**What.** The driver polls the SAME probe functions the admin storage-health
report and `GET /api/v1/status` module health use: every store that exposes
`Ping(ctx) error` is already collected by the composition root into
`appBuilder.storageHealthSources` and surfaced as `sso.StorageHealthSource`.

**Code evidence (no invented interfaces):**

- `internal/handler/serverdeps.go:180-184` defines
  `StorageHealthSource{Name string; Ping func(ctx context.Context) error; SchemaVersions ...}`.
- `interfaces/sso/server_health.go:151-160` `WithStorageHealth(sources ...)` and
  `interfaces/sso/server_health.go:208-243` `probeModules` — the pull-based
  per-store `Ping` probe is the existing health mechanism (bounded per source by
  `storageHealthProbeTimeout = 3s`, `server_health.go:262-264`).
- `cmd/sso-server/serverbuildsign/build_readiness.go:67-100`
  `AppendStorageHealthSource` gates on `interface{ Ping(context.Context) error }`
  — memory backends contribute nothing, so the watchlist contains exactly the
  stores with a real reachability signal, the same set `/readyz` aggregates
  (`build_readiness.go` comment).
- `interfaces/sso/server_health.go:91-148` `handleReadyz` — readiness checks and
  storage-health sources are populated side by side; the storage sources are the
  per-store half of that posture.

**Layer-boundary adaptation.** `platform/lifecycle/degradation` must not import
`interfaces/sso` or `internal/handler` (upward dependencies; AGENTS.md
architecture §2). The driver therefore owns a minimal probe port and the
composition root adapts the EXISTING `Ping` closures into it:

```go
// platform/lifecycle/degradation/driver.go (new)
type Health int
const (
    HealthHealthy   Health = iota // store reported reachable
    HealthUnhealthy               // store definitively reported unreachable
    HealthUnknown                 // probe itself failed/timed out — fail-open
)
type StoreHealthFunc func(ctx context.Context) Health
type Probe struct {
    Name  string
    Check StoreHealthFunc
}
```

`cmd/sso-server/serverbuildplatform` (the composition root) maps each
`sso.StorageHealthSource` to a `degradation.Probe` by wrapping its `Ping`
closure: `nil → Healthy`, `context.DeadlineExceeded`/`context.Canceled →
Unknown`, any other error → `Unhealthy`. This reuses the seam and adds no new
health SPI anywhere; `interfaces/sso` stays at its 60-file ceiling.

**Which stores trigger read_only.** The composition root hands the driver every
wired storage-health source EXCEPT `audit-*` sinks:

- `cmd/sso-server/build_app_core.go:230` registers the primary audit sink as a
  storage-health source (`audit-<primaryName>`). Audit sink errors are
  **fail-open by contract** (AGENTS.md §3: "Fail open with audit/logging: …
  audit sink errors"), so an audit-store loss must NEVER flip the server
  read-only. The `audit-` prefix filter lives in the composition root next to
  the registrations, with the contract reference in the comment.
- Every other source (`sqlite-identity-*`, `sqlite-tenant`, `sqlite-permissions`,
  `sqlite-jti-replay`, `sqlite-webauthn-*`, `sqlite-mfa-*`, `sqlite-ciba*`,
  `sqlite-pairwise-subjects`, `identity-links`, `postgres/sqlite-refresh-grace`,
  `tenant-resource-quota`, `sqlite-account-lockout`, `redis-bcl-failure-queue`,
  `sqlite-bcl-subject-client-index`, `sqlite-anomaly-*`) is a store whose loss
  makes a write error deep in a handler — exactly the class `ModeReadOnly`
  exists to shed early with 503 + Retry-After (`platform/lifecycle/degradation/mode.go`
  `ModeReadOnly` doc). This also matches the existing `/readyz` posture: the same
  stores already trip readiness.

**Decision.** Reuse `sso.StorageHealthSource.Ping` via a composition-root
adapter; exclude `audit-*`; document the exclusion at the filter site.

---

## Decision 2: driver loop — new config keys, grace hysteresis, recovery, shutdown

**Config (new keys, recommended `degradation.auto_read_only.*` shape).**
`config.DegradationConfig` (`config/config_snapshot.go:356`) gains a nested
section:

```go
type AutoReadOnlyConfig struct {
    // Interval is the poll cadence; <=0 takes degradation.DefaultAutoInterval.
    Interval time.Duration `yaml:"interval"`
    // Grace is the continuous-unhealthy window before read_only; <=0 takes
    // degradation.DefaultAutoGrace.
    Grace time.Duration `yaml:"grace"`
}
```

Defaults live in the driver package (`DefaultAutoInterval = 30s`,
`DefaultAutoGrace = 60s`) — the existing pattern for package-owned defaults
(e.g. `rotation.ClientSecretScanInterval`). Armed iff
`degradation.enabled && degradation.auto_read_only_on_store_loss`. If armed but
no watchable store exists (memory-only deployment, or all sources are audit),
the composition root logs and returns no driver — a memory-only deployment that
sets the intent flag for a future multi-store rollout must keep booting.

**Loop.** `degradation.Driver` (new file `driver.go`):

- `NewDriver(mgr *Manager, baseline Mode, probes []Probe, interval, grace time.Duration, logger spi.Logger) *Driver`
  — `baseline` is the manager's boot posture (what `BuildDegradationManager`
  validated); `interval`/`grace` `<= 0` take the package defaults; nil `mgr`
  returns nil (programming-error guard; the composition root pre-checks).
- `Run(ctx) <-chan struct{}` — one immediate sweep, then a ticker at the
  effective interval; returns a done channel closed when `ctx` cancels
  (standard cancel+done lifecycle, same shape as every other background loop in
  `cmd/sso-server`, e.g. `startBreakGlassSweeper`).
- Sweep: probe every `Probe` (each under a per-probe timeout — see Decision 3),
  aggregate to a single binary signal: **lossy iff any probe returned
  `HealthUnhealthy`**.

**Hysteresis (transient jitter never flaps the mode).** A sweep that is NOT
lossy (all Healthy, or any Unknown) clears the loss window. A lossy sweep starts
it (`lostSince`). The driver calls `SetMode(read_only)` only when the loss has
been observed continuously for ≥ `grace`. One flapping tick therefore never
transitions; the flip requires a sustained outage. Recovery needs no separate
debounce: after recovery the same grace gate protects re-entry, so the worst
possible oscillation is one pair of flips per grace period.

**Recovery semantics.** On a clean sweep, if the current mode is `read_only`
AND the driver made that transition (`ownReadOnly`), it restores to
`baseline` — the configured `initial_mode`. The driver only ever transitions
`baseline ↔ read_only`:

- Degrade fires only when the current mode equals `baseline`; any other mode
  (operator-set `maintenance`/`auth_only`/`local_only`, or a manual `read_only`)
  is left untouched — an explicit operator override wins.
- If the operator returns the mode to `baseline` while the store is still lost,
  the next sweep re-asserts `read_only` (invariant enforcement at the baseline
  only; the operator opted into this by arming the flag, and every re-assertion
  is audited through the same `OnChange` path).
- A `read_only` the driver did not set is never auto-restored.
- With `initial_mode: read_only` the driver is inert by design: the operator's
  baseline IS read-only, so there is nothing to degrade from or restore to.

**Graceful shutdown.** `Run(ctx)` returns on cancel; the composition root
records a cancel/done pair on the `appBuilder` → `app` → `stopScheduler`
(`cmd/sso-server/main_shutdown.go:302-330`). A restart returns to the configured
`initial_mode` anyway (Manager is deliberately ephemeral per replica).

---

## Decision 3: failure modes — fail-open probes, same audit/metric path

**Probe error/timeout is fail-open.** The tri-state verdict exists exactly for
this: only a definitive `HealthUnhealthy` from the store itself counts toward
the loss window.

- Per-probe timeout: `interval/2`, clamped to `[100ms, 3s]` — the 3s ceiling
  mirrors the sibling storage-health probe convention
  (`storageHealthProbeTimeout = 3s`, `interfaces/sso/server_health.go:262`).
- A hung probe is cut by the driver's deadline; the wrapped `Ping` then returns
  `context.DeadlineExceeded`, which the adapter maps to `HealthUnknown`
  (fail-open). A probe that returns `Unknown` neither starts nor extends the
  loss window and CLEARS it like a healthy verdict — uncertainty delays, never
  accelerates, a read_only transition (AGENTS.md §3 trust/failure-mode
  discipline).
- The driver logs each `Unhealthy` verdict with the store name and each
  `Unknown` at debug level.

**Transitions go through the existing OnChange path.** The driver calls
`mgr.SetMode(ctx, ModeReadOnly, "auto_read_only: store loss (...)")` /
`SetMode(ctx, baseline, "auto_read_only: store health recovered")`. The
`OnChange` hook registered by `WithDegradationManager`
(`options_httpstack.go:147-160`) then logs, moves the `sso_degradation_mode`
gauge, and records `audit.EventDegradationModeChanged` with `from`/`to` meta
(`server_health.go:369-386`) — byte-identical to an admin `POST /dr/mode`
transition, including the no-op guard (`SetMode` fires no hook when the mode
does not change, `manager.go:86-88`, so an already-degraded sweep does not spam
audit). No new metrics or audit event types.

**Driver-internal failures.** `SetMode` errors are logged and swallowed (the
modes passed are compile-time constants; `ErrInvalidMode` is unreachable). The
loop itself cannot wedge: every probe is deadline-bounded, and a canceled `ctx`
exits the loop.

---

## Decision 4: hard boundaries

- **No Policy/Mode semantics change.** `mode.go`/`policy.go` are untouched; the
  driver only calls the existing `Manager.SetMode`.
- **Byte-identical when off.** `degradation.enabled` false, the flag unset, or
  no watchable store ⇒ `BuildDegradationAutoDriver` returns nil and no goroutine
  is started; `wireDegradation` falls through to today's log line. Config struct
  grows a nested section only (zero value = off).
- **No maintenance exemptions.** No `fileSizeExemptions`/`layerExemptions`
  entries. `driver.go` stays far under 500 lines; the degradation package stays
  at 4 non-test files (≤ 10 per directory).
- **No upward dependencies.** `platform/lifecycle/degradation` imports only
  stdlib + `shared/spi` (`spi.Logger`, already used by sibling
  `platform/lifecycle/rotation`). The adapter (composition root) is the only
  place that touches `interfaces/sso`.
- **`interfaces/sso` untouched** (60-file ceiling). The wiring-level test lives
  in `cmd/sso-server`.
- **`build_app_security.go` stays ≤ 500 lines.** The `wireDegradation` branch
  arms the driver inline (a new cmd file is impossible: `cmd/sso-server` sits
  at its frozen 24-file fan-out ceiling and `serverbuildplatform` at its
  10-file cap, `directory_fanout_test.go:52`), so the file ends at the same
  500-line budget it already had at HEAD.

---

## Sequencing, contracts, and gates

One change, in this order:

1. `config/config_snapshot.go` — `AutoReadOnlyConfig` + comment updates
   (`AutoReadOnlyOnStoreLoss` is no longer "honored as a boot-time log
   acknowledgement").
2. `platform/lifecycle/degradation/driver.go` + `driver_test.go` — the driver
   and its unit tests (fake probes).
3. `cmd/sso-server/serverbuildplatform/build_governance.go` (456/500 lines at
   HEAD) — `BuildDegradationAutoDriver` + `autoReadOnlyProbes` (audit-*
   filter + Ping adapter). No new file here either: the package is at its
   10-non-test-file cap.
4. `cmd/sso-server/build_app_security.go` — `wireDegradation` arms the driver
   inline (no helper function, no new file); `build_app.go` (appBuilder
   fields), `main.go` (app fields), `build_app_core.go` (`assembleExtras`),
   `main_shutdown.go` (`stopScheduler` pair) — the standard cancel+done
   lifecycle.
5. `cmd/sso-server/degradation_wiring_test.go` + `build_governance_test.go` —
   wiring-level + adapter tests (test files do not count toward fan-out).
6. Docs in the same commit: `docs/config-reference.md` (degradation section),
   `docs/deferred-backlog.md` (promote the Deferred decision), `CHANGELOG.md`
   (Added).

Contract updates in the same change: config keys →
`docs/config-reference.md`; no new endpoints (no `docs/openapi.yaml` change); no
new error codes.

## Acceptance assertions (all executable)

| # | Assertion | Test |
|---|---|---|
| A1 | Store probe `Unhealthy` for ≥ grace ⇒ manager reaches `read_only`; reason mentions the store | `driver_test.go` |
| A2 | All probes healthy again ⇒ manager returns to `baseline` (and only then) | `driver_test.go` |
| A3 | One flapping `Unhealthy` tick between healthy sweeps ⇒ mode never changes | `driver_test.go` |
| A4 | Probe returning `Unknown` (and a hung probe cut by the timeout) ⇒ never transitions | `driver_test.go` |
| A5 | Operator-set non-baseline modes are not fought; baseline return re-asserts `read_only` while the store is still lost | `driver_test.go` |
| A6 | Manual `read_only` (driver did not set it) is never auto-restored | `driver_test.go` |
| A7 | Interval/grace `<= 0` ⇒ package defaults; `Run(ctx)` returns on cancel | `driver_test.go` |
| A8 | Armed config + fake `StorageHealthSource` through `wireDegradation` ⇒ driver armed, cancel/done non-nil, end-to-end transition fires | `degradation_wiring_test.go` (cmd) |
| A9 | Flag unset / degradation disabled ⇒ no driver, no goroutine | `degradation_wiring_test.go` |
| A10 | `build_app_security.go` ≤ 500 lines (asserted in the wiring test; also enforced by `TestMaintainability_FileSizeBudget`) | `degradation_wiring_test.go` |

Verification commands (run and reported):

```bash
go build ./... && go vet ./...
go test ./platform/lifecycle/degradation/... -count=1
go test ./cmd/sso-server/... -count=1 -run 'Degrad'
go test -count=1 -run 'TestMaintainability_|TestArchitecture_|TestDirectory' .
```

(`python cli.py config-validate-all` does not exist in this repository — the
config-relevant gates are the Go config tests + `TestReferenceConfigYAMLParses` +
the maintainability suite above; see the CHECKS_REGISTRY for the actual command
set.)
