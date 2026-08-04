# Architecture Analysis: Anomaly Detection → Response Gap

> Analyst: Architect Agent | Date: 2026-07-10
> Input: User analysis report + codebase survey via grep + read

---

## 1. Answers to Specific Questions

### Q1: What is this report's goal? Strategic planning or green-light to implement?

**Both, leaning toward immediate action on direction 3 (Active ITDR).**

The analysis document is thorough enough to move from "strategic reconnaissance" to "feasibility spec." Three signals tell me the author was already doing pre-implementation due diligence:

1. **Every gap was grep-verified** — not hypothetical. The code confirmation means the author had already mentally wired it.
2. **Code locations and interface names** were cited precisely — author knew where to touch.
3. **Boundary cases were enumerated** (fail-open vs fail-closed, cluster propagation, tenant isolation).

**My recommendation:** Treat direction 3 (Active ITDR) as immediately actionable. Direction 1 (Terraform Provider) is a separate Go module — zero core changes — so it can proceed in parallel with a different engineer. Direction 3 changes core packages and benefits from the architect+implement+review cycle.

### Q2: Terraform Provider — Plugin Framework vs SDK v2?

**Plugin Framework. No hesitation.**

Rationale beyond Terraform's EOL announcement:

| Criterion | Plugin Framework | SDK v2 |
|---|---|---|
| Type safety | Native Go types, compile-time validation | `interface{}` + stringly-typed schema |
| Terraform CLI compatibility | Plugin Protocol v5+v6, future-proof | Protocol v5 only |
| Testing | Built-in `tfprotov6` + `plancheck` helpers | External `hashicorp/terraform-plugin-test` |
| Provider-defined functions | Native support | N/A |
| Ecosystem trajectory | All new official providers use it | Maintenance mode since 2024 |

The decision is clear for a net-new provider. The only reason to pick SDK v2 would be if we needed to reuse an existing SDK v2 library (e.g., `hashicorp/terraform-provider-google` pattern) — but this is a brand-new provider for a custom API, so we start clean.

### Q3: Active ITDR wiring — callback on Runner vs DetectionPipeline?

**Option A (callback) for wave 1, shaped to allow Option B later.**

Detailed analysis:

| Dimension | A: Callback in Runner | B: DetectionPipeline |
|---|---|---|
| Lines changed | ~50 in `runner.go`, ~30 in `detector.go` | ~600 new code, ~20 changed |
| New abstractions | 0 (uses existing Sink pattern) | 1 (Pipeline) |
| Migration path | Can add Pipeline later without breaking | Paved road for new detectors |
| Third-detector risk | Must remember to wire each new detector | Single routing point |
| Rate-limiting | Must be in each detector's executor hook | Centralized |
| Audit trail | Per-executor | Unified |

The real constraint is: **how many detector types exist?** Currently: exactly two (`anomaly.Detector` for login events, `tokenanomaly.Detector` for token usage). Both are stable. No third type is planned. At this level of complexity, a new abstraction layer is premature — it's solving a composability problem we don't have yet.

**Contract:** The `ThreatExecutor` SPI is the same interface in both designs. The `ThreatExecutors` composite (policy lookup + rate-limit + dispatch) is the same struct. Adding a `DetectionPipeline` later that owns Runner + executor + routing table is an internal refactor — the SPI contract doesn't change, so no callers change.

### Q4: Refresh grace window — known user feedback?

**Preventive fix, not incident-driven.** Based on code evidence:

- `WithRefreshRotationGrace` was added as an option (not default) — it's opt-in
- The Redis-backed `RefreshGraceStore` in `infrastructure/redis/` exists but the in-memory version is single-replica only
- No TODO, FIXME, or bug reference links to a customer issue

The window behavior is correct (the grace cache prevents false family-reuse kills within the window), but the **naming and discovery** issue the analysis mentions (operators don't know it exists) is real — it's behind an option with a detailed but long godoc, not in the config reference or deployment guide.

**Recommendation:** Document it in `docs/config-reference.md` and as a YAML config shorthand `sso.security.refresh_grace: 5s`. Code-wise it's correct; it's a discoverability gap.

---

## 2. Architecture Assessment

### 2.1 Current Architecture Strengths

| Strength | Evidence |
|---|---|
| **Clean layer isolation** | `domains/anomaly` has no import of `protocols/oauth/` — detectors are composable via interfaces only |
| **Fail-open discipline** | `anomaly.Runner` drops events on overflow, logs errors per-detector, never blocks login path |
| **Fail-closed where correct** | Refresh rotation `DeleteFamily` is fail-closed (correct — it's a security gate, not a performance optimization) |
| **Decorator pattern for token anomaly** | `tokenanomaly.Detector` wraps `tokenusage.Store` — drops in without changing the recorder path or the read API |
| **Audit as backbone** | Every detection result flows through `audit.Recorder` — single observability contract |
| **Minimal third-party** | The whole anomaly stack is pure Go interfaces + a goroutine pool — no Kafka, no Redis required for basic operation |
| **Granular SPIs** | `RecentLoginStore`, `IPFailureCounter`, `FindingStore` each serve one purpose — operators pay only for what they wire |

### 2.2 Architecture Debt and Gaps

| Issue | Severity | Location | Mitigation |
|---|---|---|---|
| **Detection→Response gap** | **HIGH** | `domains/anomaly/runner.go` + `domains/tokenanomaly/detector.go` | This feature spec |
| **MemoryLimiter self-DoS** | **HIGH** | `interfaces/ratelimit/ratelimit.go:152` | See §5.1 below |
| **Executor would need access to stores Runner doesn't own** | **MEDIUM** | Cross-package dependency | Wire via server's `Deps` interface, not through Runner |
| **tokenanomaly.Analyze has no backpressure** | **MEDIUM** | `domains/tokenanomaly/detector.go:226` | Sweep is timer-based — if store is slow, sweeps pile up. Not a DoS (it's off-path) but can produce stale findings under load |
| **Policy store no-op doesn't surface to operator** | **LOW** | `conditionalaccess.PolicyStore` (memory) | Default empty policy set means "allow all" — correct but operators may think it's enforcing when it isn't |

### 2.3 Code Budget Compliance

Current state of affected packages (pre-change):

| File | Lines | Budget | Status |
|---|---|---|---|
| `domains/anomaly/runner.go` | 228 | 500 ✅ | Under |
| `domains/anomaly/types.go` | 130 | 500 ✅ | Under |
| `domains/tokenanomaly/detector.go` | 308 | 500 ✅ | Under |
| `interfaces/ratelimit/ratelimit.go` | 194 | 500 ✅ | Under |

No file is near the 500-line limit, so the feature work fits without a split-first requirement.

---

## 3. Expansion Directions (Ranked)

### Direction 1: Active ITDR (Detection → Response Bridge)
**Priority: P0** | **Effort: ~400 lines** | **Risk: Low**

Already spec'd above. The highest value-per-line-change ratio in the codebase.

### Direction 2: Terraform Provider
**Priority: P0** | **Effort: ~2000 lines (separate module)** | **Risk: Very Low**

Independent Go module at `terraform/` or separate repo `snaplink/terraform-provider-sso`. Zero changes to core.

Architecture:

```
terraform-provider-sso/
├── provider.go          # Provider schema + ConfigureFunc
├── resources/
│   ├── resource_client.go        # oauth.Client CRUD
│   ├── resource_tenant.go        # tenant.Config CRUD
│   ├── resource_policy.go        # conditionalaccess.Policy CRUD
│   ├── resource_signing_key.go   # key lifecycle
│   └── resource_audit_sink.go    # audit.Sink config
├── datasources/
│   ├── data_client.go            # read-only client lookup
│   ├── data_tenant.go
│   └── data_jwks.go              # fetch current JWKS
└── client/
    └── sso_client.go             # HTTP client wrapper against admin API
```

**Key design decision:** The provider calls the SSO server's **admin API** (HTTP), not Go interfaces directly. This is critical:
- No import of SSO core — avoids Go module dependency, license coupling, build complexity
- Uses the same API surface as a human operator with a curl script — naturally scoped to what the admin API exposes
- The admin API already has gRPC equivalents for internal use; the Terraform provider only needs HTTP

**Terraform Plugin Framework resource pattern:**
```go
// resource_client.go
func resourceClient() resource.Resource {
    return &clientResource{}
}

type clientResource struct {
    client *sso.Client  // HTTP client wrapping admin API
}

func (r *clientResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
    resp.Schema = schema.Schema{
        Attributes: map[string]schema.Attribute{
            "client_id":      schema.StringAttribute{Computed: true},
            "client_name":    schema.StringAttribute{Required: true},
            "redirect_uris":  schema.ListAttribute{ElementType: types.StringType, Required: true},
            "grant_types":    schema.ListAttribute{ElementType: types.StringType, Optional: true},
            "tenant_id":      schema.StringAttribute{Optional: true, Computed: true},
        },
    }
}
```

### Direction 3: Conditional Access Threat-Type Condition
**Priority: P1** | **Effort: ~150 lines** | **Risk: Low**

Extend `conditionalaccess.Conditions` with a `ThreatType` field. This lets operators write policies like:

```yaml
policies:
  - name: "auto-suspend-impossible-travel"
    conditions:
      threat_type: "impossible_travel"
      risk_score: "> 0.7"
    actions:
      deny: true
      require_mfa: true
```

This is the **synchronous** complement to the async executor: the async executor suspends sessions (affects next request), while the conditional access policy blocks the current request if a recent threat tag exists.

Implementation is straightforward — `conditionalaccess.Conditions` already parses `risk_score`, `user_member_of`, `device_managed`. Adding `threat_type` follows the same pattern.

### Direction 4: MemoryLimiter Shard-Level DoS Fix
**Priority: P1** | **Effort: ~50 lines** | **Risk: Low**

The issue: `MemoryLimiter.Allow()` acquires a per-shard lock, then inside the critical section does a lazy prune (1-in-64 calls). Under a high-cardinality key attack (IP spray), the prune scan is O(N/shards) while holding the lock — serializing ALL requests in that shard.

**Fix:** Move prune out of the critical section. Two options:

**Option A (recommended): Background goroutine.** Spawn a periodic pruner that walks all shards outside of `Allow()`. `Allow()` only does the hash + bucket lookup + token reserve. This removes the O(N) scan from the hot path entirely.

```go
// New approach: no prune in Allow()
func (m *MemoryLimiter) Allow(key string) (bool, time.Duration) {
    idx := shardIndex(key)
    sh := &m.shards[idx]
    sh.mu.Lock()
    b, ok := sh.buckets[key]
    if !ok {
        b = &bucketEntry{lim: rate.NewLimiter(rate.Limit(m.perSecond), m.burst)}
        sh.buckets[key] = b
    }
    b.lastSeen = time.Now()
    sh.mu.Unlock()
    // ...
}

// Background goroutine started at construction
func (m *MemoryLimiter) startPruner(ctx context.Context) {
    go func() {
        ticker := time.NewTicker(m.stalePruneAfter / 2)
        for {
            select {
            case <-ticker.C:
                m.pruneAll()
            case <-ctx.Done():
                return
            }
        }
    }()
}
```

**Option B:** Use `sync.Map` with amortized delete. Simpler but `sync.Map` doesn't support the O(N) scan needed for time-based eviction.

**Recommendation: Option A.** Background prune is the standard pattern (Go's own `http.Server` does this for connection state). The current 1-in-64 sampling was a clever optimization but creates a tail-latency DoS vector.

### Direction 5: Redis-Backed Rate Limiter (Production HA)
**Priority: P2** | **Effort: ~200 lines** | **Risk: Low**

The `interfaces/ratelimit/` package already defines a `Limiter` interface. A `RedisLimiter` implementation (using `infrastructure/redis/` existing client) gives operators cross-replica rate enforcement. This is a store implementation — no API changes.

---

## 4. Interface Design Recommendations

### 4.1 ThreatExecutor SPI

The most critical interface in this spec. Design principles:

```
ThreatExecutor
├── Per-action, not per-threat → one executor per action type
├── Fail-open by contract → documented in interface godoc
├── Stateless → all state in ThreatPolicyStore
└── Idempotent → executing the same threat twice is safe
```

The `Execute(ctx, threat, policy)` signature is deliberate:
- `threat` carries the detection result (what happened)
- `policy` carries the configured response (what to do about it)
- Executor is the mechanical layer (how to do it)

This separation means the policy engine and the executor can be tested independently:

```
Policy tests:              threat + policy → shouldMatch
Executor tests:            threat + action → verifySideEffect
Integration tests:         threat + policy + executor → full chain
```

### 4.2 No New Abstraction for Threat Events

I considered a unified `Threat` type that replaces both `anomaly.Signal` and `tokenanomaly.Finding`, but rejected it:

- `Signal` has a `Score` field (0-100 confidence) — `Finding` doesn't
- `Finding` has an `ObservedAt` range — `Signal` doesn't
- Changing either type would break existing consumers (admin API reads Findings, audit reads Signals)

Instead, the bridge adapts each into a `Threat` at the executor boundary:

```go
// In anomaly → bridge
func SignalToThreat(s Signal, event *LoginEvent) Threat {
    return Threat{
        Type:      s.Type,
        Severity:  string(s.Severity),
        SubjectID: s.SubjectID,
        ClientID:  event.ClientID,
        Evidence:  s.Evidence,
    }
}

// In tokenanomaly → bridge
func FindingToThreat(f Finding) Threat {
    return Threat{
        Type:      f.Type,
        Severity:  string(f.Severity),
        SubjectID: f.SubjectID,
        // ... token-specific fields
    }
}
```

This is more code but zero risk to the existing detection surfaces.

### 4.3 Keep `anomaly.Sink` Unchanged

The `Sink` interface (audit recording) is separate from the executor (active response). They run in parallel in `Runner.inspect()`:

```go
// After running all detectors:
for _, signal := range signals {
    // 1. Audit (existing)
    if r.sink != nil {
        r.sink.Record(ctx, event, signal)
    }
    // 2. Act (new — alongside, not replacing)
    if r.executor != nil {
        r.executor.Execute(ctx, signalToThreat(signal, event))
    }
}
```

Parallel execution ensures a broken executor (panic or hang) doesn't silence audit events. The `Sink` path is left untouched — existing operators who upgrade get the executor as pure additive capability.

---

## 5. Technology Choices

### 5.1 New Dependencies Required

| Dependency | For | Risk |
|---|---|---|
| `hashicorp/terraform-plugin-framework` | Direction 2 (Terraform Provider) | Very Low — first-party HashiCorp, pure Go |
| `hashicorp/terraform-plugin-go` | Direction 2 (protocol bridge) | Very Low — first-party, thin shim |
| `hashicorp/terraform-plugin-testing` | Direction 2 (acceptance tests) | Very Low — test-only dependency |

**No new dependencies for Direction 1 (Active ITDR).** All SPIs are in-core Go. The `ThreatPolicyStore` needs embedded JSON serialization — Go standard library `encoding/json` is sufficient.

### 5.2 Evaluation Criteria for Any New Dependency

1. **License:** Must be MPL-2.0, MIT, Apache-2.0, or BSD. No AGPL/GPL.
2. **Transitive dependency footprint:** Should not pull in grpc, protobuf, or kubernetes client libraries.
3. **Go version compatibility:** Must build with project's `go.mod` version (whatever Snaplink SSO targets).
4. **Maintenance status:** Last commit within 12 months; no open CVEs.

### 5.3 Merge Strategy: Parallel Tracks

```
Track A (core team):     Active ITDR (Direction 1)
Track B (infra team):    MemoryLimiter fix (Direction 4) + RedisLimiter (Direction 5)
Track C (ecosystem):     Terraform Provider (Direction 2) — separate module, any engineer
```

No blocking dependencies between tracks. The Active ITDR executor is the only one that reads from core state — it uses existing SPIs (`SessionManager`, `RefreshTokenStore`, `cluster.Bus`), so it doesn't need the RedisLimiter or other infra to ship.

---

## 6. Implementation Roadmap

### Phase 1 (Week 1-2): Active ITDR Core

| Day | Deliverable |
|---|---|
| 1-2 | `domains/threataction/executor.go` — Threat, Action, Executor SPI + docs |
| 3-4 | `domains/threataction/policy.go` — ThreatPolicy, ThreatPolicyStore, matching |
| 5 | `domains/threataction/memory/policy_store.go` — CRUD + tests |
| 6-7 | `domains/threataction/registry.go` — ThreatExecutors composite + rate-limit + audit |
| 8 | Wire into `anomaly.Runner.inspect()` (~30 lines) |
| 9 | Wire into `tokenanomaly.Detector.Analyze()` (~20 lines) |
| 10 | `make acceptance` — all gates pass |

### Phase 2 (Week 3-4): Action Handlers + Admin API

| Day | Deliverable |
|---|---|
| 11-12 | `SuspendSessionExecutor` + `RevokeFamilyExecutor` |
| 13 | Cluster bus integration |
| 14-15 | `domains/threataction/admin.go` — policy CRUD HTTP handlers |
| 16 | Integration tests (detector → executor → verify state change) |
| 17 | `docs/openapi.yaml` + `docs/error-codes.md` updates |
| 18-20 | `make acceptance` + review + fix |

### Phase 3 (Week 5): Production Hardening

| Task | Detail |
|---|---|
| Observability | Metrics for executor dispatch, latency, errors per action type |
| Rate-limit tuning | Default rate limits that prevent notification storms |
| Tenant isolation | Ensure tenant-scoped threats don't affect other tenants |
| Docs | Operator guide: "Setting up automated threat response" |

### Risk Matrix

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Executor accidentally blocks request path | Low | Critical | Executor runs on the SAME goroutine as detection (off-path, after response sent). Documented fail-open contract. Timeout per executor call. |
| Policy store becomes single point of failure | Medium | Medium | Memory store is always-available (in-process). SQLite/Redis store downstream would be optional — executor degrades to Noop on store error. |
| `SessionManager.SuspendSession` not designed for concurrent revocation calls | Low | Medium | SessionManager uses `DELETE RETURNING` pattern — concurrent revocations are idempotent. Verify with race tests. |
| Token anomaly sweeper and executor race | Low | Low | Finding → Threat conversion is a read — no mutation. The FindingStore is append-only. |

---

## 7. Summary of Recommendations

| # | Recommendation | Priority |
|---|---|---|
| 1 | **Implement Active ITDR now** — the highest-value change in the analysis. Detect-to-respond bridge completes the anomaly architecture. | P0 |
| 2 | **Terraform Provider as parallel track** — separate module, Plugin Framework, zero core changes. Any team member can build. | P0 |
| 3 | **MemoryLimiter background pruner** — quick fix (one afternoon), eliminates a real DoS vector. | P1 |
| 4 | **Extend Conditional Access with ThreatType** — small change, large policy expressiveness win. | P1 |
| 5 | **Document Refresh Grace Window** — code is correct, just needs to be findable. | P1 |
| 6 | **Redis-backed rate limiter** — production HA for operators running multi-replica. | P2 |

The Active ITDR direction is the architectural keystone: it makes all the existing detection investment ("smoke alarms") actually actionable ("fire department"). Without it, the anomaly subsystem is a monitoring dashboard — with it, it's an automated defense layer.
