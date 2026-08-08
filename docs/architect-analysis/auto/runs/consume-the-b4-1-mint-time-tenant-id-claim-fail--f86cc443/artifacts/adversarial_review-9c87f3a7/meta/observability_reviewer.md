Done. Doc-only edits (no `.go` changes, so no build gate needed). Here is the verification report.

## Q4 verification against HEAD

### Seam 1 — readyz degradation at 5m MaxLag: **exists as described** ✓
- `SNAPLINK_BILLING_QUOTA_MAX_LAG` default `5 * time.Minute` (`quota_relay.go:79`; flag `quota-max-lag`, non-default validation at :175).
- `tenant_quota_projection` registered (`app.go:103`) → `Relay.Ready` → `QuotaProjectionDeliveryReady(now, maxLag)`: postgres runs `EXISTS(... WHERE q.status <> 'delivered' AND o.created_at_ns <= now − maxLag)` → `ErrQuotaProjectionLag`; store errors also fail the check (`outbox.go:398-410`). Matches observability.md's wording exactly ("oldest unfinished fact exceeds `SNAPLINK_BILLING_QUOTA_MAX_LAG` or its store cannot be inspected").

### Seam 2 — fixed worker log line: **exists as described** ✓
- `tenant quota projection relay paused after error: %v` (`quota_relay.go:459`), single call site, fires for any `RunOnce` error at most once per `errorPause` (5 s — bounded rate). `ErrAuthorizationRejected` prints `quota projection: authorization rejected; relay paused` (`client.go:21`), so the error value distinguishes the class in the log. The prefix is already documented in observability.md, whose "repeated worker pauses" directive maps to this line.

### Seam 3 — outbox `last_error` queryability: **exists as described** ✓
- `reasonAuthorization = "quota projection authorization rejected"` (`relay.go:19`), produced only by `classifyPublishError` on `ErrAuthorizationRejected` (`relay.go:237-238`).
- Persisted by `FailQuotaProjectionDelivery` (`last_error=$3`, 1024-char bounded) into durable `tenant_commerce_quota_outbox` (`store.go:193-207`: `status, attempts, next_attempt_at_ns, lease_owner, lease_until_ns, last_error, delivered_revision, delivered_at_ns`), with a claim index on `(status, next_attempt_at_ns, ...)`. Plain SQL-queryable.

### Seam 4 — ~70–75 m discriminator: **sound; two corrections applied**
- F5 bound verified precisely: `refreshAt = fetch + min(expires_in, 24 h) − min(30 s skew, lifetime/2)` (`oauth_token_source.go:240-245`); recovery = first attempt after `refreshAt`, so the episode is ≤ `expires_in − 30 s + maxBackoff` ≈ **60.5 m** with defaults. The doc's formula (TTL + skew + maxBackoff + margin ≈ 70–75 m) errs conservative — the correct direction for a ceiling — with ~10–14 m cushion covering the lazy-refetch trigger, poll, and jitter. F2/F3 grow unbounded, so the split holds.
- **Defect found and fixed**: the PAGE rule was keyed on "oldest row's `next_attempt_at_ns` age" — but `next_attempt_at_ns` is rewritten on every retry (bounded by `MaxBackoff`), so its age never grows for F2/F3 and the rule would **never page**. Corrected to joined `tenant_commerce_outbox.created_at_ns` (the quota table has no creation timestamp; the readyz SQL already uses this join as precedent).
- Also corrected: the "≤ TTL, by construction" phrasing (real bound adds one lazy-refetch backoff), and §4.3's secondary rule now correlates with durable `delivered_at_ns` progress — `RunResult` is in-process and not externally observable.
- Residual note recorded: `last_error` is **never cleared on delivery** (`CompleteQuotaProjectionDelivery` touches only status/revision/timestamps), so the `status='pending'` filter is load-bearing — now stated in the doc.

### Expressibility — WARN/PAGE without new metrics: **confirmed**
- Admin fail-open WARN (`rate(...|~ "admin tenant gate resolver error")[5m] > 0`) is expressible once the designed `adminGateLog` line (design §3.2.1) lands — substring match works against the designed format; log-shipper only.
- reasonAuthorization WARN/PAGE: SQL over existing columns; the claim index covers it.
- PAGE-at-15m-sustained aligns with the real renewal tolerance (`renewalMaxToleratedLag = 15 * time.Minute`, `renewal.go:21`) and the observability.md directive "Alert on sustained readiness failure for two max-lag evaluation windows and on repeated worker pauses" — exact quote, present.
- Optional counters remain correctly framed as a fallback mirroring the renewal precedent; billing `/metrics` is renewal-only today (`renewal.go:182-231`), confirming zero new metrics is the right default.

### Two flagged (not doc-corrected) items
1. **adminGateLog content divergence**: hardening §4.2's "add `client_id` to the line" contradicts the security reviewer's identifier-freedom pin; also, per-request stderr amplification during an outage is unaddressed (the alert rule is rate-based, but the design should adopt the reviewer's windowed/rate-limited logging).
2. **Deployment-window "≤ TTL" phrasing** (F1) is coarse but absorbed by the margin — F1 clears at the same refresh bound as F5, so the duration rule covers both classes.
