# Grafana dashboard + Prometheus alerts for snaplink/sso

Starter pack for the observability story: a Grafana dashboard
visualizing the 5 `sso_*` metrics + Go runtime collectors, plus a
Prometheus alert ruleset covering the most common SLO violations.

```
deploy/grafana/
├── sso-overview.json   # Grafana 10+ dashboard (15 panels across 5 rows)
├── alerts.yaml         # Prometheus alerting rules (10 rules)
└── README.md           # you are here
```

## Import the dashboard

1. Grafana → Dashboards → New → Import
2. Upload `sso-overview.json` (or paste contents)
3. Pick your Prometheus datasource (the `$datasource` variable
   defaults to the one named "Prometheus")
4. Save

The dashboard has a `$instance` template variable wired to
`sso_http_requests_total{instance}` — toggle individual replicas or
keep the default "All".

### Panels

| Row        | Panel                                       | Metric / query                                                  |
|------------|---------------------------------------------|-----------------------------------------------------------------|
| Overview   | Requests / sec (5m)                         | `rate(sso_http_requests_total[5m])`                             |
| Overview   | Error rate (4xx + 5xx, 5m)                  | 4xx+5xx / total                                                 |
| Overview   | Login success rate (1h)                     | success / total of `sso_login_attempts_total`                   |
| Overview   | Active instances                            | `count(up{job=~".*sso.*"} == 1)`                                |
| HTTP       | Requests/s by status class                  | `sum by (status_class) (rate(...))`                             |
| HTTP       | Request duration p95 by method              | `histogram_quantile(0.95, ...)`                                 |
| Auth flow  | Login attempts / s by provider + outcome    | `sso_login_attempts_total`                                      |
| Auth flow  | Tokens issued / s by strategy               | `sso_tokens_issued_total`                                       |
| Auth flow  | Risk decisions / s                          | `sso_risk_decisions_total`                                      |
| Go runtime | Goroutines                                  | `go_goroutines`                                                 |
| Go runtime | Heap allocated                              | `go_memstats_alloc_bytes`                                       |
| Go runtime | GC pause p99                                | `go_gc_duration_seconds{quantile="1"}`                          |
| Audit pipeline & signing health | Audit async drops / sec by cause      | `sso_audit_async_drops_{queue_full,closed,inner_error}_total`   |
| Audit pipeline & signing health | Audit queue fill ratio                | `sso_audit_async_queue_depth` / `sso_audit_async_queue_capacity`|
| Audit pipeline & signing health | Signing health (KMS backend + key aggregation) | `sso_signing_backend_up`, `sso_signing_key_aggregation_up`, `sso_signing_key_adoption_errors_total` |

## Wire the alerts

`alerts.yaml` is shaped for direct use as Prometheus's alerting
configuration — ten rules with `for:` debounce windows tuned to be
quiet under normal load:

| Rule                               | Severity | Condition                                              |
|-------------------------------------|----------|--------------------------------------------------------|
| `SSOHighHTTPErrorRate`             | warning  | 5xx rate > 5% for 5m                                   |
| `SSOHighLoginFailureRate`          | warning  | login failure ratio > 20% for 10m (creds-stuffing)     |
| `SSORateLimitSaturated`            | info     | 429s firing at > 0.5/s for 5m                          |
| `SSOLatencyP95High`                | warning  | p95 request latency > 1s for 10m                       |
| `SSORiskScorerSilent`              | warning  | login traffic exists but risk decisions == 0 for 15m   |
| `SSOInstanceDown`                  | critical | `up == 0` for 2m                                       |
| `SSOAuditEventsDropped`            | critical | any audit async drop counter increased over 5m         |
| `SSOAuditQueueSaturated`           | warning  | audit queue depth / capacity > 80% for 5m               |
| `SSOSigningBackendDown`            | critical | `sso_signing_backend_up == 0` for 2m (per alg)          |
| `SSOSigningKeyAggregationDegraded` | warning  | `sso_signing_key_aggregation_up == 0` for 5m            |

### kube-prometheus-stack

Wrap in a `PrometheusRule` CRD:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: snaplink-sso
  namespace: snaplink-sso
spec:
  groups:
    # paste the contents of alerts.yaml's `groups:` here
```

### Plain Prometheus

Reference from `prometheus.yml`:

```yaml
rule_files:
  - /etc/prometheus/rules/sso-server-alerts.yaml
```

## Tuning

Every threshold is a **starting point**, not a recommendation. Before
promoting any of these to paging severity:

1. Watch them fire silently for at least one week of representative
   traffic.
2. Adjust the thresholds + `for:` windows to your false-positive
   tolerance.
3. Route via your existing Alertmanager labels (`severity:` is the
   only label set here; add `team:`, `service:`, etc. to match your
   routing conventions).

The dashboard panels are intentionally vendor-neutral — replace the
default thresholds (the green/yellow/red color stops in the overview
stat panels) with values that match what "healthy" looks like for
your deployment.
