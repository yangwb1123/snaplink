# Config canary apply

This design extends the declared configuration-baseline API in
`platform/configaudit`. It does not make the Go server a runtime configuration
hot-loader: `POST /api/v1/admin/config/apply` still records a redacted,
append-only baseline, and the canary observes the health ports already wired
by the composition layer.

## Contract

Canary mode is explicit: `POST .../config/apply?approve=true&canary=true`.
The optional `window` query parameter is a Go duration, defaults to `60s`, and
is bounded to `1s` through `24h`. An omitted or false `canary` parameter keeps
the existing apply response and state transitions byte-for-byte compatible.

The canary requires an existing applied baseline. That predecessor is the
rollback target; refusing a first-ever canary is safer than accepting a
candidate that cannot be restored. Only one canary may be observing at a
time. A concurrent apply or rollback receives `409 config_canary_in_progress`.

## State machine

```text
apply + persist observing -> canary-observing
canary-observing + healthy window -> confirmed
canary-observing + definitive unhealthy -> rolled_back
canary-observing + process restart -> rolled_back (fail-safe recovery)
```

The state is persisted beside the applied-version chain. The durable SQLite
backend writes the candidate and observing state in one transaction; the
memory backend does the same under its store mutex. Terminal state is retained
as the latest canary record and is replaced by the next canary. On restart an
observing record is not resumed: the worker first restores its recorded
predecessor, then records `rolled_back`. This prevents an unobserved candidate
from remaining authoritative after an interrupted observation window. If that
rollback fails, the observing record remains and recovery retries.

Canary rollback is conditional on the candidate still being the latest
applied version. This prevents an old worker from rolling back a newer manual
change. Normal apply and rollback are rejected while observation is active.

## Health and failure posture

The controller receives an injected list of health probes. Composition adapts
the existing `StorageHealthSource` ports; `configaudit` does not import
`interfaces/sso` or the degradation manager. A probe returns `healthy`,
`unhealthy`, or `unknown`:

- any definitive `unhealthy` result triggers automatic rollback;
- `unknown` is fail-open and is not treated as a rollback signal;
- healthy (or unknown) observations through the full window confirm the
  canary;
- no probe/controller means the canary request is rejected with
  `501 config_canary_not_available`.

Observation uses a bounded one-second poll interval and is cancellation-safe.
The storage-health adapter classifies context cancellation/deadlines as
`unknown`, matching the degradation driver's fail-open advisory behavior;
concrete non-timeout Ping failures are the definitive unhealthy signal.

## Audit and compatibility

`admin_config_applied` remains emitted for the baseline write. Canary lifecycle
events add metadata only (canary id, version id, predecessor, peer digest,
reason, and failure detail):

- `config_canary_started`
- `config_canary_confirmed`
- `config_canary_rolled_back`

Snapshots remain redacted and are never copied into audit metadata. The
existing `Applied`/`Rollback` history chain remains the source of baseline
state; the canary record explains whether its observation completed or was
reverted. The non-canary request path does not start the worker, add a query
field to its response, or change its error mapping.

The API continues to require `approve=true`, `admin:write`, digest equality,
and the existing actor/audit handling. No new configuration key is needed;
the window is an explicitly bounded per-request control.
